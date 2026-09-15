package server

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stripe/stripe-go/v86"
	ipa "github.com/ubccr/goipa"
)

const IPAEntitlementGroupPrefix = "stripe-entitlement-"
const LastProcessedWebhookEventKey = "last-processed-webhook-event"
const ProcessedWebhookEventKeyPrefix = "processed-webhook-event-"
const ProcessingWebhookEventKeyPrefix = "processing-webhook-event-"

func (r *Router) RequireStripeWebhook(c *fiber.Ctx) error {
	payload := c.BodyRaw()
	header := c.GetReqHeaders()["Stripe-Signature"][0]
	secret := viper.GetString("stripe.webhook_secret")

	event, err := stripe.ConstructEvent(payload, header, secret)
	if err != nil {
		serr := c.SendStatus(fiber.StatusBadRequest)
		if serr != nil {
			return fmt.Errorf(
				"failed to reply with 400 Bad Request to an invalid Stripe webhook: %w (which was invalid because: %w)",
				serr,
				err,
			)
		}

		return fmt.Errorf("failed to decode Stripe webhook: %w", err)
	}

	err = c.SendStatus(fiber.StatusAccepted)
	if err != nil {
		return fmt.Errorf("failed to reply with 202 Accepted to a valid Stripe webhook: %w", err)
	}

	c.Locals(ContextKeyStripeEvent, &event)

	return c.Next()
}

func (r *Router) stripeEvent(c *fiber.Ctx) *stripe.Event {
	return c.Locals(ContextKeyStripeEvent).(*stripe.Event)
}

func (r *Router) StripeWebhook(c *fiber.Ctx) error {
	event := r.stripeEvent(c)
	return r.handleWebhookEvent(r.stripeClient, r.adminClient, event)
}

func (r *Router) handleWebhookEvent(sc *stripe.Client, ic *ipa.Client, event *stripe.Event) error {
	// have we already processed this event?
	isProcessingOrProcessed, err := r.isEventProcessingOrProcessed(event)
	if err != nil {
		return fmt.Errorf(
			"failed to determine if event %s is being processed or has already been processed: %w",
			event.ID,
			err,
		)
	}

	if isProcessingOrProcessed {
		log.WithFields(log.Fields{
			"id":         event.ID,
			"event_type": event.Type,
		}).Warn("already-processed Stripe webhook event ignored")

		return nil
	}

	err = r.markEventProcessing(event)
	if err != nil {
		return fmt.Errorf("failed to mark event %s as being processed: %w", event.ID, err)
	}

	switch event.Type {
	case stripe.EventTypeEntitlementsActiveEntitlementSummaryUpdated:
		entitlements := &stripe.EntitlementsActiveEntitlementSummary{}
		err = json.Unmarshal(event.Data.Raw, entitlements)
		if err != nil {
			return err
		}

		err = handleEntitlementSummaryUpdated(sc, ic, entitlements)
		if err != nil {
			return err
		}
	default:
		log.WithFields(log.Fields{
			"id":         event.ID,
			"event_type": event.Type,
		}).Warn("unknown Stripe webhook event ignored")
	}

	return r.markEventProcessing(event)
}

func (r *Router) isEventProcessingOrProcessed(event *stripe.Event) (bool, error) {
	v, err := r.storage.Get(processedEventKey(event))
	if err != nil {
		return false, err
	}

	if v != nil {
		return true, nil
	}

	v, err = r.storage.Get(processingEventKey(event))
	if err != nil {
		return false, err
	}

	if v != nil {
		return true, nil
	}

	return false, nil
}

func (r *Router) markEventProcessing(event *stripe.Event) error {
	// get it done in a minute or something gets another bite at the apple
	err := r.storage.Set(processingEventKey(event), []byte("true"), time.Minute*1)
	if err != nil {
		return fmt.Errorf("failed to mark event %s as being processed: %w", event.ID, err)
	}

	return nil
}

func (r *Router) markEventProcessed(event *stripe.Event) error {
	// Stripe discards events after three days, so forget about stuff we've processed after that plus some leeway
	err := r.storage.Set(processedEventKey(event), []byte("true"), time.Hour*80)
	if err != nil {
		return fmt.Errorf("failed to mark event %s as having been processed: %w", event.ID, err)
	}

	return nil
}

func processingEventKey(event *stripe.Event) string {
	return ProcessingWebhookEventKeyPrefix + event.ID + "-" + string(event.Type)
}

func processedEventKey(event *stripe.Event) string {
	return ProcessedWebhookEventKeyPrefix + event.ID + "-" + string(event.Type)
}

func handleEntitlementSummaryUpdated(
	sc *stripe.Client,
	ic *ipa.Client,
	entitlementSummary *stripe.EntitlementsActiveEntitlementSummary,
) error {
	// grab the customer
	customer, err := sc.V1Customers.Retrieve(context.TODO(), entitlementSummary.Customer, &stripe.CustomerRetrieveParams{})
	if err != nil {
		return fmt.Errorf("failed to retrieve the customer associated with a Stripe webhook: %w", err)
	}

	var user *ipa.User
	if username, found := customer.Metadata["username"]; found {
		user, err = ic.UserShow(username)
	}

	if user == nil || err != nil {
		return fmt.Errorf("failed to retrieve the IPA user associated with a Stripe webhook: %w", err)
	}

	var activeEntitlementGroups []string
	if entitlementSummary.Entitlements.HasMore {
		list := &stripe.EntitlementsActiveEntitlementListParams{
			Customer: stripe.String(customer.ID),
		}

		for entitlement, err := range sc.V1EntitlementsActiveEntitlements.List(context.TODO(), list).All(context.TODO()) {
			if err != nil {
				return err
			}

			groupName, err := applyEntitlement(sc, ic, user, entitlement)
			if err != nil {
				return err
			}

			if groupName != "" {
				activeEntitlementGroups = append(activeEntitlementGroups, groupName)
			}
		}
	} else {
		for _, entitlement := range entitlementSummary.Entitlements.Data {
			groupName, err := applyEntitlement(sc, ic, user, entitlement)
			if err != nil {
				return err
			}

			if groupName != "" {
				activeEntitlementGroups = append(activeEntitlementGroups, groupName)
			}
		}
	}

	err = removeInactiveEntitlements(ic, user, activeEntitlementGroups)
	if err != nil {
		return err
	}

	return nil
}

func applyEntitlement(
	sc *stripe.Client,
	ic *ipa.Client,
	user *ipa.User,
	entitlement *stripe.EntitlementsActiveEntitlement,
) (string, error) {
	feature, err := sc.V1EntitlementsFeatures.Retrieve(
		context.TODO(),
		entitlement.Feature.ID,
		&stripe.EntitlementsFeatureRetrieveParams{},
	)

	if err != nil {
		return "", err
	}

	groupName, found := feature.Metadata["ipa_group"]
	if !found {
		log.WithFields(log.Fields{
			"feature": feature,
		}).Warn("entitlement does not have an associated IPA group - ignoring")

		return "", nil
	}

	if user.HasGroup(groupName) {
		// user is already entitled
		return groupName, nil
	}

	_, err = groupShow(ic, groupName)
	if err != nil {
		return "", fmt.Errorf("failed to look up an IPA group with the name %s: %w", groupName, err)
	}

	log.WithFields(log.Fields{
		"group": groupName,
	}).Infof("adding entitlement %s to %s", groupName, user.Username)

	err = groupAddMember(ic, groupName, user.Username)
	if err != nil {
		return "", err
	}

	// TODO: the JSON API doesn't always return an error even if it fails
	// (such as when trying to manipulate a user Mokey doesn't have access to) - we double-check here
	user, err = ic.UserShow(user.Username)
	if err != nil {
		return "", err
	}

	if !user.HasGroup(groupName) {
		return "", fmt.Errorf(
			"failed to add entitlement %s to %s for some unknown reason. Check if Mokey has permission to change groups for the user",
			groupName,
			user.Username,
		)
	}

	return groupName, nil
}

func removeInactiveEntitlements(ic *ipa.Client, user *ipa.User, activeEntitlementGroups []string) error {
	for _, groupName := range user.Groups {
		if !strings.HasPrefix(groupName, IPAEntitlementGroupPrefix) {
			// not a group related to entitlements; ignore
			continue
		}

		if slices.Contains(activeEntitlementGroups, groupName) {
			// this entitlement is active; ignore
			continue
		}

		// inactive entitlement; remove
		log.WithFields(log.Fields{
			"group": groupName,
		}).Infof("removing entitlement %s from %s", groupName, user.Username)

		err := groupRemoveMember(ic, groupName, user.Username)
		if err != nil {
			return err
		}

		// TODO: the JSON API doesn't always return an error even if it fails
		// (such as when trying to manipulate a user Mokey doesn't have access to) - we double-check here
		user, err = ic.UserShow(user.Username)
		if err != nil {
			return err
		}

		if user.HasGroup(groupName) {
			return fmt.Errorf(
				"failed to remove entitlement %s from %s for some unknown reason. Check if Mokey has permission to change groups for the user",
				groupName,
				user.Username,
			)
		}
	}

	return nil
}

func (r *Router) processMissedWebhookEvents() error {
	log.Info("checking for missed webhook events")

	b, err := r.storage.Get(LastProcessedWebhookEventKey)
	if err != nil {
		return err
	}

	sc := r.stripeClient
	list := &stripe.EventListParams{
		DeliverySuccess: new(false),
	}

	if b != nil {
		lastEvent := string(b)
		list.EndingBefore = stripe.String(lastEvent)
	}

	for event, err := range sc.V1Events.List(context.TODO(), list).All(context.TODO()) {
		if err != nil {
			return err
		}

		log.WithFields(log.Fields{
			"id":         event.ID,
			"event_type": event.Type,
		}).Info("processing missed event")

		err = r.handleWebhookEvent(sc, r.adminClient, event)
		if err != nil {
			return err
		}
	}

	return nil
}
