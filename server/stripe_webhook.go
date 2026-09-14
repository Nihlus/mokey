package server

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stripe/stripe-go/v86"
)

const IPAEntitlementGroupPrefix = "stripe-entitlement-"

func (r *Router) RequireStripeWebhook(c *fiber.Ctx) error {
	sc := newStripeClient()
	c.Locals(ContextKeyStripeClient, sc)

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

	// grab the customer
	if customerId, found := event.Data.Object["customer"]; found {
		sc := r.stripeClient(c)
		customer, err := sc.V1Customers.Retrieve(context.TODO(), customerId.(string), &stripe.CustomerRetrieveParams{})
		if err != nil {
			return fmt.Errorf("failed to retrieve the customer associated with a Stripe webhook: %w", err)
		}

		c.Locals(ContextKeyStripeCustomer, customer)

		if username, found := customer.Metadata["username"]; found {
			user, err := r.adminClient.UserShow(username)
			if err != nil {
				return fmt.Errorf("failed to retrieve the IPA user associated with a Stripe webhook: %w", err)
			}

			c.Locals(ContextKeyUser, user)
		}
	}

	return c.Next()
}

func (r *Router) stripeEvent(c *fiber.Ctx) *stripe.Event {
	return c.Locals(ContextKeyStripeEvent).(*stripe.Event)
}

func (r *Router) StripeWebhook(c *fiber.Ctx) error {
	event := r.stripeEvent(c)

	// route the event
	switch event.Type {
	case stripe.EventTypeEntitlementsActiveEntitlementSummaryUpdated:
		entitlements := &stripe.EntitlementsActiveEntitlementSummary{}
		err := json.Unmarshal(event.Data.Raw, entitlements)
		if err != nil {
			return err
		}

		return r.handleEntitlementSummaryUpdated(entitlements, c)
	default:
		log.WithFields(log.Fields{
			"id":         event.ID,
			"event_type": event.Type,
		}).Warn("unknown Stripe webhook event ignored")

		return nil
	}
}

func (r *Router) handleEntitlementSummaryUpdated(entitlementSummary *stripe.EntitlementsActiveEntitlementSummary, c *fiber.Ctx) error {
	customer := r.customer(c)
	sc := r.stripeClient(c)

	var activeEntitlementGroups []string
	if entitlementSummary.Entitlements.HasMore {
		list := &stripe.EntitlementsActiveEntitlementListParams{
			Customer: stripe.String(customer.ID),
		}

		for entitlement, err := range sc.V1EntitlementsActiveEntitlements.List(context.TODO(), list).All(context.TODO()) {
			if err != nil {
				return err
			}

			groupName, err := r.applyEntitlement(entitlement, c)
			if err != nil {
				return err
			}

			if groupName != "" {
				activeEntitlementGroups = append(activeEntitlementGroups, groupName)
			}
		}
	} else {
		for _, entitlement := range entitlementSummary.Entitlements.Data {
			groupName, err := r.applyEntitlement(entitlement, c)
			if err != nil {
				return err
			}

			if groupName != "" {
				activeEntitlementGroups = append(activeEntitlementGroups, groupName)
			}
		}
	}

	err := r.removeInactiveEntitlements(activeEntitlementGroups, c)
	if err != nil {
		return err
	}

	return nil
}

func (r *Router) applyEntitlement(entitlement *stripe.EntitlementsActiveEntitlement, c *fiber.Ctx) (string, error) {
	sc := r.stripeClient(c)
	ipa := r.adminClient
	user := r.user(c)

	feature, err := sc.V1EntitlementsFeatures.Retrieve(context.TODO(), entitlement.Feature.ID, &stripe.EntitlementsFeatureRetrieveParams{})
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

	_, err = groupShow(ipa, groupName)
	if err != nil {
		return "", fmt.Errorf("failed to look up an IPA group with the name %s: %w", groupName, err)
	}

	log.WithFields(log.Fields{
		"group": groupName,
	}).Infof("adding entitlement %s to %s", groupName, user.Username)

	err = groupAddMember(ipa, groupName, user.Username)
	if err != nil {
		return "", err
	}

	// TODO: the JSON API doesn't always return an error even if it fails
	// (such as when trying to manipulate a user Mokey doesn't have access to) - we double-check here
	user, err = ipa.UserShow(user.Username)
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

func (r *Router) removeInactiveEntitlements(activeEntitlementGroups []string, c *fiber.Ctx) error {
	ipa := r.adminClient
	user := r.user(c)

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

		err := groupRemoveMember(ipa, groupName, user.Username)
		if err != nil {
			return err
		}

		// TODO: the JSON API doesn't always return an error even if it fails
		// (such as when trying to manipulate a user Mokey doesn't have access to) - we double-check here
		user, err = ipa.UserShow(user.Username)
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
