package server

import (
	"context"
	"fmt"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stripe/stripe-go/v86"
)

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
	case stripe.EventTypeCustomerCreated:
		customer := &stripe.Customer{}
		err := customer.UnmarshalJSON(event.Data.Raw)
		if err != nil {
			return err
		}

		return handleCreatedCustomer(event, customer, c)
	case stripe.EventTypeCustomerSubscriptionCreated:
		subscription := &stripe.Subscription{}
		err := subscription.UnmarshalJSON(event.Data.Raw)
		if err != nil {
			return err
		}

		return handleCreatedSubscription(event, subscription, c)
	case stripe.EventTypeCustomerSubscriptionUpdated:
		subscription := &stripe.Subscription{}
		err := subscription.UnmarshalJSON(event.Data.Raw)
		if err != nil {
			return err
		}

		return handleUpdatedSubscription(event, subscription, c)
	case stripe.EventTypeCustomerSubscriptionDeleted:
		subscription := &stripe.Subscription{}
		err := subscription.UnmarshalJSON(event.Data.Raw)
		if err != nil {
			return err
		}

		return handleDeletedSubscription(event, subscription, c)
	case stripe.EventTypeInvoicePaid:
		invoice := &stripe.Invoice{}
		err := invoice.UnmarshalJSON(event.Data.Raw)
		if err != nil {
			return err
		}

		return handleInvoicePaid(event, invoice, c)
	default:
		log.WithFields(log.Fields{
			"id":         event.ID,
			"event_type": event.Type,
		}).Warn("unknown Stripe webhook event ignored")

		return nil
	}
}

func handleCreatedCustomer(event *stripe.Event, customer *stripe.Customer, c *fiber.Ctx) error {
	log.Info("created customer")
	log.Info(event)
	log.Info(customer)

	return nil
}

func handleCreatedSubscription(event *stripe.Event, subscription *stripe.Subscription, c *fiber.Ctx) error {
	log.Info("created subscription")
	log.Info(event)
	log.Info(subscription)

	return nil
}

func handleUpdatedSubscription(event *stripe.Event, subscription *stripe.Subscription, c *fiber.Ctx) error {
	log.Info("updated subscription")
	log.Info(event)
	log.Info(subscription)

	return nil
}

func handleDeletedSubscription(event *stripe.Event, subscription *stripe.Subscription, c *fiber.Ctx) error {
	log.Info("deleted subscription")
	log.Info(event)
	log.Info(subscription)

	return nil
}

func handleInvoicePaid(event *stripe.Event, invoice *stripe.Invoice, c *fiber.Ctx) error {
	log.Info("invoice paid")
	log.Info(event)
	log.Info(invoice)

	return nil
}
