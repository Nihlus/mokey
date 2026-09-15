package server

import (
	"context"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
	"github.com/stripe/stripe-go/v86"
	ipa "github.com/ubccr/goipa"
)

type StripeVariables struct {
	PublishableKey string
	PricingTable   string
}

func newStripeClient() *stripe.Client {
	secretKey := viper.GetString("stripe.secret_key")
	return stripe.NewClient(secretKey)
}

func (r *Router) stripeVars(c *fiber.Ctx, vars fiber.Map) {
	vars["customer"] = r.customer(c)
}

func (r *Router) customer(c *fiber.Ctx) *stripe.Customer {
	return c.Locals(ContextKeyStripeCustomer).(*stripe.Customer)
}

func (r *Router) ManageSubscriptions(c *fiber.Ctx) error {
	sc := r.stripeClient
	customer := r.customer(c)

	create := &stripe.BillingPortalSessionCreateParams{
		Customer:  stripe.String(customer.ID),
		ReturnURL: stripe.String(fmt.Sprintf("%s", c.BaseURL())),
	}

	session, err := sc.V1BillingPortalSessions.Create(context.TODO(), create)
	if err != nil {
		return err
	}

	return c.Redirect(session.URL)
}

func refreshCustomer(sc *stripe.Client, customer *stripe.Customer, user *ipa.User) (*stripe.Customer, error) {
	needsUpdate := customer.Email != user.Email ||
		customer.Name != user.DisplayName ||
		customer.Phone != user.TelephoneNumber ||
		customer.Metadata["uid"] != user.Uid ||
		customer.Metadata["gid"] != user.Gid ||
		customer.Metadata["username"] != user.Username

	if !needsUpdate {
		return customer, nil
	}

	update := &stripe.CustomerUpdateParams{
		Email: stripe.String(user.Email),
		Name:  stripe.String(user.DisplayName),
		Phone: stripe.String(user.TelephoneNumber),
		Metadata: map[string]string{
			"uid":        user.Uid,
			"gid":        user.Gid,
			"username":   user.Username,
			"updated_at": time.Now().UTC().Format(time.RFC3339),
		},
	}

	customer, err := sc.V1Customers.Update(context.TODO(), customer.ID, update)
	return customer, err
}

func getOrCreateCustomer(sc *stripe.Client, user *ipa.User) (*stripe.Customer, error) {
	// see if we can look up an existing customer
	search := &stripe.CustomerSearchParams{
		SearchParams: stripe.SearchParams{
			Query: fmt.Sprintf("metadata[\"uid\"]:\"%s\"", user.Uid),
		},
	}

	var customer *stripe.Customer = nil
	customers := sc.V1Customers.Search(context.TODO(), search)
	for c, err := range customers.All(context.TODO()) {
		if err != nil {
			return nil, err
		}

		if c != nil {
			customer = c
			break
		}
	}

	if customer != nil {
		return customer, nil
	}

	create := &stripe.CustomerCreateParams{
		Email: stripe.String(user.Email),
		Name:  stripe.String(user.DisplayName),
		Phone: stripe.String(user.TelephoneNumber),
		Metadata: map[string]string{
			"uid":        user.Uid,
			"gid":        user.Gid,
			"username":   user.Username,
			"updated_at": time.Now().UTC().Format(time.RFC3339),
		},
	}

	c, err := sc.V1Customers.Create(context.TODO(), create)
	return c, err
}
