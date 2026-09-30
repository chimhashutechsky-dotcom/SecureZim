"""
Stripe payment integration for subscription billing.
Handles card/mobile-money payments with webhook verification.
"""
import os
import hmac
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import stripe
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class StripeConfig:
    """Stripe configuration."""
    
    def __init__(self):
        self.api_key = os.getenv("STRIPE_API_KEY")
        self.webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
        self.publishable_key = os.getenv("STRIPE_PUBLISHABLE_KEY")
        
        if not self.api_key:
            logger.warning("STRIPE_API_KEY not configured - payment features disabled")
        
        if self.api_key:
            stripe.api_key = self.api_key


class PaymentPlan(BaseModel):
    """Payment plan definition."""
    plan_id: str
    name: str
    monthly_price_cents: int
    scan_quota: int
    assets_limit: int
    features: list[str]


# Standard subscription plans matching the app's tiers
SUBSCRIPTION_PLANS = {
    "free": PaymentPlan(
        plan_id="free",
        name="Free",
        monthly_price_cents=0,
        scan_quota=10,
        assets_limit=5,
        features=["Basic scanning", "Community support"]
    ),
    "starter": PaymentPlan(
        plan_id="starter",
        name="Starter",
        monthly_price_cents=2999,  # $29.99
        scan_quota=100,
        assets_limit=25,
        features=["Advanced scanning", "Email support", "API access"]
    ),
    "business": PaymentPlan(
        plan_id="business",
        name="Business",
        monthly_price_cents=9999,  # $99.99
        scan_quota=500,
        assets_limit=100,
        features=["Priority scanning", "Phone support", "Webhooks", "Custom reports"]
    ),
    "professional": PaymentPlan(
        plan_id="professional",
        name="Professional",
        monthly_price_cents=29999,  # $299.99
        scan_quota=5000,
        assets_limit=1000,
        features=["Unlimited priority scanning", "Dedicated support", "SLA", "Custom integrations"]
    ),
}


class CreatePaymentIntentRequest(BaseModel):
    """Request to create a payment intent."""
    plan_id: str = Field(..., description="Subscription plan ID")
    customer_email: str = Field(..., description="Customer email")
    customer_id: Optional[str] = Field(None, description="Existing Stripe customer ID")


class PaymentIntentResponse(BaseModel):
    """Payment intent response."""
    client_secret: str
    payment_intent_id: str
    amount: int
    currency: str = "usd"


class SubscriptionResponse(BaseModel):
    """Active subscription response."""
    subscription_id: str
    plan_id: str
    plan_name: str
    status: str
    current_period_start: datetime
    current_period_end: datetime
    amount_paid_cents: int
    next_payment_date: datetime
    payment_method: Optional[str] = None


class WebhookVerificationError(Exception):
    """Raised when webhook signature verification fails."""
    pass


class PaymentProcessor:
    """Handles Stripe payment operations."""
    
    def __init__(self):
        self.config = StripeConfig()
        self.enabled = bool(self.config.api_key)
    
    def create_payment_intent(
        self,
        plan_id: str,
        customer_email: str,
        customer_id: Optional[str] = None,
    ) -> PaymentIntentResponse:
        """
        Create a Stripe payment intent for a subscription plan.
        
        Args:
            plan_id: Plan ID (e.g., 'starter', 'business')
            customer_email: Customer email for receipt
            customer_id: Optional existing Stripe customer ID
        
        Returns:
            PaymentIntentResponse with client_secret for frontend
        
        Raises:
            ValueError: If plan_id is invalid or Stripe not configured
            stripe.error.StripeError: On Stripe API failures
        """
        if not self.enabled:
            raise ValueError("Stripe payment processing not configured")
        
        if plan_id not in SUBSCRIPTION_PLANS:
            raise ValueError(f"Invalid plan_id: {plan_id}")
        
        plan = SUBSCRIPTION_PLANS[plan_id]
        
        # Create or get customer
        if not customer_id:
            customer = stripe.Customer.create(email=customer_email)
            customer_id = customer.id
        
        # Create payment intent for one-time payment
        # (In production, use Stripe Billing for recurring payments)
        intent = stripe.PaymentIntent.create(
            amount=plan.monthly_price_cents,
            currency="usd",
            customer=customer_id,
            description=f"SecureZim {plan.name} subscription",
            metadata={
                "plan_id": plan_id,
                "plan_name": plan.name,
                "product_type": "subscription",
            },
            automatic_payment_methods={"enabled": True},
        )
        
        logger.info(
            f"Payment intent created: {intent.id} for plan {plan_id} "
            f"customer {customer_id}"
        )
        
        return PaymentIntentResponse(
            client_secret=intent.client_secret,
            payment_intent_id=intent.id,
            amount=plan.monthly_price_cents,
        )
    
    def create_subscription(
        self,
        plan_id: str,
        customer_id: str,
        payment_method_id: str,
    ) -> SubscriptionResponse:
        """
        Create a recurring subscription via Stripe Billing.
        
        Args:
            plan_id: Plan ID
            customer_id: Stripe customer ID
            payment_method_id: Stripe payment method ID
        
        Returns:
            SubscriptionResponse with subscription details
        
        Raises:
            ValueError: If plan_id is invalid or Stripe not configured
            stripe.error.StripeError: On Stripe API failures
        """
        if not self.enabled:
            raise ValueError("Stripe payment processing not configured")
        
        if plan_id not in SUBSCRIPTION_PLANS:
            raise ValueError(f"Invalid plan_id: {plan_id}")
        
        plan = SUBSCRIPTION_PLANS[plan_id]
        
        # Attach payment method to customer
        stripe.PaymentMethod.attach(
            payment_method_id,
            customer=customer_id,
        )
        
        # Set as default payment method
        stripe.Customer.modify(
            customer_id,
            invoice_settings={"default_payment_method": payment_method_id},
        )
        
        # Get or create Stripe product and price for this plan
        product_id = self._get_or_create_product(plan_id, plan)
        price_id = self._get_or_create_price(product_id, plan_id, plan)
        
        # Create subscription
        subscription = stripe.Subscription.create(
            customer=customer_id,
            items=[{"price": price_id}],
            payment_settings={
                "payment_method_types": ["card"],
                "save_default_payment_method": "on_subscription",
            },
        )
        
        logger.info(
            f"Subscription created: {subscription.id} for customer {customer_id} "
            f"plan {plan_id}"
        )
        
        return self._subscription_to_response(subscription, plan)
    
    def get_subscription(self, subscription_id: str) -> SubscriptionResponse:
        """Get subscription details."""
        if not self.enabled:
            raise ValueError("Stripe payment processing not configured")
        
        subscription = stripe.Subscription.retrieve(subscription_id)
        plan_id = subscription.metadata.get("plan_id", "unknown")
        plan = SUBSCRIPTION_PLANS.get(plan_id)
        
        if not plan:
            raise ValueError(f"Unknown plan in subscription: {plan_id}")
        
        return self._subscription_to_response(subscription, plan)
    
    def cancel_subscription(self, subscription_id: str) -> None:
        """Cancel a subscription immediately."""
        if not self.enabled:
            raise ValueError("Stripe payment processing not configured")
        
        stripe.Subscription.delete(subscription_id)
        logger.info(f"Subscription cancelled: {subscription_id}")
    
    def verify_webhook_signature(
        self,
        payload: bytes,
        sig_header: str,
    ) -> Dict[str, Any]:
        """
        Verify Stripe webhook signature and return event data.
        
        Args:
            payload: Raw request body bytes
            sig_header: Stripe signature header value
        
        Returns:
            Parsed event dictionary
        
        Raises:
            WebhookVerificationError: If signature verification fails
        """
        if not self.config.webhook_secret:
            raise WebhookVerificationError("Webhook secret not configured")
        
        try:
            event = stripe.Webhook.construct_event(
                payload,
                sig_header,
                self.config.webhook_secret,
            )
            return event
        except ValueError as e:
            logger.error(f"Invalid webhook payload: {e}")
            raise WebhookVerificationError("Invalid webhook payload") from e
        except stripe.error.SignatureVerificationError as e:
            logger.error(f"Invalid webhook signature: {e}")
            raise WebhookVerificationError("Signature verification failed") from e
    
    def handle_payment_intent_succeeded(self, event: Dict[str, Any]) -> None:
        """Handle payment_intent.succeeded webhook."""
        intent = event["data"]["object"]
        customer_id = intent.get("customer")
        plan_id = intent.get("metadata", {}).get("plan_id")
        
        logger.info(
            f"Payment succeeded: {intent['id']} for customer {customer_id} "
            f"plan {plan_id}"
        )
        # TODO: Update subscription status in database
    
    def handle_invoice_payment_succeeded(self, event: Dict[str, Any]) -> None:
        """Handle invoice.payment_succeeded webhook."""
        invoice = event["data"]["object"]
        subscription_id = invoice.get("subscription")
        customer_id = invoice.get("customer")
        amount_paid = invoice.get("amount_paid")
        
        logger.info(
            f"Invoice paid: {invoice['id']} subscription {subscription_id} "
            f"amount {amount_paid} cents"
        )
        # TODO: Update subscription status and billing records in database
    
    def handle_invoice_payment_failed(self, event: Dict[str, Any]) -> None:
        """Handle invoice.payment_failed webhook."""
        invoice = event["data"]["object"]
        subscription_id = invoice.get("subscription")
        customer_id = invoice.get("customer")
        
        logger.warning(
            f"Invoice payment failed: {invoice['id']} subscription {subscription_id}"
        )
        # TODO: Notify customer and schedule retry
    
    def handle_customer_subscription_deleted(self, event: Dict[str, Any]) -> None:
        """Handle customer.subscription.deleted webhook."""
        subscription = event["data"]["object"]
        subscription_id = subscription.get("id")
        customer_id = subscription.get("customer")
        
        logger.info(
            f"Subscription deleted: {subscription_id} customer {customer_id}"
        )
        # TODO: Downgrade customer plan in database
    
    def handle_webhook_event(self, event: Dict[str, Any]) -> None:
        """Route webhook event to appropriate handler."""
        event_type = event.get("type")
        
        handlers = {
            "payment_intent.succeeded": self.handle_payment_intent_succeeded,
            "invoice.payment_succeeded": self.handle_invoice_payment_succeeded,
            "invoice.payment_failed": self.handle_invoice_payment_failed,
            "customer.subscription.deleted": self.handle_customer_subscription_deleted,
        }
        
        handler = handlers.get(event_type)
        if handler:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Error handling webhook {event_type}: {e}", exc_info=True)
        else:
            logger.debug(f"Unhandled webhook type: {event_type}")
    
    def _get_or_create_product(self, plan_id: str, plan: PaymentPlan) -> str:
        """Get or create Stripe product for plan."""
        # Search for existing product with this plan_id
        products = stripe.Product.list(
            limit=100,
            metadata={"plan_id": plan_id},
        )
        
        if products.data:
            return products.data[0].id
        
        # Create new product
        product = stripe.Product.create(
            name=f"SecureZim {plan.name}",
            description=plan.name,
            type="service",
            metadata={"plan_id": plan_id},
        )
        
        logger.info(f"Created Stripe product: {product.id} for plan {plan_id}")
        return product.id
    
    def _get_or_create_price(
        self,
        product_id: str,
        plan_id: str,
        plan: PaymentPlan,
    ) -> str:
        """Get or create Stripe price for plan."""
        # Search for existing price
        prices = stripe.Price.list(
            product=product_id,
            limit=100,
        )
        
        if prices.data:
            return prices.data[0].id
        
        # Create new price (recurring, monthly)
        price = stripe.Price.create(
            product=product_id,
            billing_scheme="per_unit",
            unit_amount=plan.monthly_price_cents,
            currency="usd",
            recurring={
                "aggregate_usage": "sum",
                "interval": "month",
                "usage_type": "licensed",
            },
            metadata={"plan_id": plan_id},
        )
        
        logger.info(f"Created Stripe price: {price.id} for plan {plan_id}")
        return price.id
    
    def _subscription_to_response(
        self,
        subscription: stripe.Subscription,
        plan: PaymentPlan,
    ) -> SubscriptionResponse:
        """Convert Stripe subscription to response object."""
        return SubscriptionResponse(
            subscription_id=subscription.id,
            plan_id=plan.plan_id,
            plan_name=plan.name,
            status=subscription.status,
            current_period_start=datetime.fromtimestamp(
                subscription.current_period_start
            ),
            current_period_end=datetime.fromtimestamp(
                subscription.current_period_end
            ),
            amount_paid_cents=plan.monthly_price_cents,
            next_payment_date=datetime.fromtimestamp(
                subscription.current_period_end
            ),
            payment_method=subscription.default_payment_method,
        )


# Global payment processor instance
payment_processor = PaymentProcessor()
