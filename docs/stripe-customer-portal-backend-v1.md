# Stripe Customer Portal Backend v1

**Status:** Backend endpoint only

## Endpoint

```text
POST /api/billing/portal
```

Creates a Stripe-hosted Billing Portal Session for the authenticated user's
existing Stripe Customer.

## Request

Requires an authenticated CyberMeters session:

```http
Authorization: Bearer <session-token>
Content-Type: application/json
```

Body:

```json
{
  "return_url": "https://app.cybermeters.com/billing"
}
```

`return_url` must be an absolute `https://` or `http://` URL.

## Behavior

1. Requires authentication.
2. Reads the latest subscription row for the authenticated user from
   `subscriptions`.
3. Requires `subscriptions.stripe_customer_id`.
4. Validates `STRIPE_SECRET_KEY`.
5. Calls Stripe with `fetch`:

```text
POST https://api.stripe.com/v1/billing_portal/sessions
```

6. Sends:
   - `customer`
   - `return_url`
7. Returns the hosted Portal URL.

No D1 rows are updated by this endpoint. Subscription changes made in Stripe
must sync back through `POST /api/billing/webhook`.

## Success Response

```json
{
  "portal_url": "https://billing.stripe.com/...",
  "session_id": "bps_..."
}
```

## Error Responses

| HTTP | Error | Meaning |
| --- | --- | --- |
| `401` | `Unauthorized` | No valid CyberMeters session. |
| `400` | `Invalid JSON body` | Request body is not valid JSON. |
| `400` | `invalid_return_url` | `return_url` is missing or not an absolute HTTP/HTTPS URL. |
| `404` | `subscription_not_found` | No `subscriptions` row exists for the user. |
| `409` | `stripe_customer_missing` | Subscription exists but has no `stripe_customer_id`. |
| `503` | `missing_stripe_config` | `STRIPE_SECRET_KEY` is not configured. |
| `502` | `stripe_api_error` | Stripe returned a non-2xx response. |
| `502` | `stripe_request_failed` | Worker could not reach Stripe. |

## Stripe Dashboard Configuration

Before using this endpoint, configure Customer Portal in Stripe Dashboard:

1. Open Stripe Dashboard.
2. Go to **Settings > Billing > Customer portal**.
3. Enable Customer Portal.
4. Configure allowed subscription update/cancel behavior.
5. Configure permitted payment method and invoice history options.
6. Save the configuration for the active Stripe mode.

Use test mode settings for test keys and live mode settings for live keys.

## Test Curl

```bash
curl -s -X POST https://<worker-host>/api/billing/portal \
  -H "Authorization: Bearer <session-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "return_url": "https://app.cybermeters.com/billing"
  }'
```

Expected success:

```json
{
  "portal_url": "https://billing.stripe.com/...",
  "session_id": "bps_..."
}
```

## D1 Preconditions

The authenticated user must have a `subscriptions` row with a Stripe customer:

```sql
SELECT s.id, s.stripe_customer_id
FROM subscriptions s
JOIN workspaces w ON w.id = s.workspace_id
WHERE w.owner_user_id = 'USER_ID'
ORDER BY s.created_at DESC
LIMIT 1;
```

`stripe_customer_id` is written by webhook lifecycle events after Checkout.

## Non-Goals

- No frontend UI.
- No Stripe SDK.
- No checkout changes.
- No webhook lifecycle changes.
- No D1 writes.
- No plan activation.
- No manual cancellation.
- No trial logic.
- No feature gating.
- No pricing changes.
