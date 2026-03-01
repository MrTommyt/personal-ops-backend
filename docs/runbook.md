# Runbook

## Secret Rotation
1. Generate new `JWT_ACCESS_SECRET` and `JWT_REFRESH_SECRET`.
2. Deploy with both old/new secret support if zero-downtime rotation is required (current code rotates by replacing secrets and forcing re-login).
3. Rotate `GRAFANA_WEBHOOK_SECRET`, `N8N_SHARED_SECRET`, `N8N_CALLBACK_SECRET` and update corresponding callers.
4. Rotate FCM service account key in GCP and update `FCM_PRIVATE_KEY`.

## Operational Checks
- `GET /health` must return `ok: true`.
- Inspect `outbox` table size; backlog indicates failed push/n8n delivery.
- Check logs for repeated webhook signature failures.

## Common Incidents
- Push failures: verify FCM env vars, ensure service account has `firebase.messaging` scope.
- Grafana webhook unauthorized: verify `X-Grafana-Token` or signature secret match.
- n8n callback unauthorized: verify HMAC sha256 hex in `X-N8N-Signature`.
