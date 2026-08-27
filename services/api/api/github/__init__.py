"""GitHub integration clients (status poster, app auth) for scan feedback.

Modules:
- acr_webhook_handler: Azure Container Registry push-event adapter
- ecr_webhook_handler: AWS ECR push-event adapter for the API webhook layer
- gcr_webhook_handler: GCR / Artifact Registry push-event adapter
- payload_parser: Parse GitHub webhook payloads
- status_poster: Post commit status back to GitHub (optional)
- webhook_handler
"""
