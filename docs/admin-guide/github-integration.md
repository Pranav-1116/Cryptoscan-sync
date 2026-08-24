# GitHub integration

1. Create a webhook on the repository: `https://<host>/api/v1/webhooks/github`
2. Content type: `application/json`
3. Secret: `GITHUB_WEBHOOK_SECRET`
4. Events: `push`

A push creates a `GITHUB_WEBHOOK` job. The worker clones the commit and runs the same pipeline as a manual scan.
