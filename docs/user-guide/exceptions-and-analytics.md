# Exceptions and analytics

## Policy exceptions

`POST /api/v1/exceptions` opens a PENDING exception. CISO/CTO approve or
reject; approval stores an HMAC signature of `{id}|approver|timestamp`.
`POST /exceptions/expire-due` flips past-due APPROVED rows to EXPIRED and
returns linked assets to FAIL.

## Analytics

`GET /api/v1/analytics` returns algorithm trends, compliance rate, a
business-unit heat map, a linear PQC forecast, prioritized recommendations,
and a one-page executive summary. Nothing in this path is a policy decision.
