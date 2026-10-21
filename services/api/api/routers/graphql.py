"""``POST /graphql`` — the read-only query surface for scan results.

Why it exists next to REST: a binary scan fans out into artifacts, components,
crypto assets, findings, YARA matches and jobs, and answering "which of last
week's firmware images carry a banned cipher and what else is in those images"
over REST is four round trips and two joins in the client. GraphQL answers it in
one query, with the fields the caller asked for and nothing else.

Read-only by construction: only ``query`` operations are accepted, mutations and
subscriptions are refused by the parser itself (see :mod:`api.graphql_lang`), and
the endpoint requires the same reader roles as the REST read endpoints. Every
answer reports the limits in force, the fields resolved, and whether a list was
truncated — a bounded answer that says so is usable; one that stays quiet is not.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import TenantContext, get_db_session, require_roles
from api.security.estate_history import history_context

router = APIRouter(tags=["graphql"])

READER_ROLES = ("admin", "superadmin", "security_analyst", "auditor", "readonly")


class GraphQLRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=100_000,
                       description="a GraphQL query document (queries only; writes are refused)")
    variables: dict[str, Any] | None = Field(None, description=(
        "values for the query's $variables; a declared variable with no value and no "
        "default is an error naming it"))
    operationName: str | None = Field(None, description=(
        "accepted for client compatibility; a document may carry exactly one operation, so "
        "there is nothing to select between"))


@router.post("/graphql")
def graphql_post(body: GraphQLRequest, request: Request, db: Session = Depends(get_db_session),
                 user: str = Depends(require_roles(*READER_ROLES)), ctx: TenantContext = Depends(history_context)):
    """Run one read-only query. 200 with an ``errors`` array, or 400 for a non-query document.

    The status codes say which kind of problem it is: **400** when the document is
    not something this surface can run at all (a mutation, a subscription, a syntax
    error, an over-limit query), **200** with ``errors`` when a field could not be
    resolved (partial success is normal and the data that did resolve is kept), and
    **405** for the verbs a query endpoint does not answer.
    """
    from api import graphql_schema
    from api.graphql_lang import GraphQLSyntaxError, parse

    try:
        parse(body.query, variables=body.variables)
    except GraphQLSyntaxError as exc:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST,
                            content={"data": None,
                                     "errors": [{"message": str(exc), "path": [],
                                                 "extensions": {"code": "INVALID_QUERY"}}],
                                     "extensions": {"read_only": True}})
    # the same tenant resolution the REST artifact surface uses: a tenant-bound
    # key reads its own bucket, a session may name X-Tenant-ID with a membership,
    # anything else is the platform estate

    tenant_id = ctx.tenant_id
    result = graphql_schema.query(body.query, variables=body.variables, session=db,
                                  tenant_id=tenant_id)
    result.setdefault("extensions", {})["surface"] = "/api/v1/graphql"
    return result


@router.get("/graphql")
def graphql_get(request: Request, query: str, variables: str | None = None,
                db: Session = Depends(get_db_session),
                user: str = Depends(require_roles(*READER_ROLES)), ctx: TenantContext = Depends(history_context)):
    """The same query over GET, for a browser address bar or a curl smoke test.

    ``variables`` is a JSON object in the query string. A malformed one is a 400
    naming it, not an ignored argument — silently dropping variables would run the
    query with the wrong values.
    """
    import json

    bound: dict[str, Any] | None = None
    if variables:
        try:
            bound = json.loads(variables)
        except json.JSONDecodeError as exc:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST,
                                content={"errors": [{"message": f"variables is not JSON: {exc}",
                                                     "extensions": {"code": "BAD_VARIABLES"}}],
                                         "data": None})
        if not isinstance(bound, dict):
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST,
                                content={"errors": [{"message": "variables must be a JSON object",
                                                     "extensions": {"code": "BAD_VARIABLES"}}],
                                         "data": None})
    return graphql_post(GraphQLRequest(query=query, variables=bound), request=request, db=db, user=user, ctx=ctx)


@router.get("/graphql/schema")
def graphql_schema_document(user: str = Depends(require_roles(*READER_ROLES))):
    """Introspection-lite: the types and root fields this surface resolves.

    Deliberately not the full introspection protocol: a client that needs
    ``__schema { types { fields { args } } }`` in spec form should be told where
    this ends, and this endpoint is that statement.
    """
    from api import graphql_schema

    return {
        "schema": "cryptoscan-graphql-lite",
        "read_only": True,
        "root_fields": {
            "binaryArtifacts": {"args": ["kind", "q", "limit"], "returns": "[BinaryArtifact]"},
            "binaryArtifact": {"args": ["id"], "returns": "BinaryArtifact"},
            "binaryJobs": {"args": ["limit", "jobType"], "returns": "[Job]"},
            "binaryJob": {"args": ["id"], "returns": "Job"},
            "binaryBatch": {"args": ["batchId"], "returns": "Batch"},
            "knowledge": {"args": [], "returns": "Knowledge"},
            "runtimeFindings": {"args": ["limit", "kind", "weakOnly"], "returns": "RuntimeFindings"},
            "__schema": {"args": [], "returns": "Schema"},
        },
        "types": graphql_schema.SCHEMA_DOC,
        "limits": {"depth": 12, "fields": 500, "list": 200},
        "refused": ["mutation", "subscription", "directives other than @skip/@include"],
        "note": ("every field resolves from what the platform already stored — the artifact "
                 "store, the job rows, the installed rule packs and the runtime-finding "
                 "inventory — so a GraphQL answer and a REST answer are the same facts"),
    }


@router.api_route("/graphql", methods=["PUT", "PATCH", "DELETE"], include_in_schema=False)
def graphql_other_verbs(request: Request, user: str = Depends(require_roles(*READER_ROLES))):
    """Writes are not here — say where they are instead of a bare 405."""
    return JSONResponse(
        status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
        headers={"Allow": "GET, POST"},
        content={"errors": [{
            "message": (f"{request.method} is not supported: this surface is read-only. Writes "
                        "live on the REST endpoints, each with its own roles and audit trail."),
            "extensions": {"code": "READ_ONLY_SURFACE"}}],
            "data": None})
