"""CryptoScan API service — FastAPI application package (app, routers, middleware, security).

Modules:
- dependencies: FastAPI dependencies
- graph_builder: Build a graph view from PostgreSQL / SQLite, then prefer Neo4j
- main: CryptoScan API + dashboard host

Subpackages: config, github, intelligence, middleware, routers, schemas, security, webhooks.
"""
