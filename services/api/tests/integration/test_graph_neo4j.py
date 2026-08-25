import pytest
from httpx import AsyncClient


class TestGraphNeo4j:
    @pytest.mark.asyncio
    async def test_graph_health_reports_backend(self, authenticated_client: AsyncClient):
        response = await authenticated_client.get("/api/v1/graph/health")
        assert response.status_code == 200
        body = response.json()
        assert body["backend"] in {"neo4j", "memory"}
        assert "ok" in body
        assert "configured" in body
