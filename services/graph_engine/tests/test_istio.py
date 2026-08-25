from graph_engine.service_mesh.istio_client import parse_prometheus_result
from graph_engine.service_mesh.service_call_extractor import extract_calls


def test_parse_prometheus_istio_metrics():
    body = {
        "data": {
            "result": [
                {
                    "metric": {"source_workload": "payment-api", "destination_workload": "customer-db"},
                    "value": [0, "150000"],
                }
            ]
        }
    }
    edges = parse_prometheus_result(body)
    assert edges == [
        {
            "parent_id": "payment-api",
            "child_id": "customer-db",
            "protocol": "istio",
            "frequency": 150000,
            "relation": "CALLS",
            "data_source": "istio-telemetry",
        }
    ]
    assert extract_calls(edges)[0]["parent_id"] == "payment-api"
