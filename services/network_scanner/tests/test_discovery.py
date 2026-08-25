from network_scanner.core.scanner import NetworkTlsScanner
from network_scanner.discovery.config_file_loader import load_targets
from network_scanner.discovery.kubernetes_discoverer import discover_from_tree


def test_load_targets_and_k8s_ingress(tmp_path):
    cfg = tmp_path / "network-scan-targets.yaml"
    cfg.write_text(
        """
targets:
  - endpoint: api.payment.example.com:443
    system_id: payment-api
    scan_frequency: daily
"""
    )
    targets = load_targets(cfg)
    assert targets[0]["endpoint"] == "api.payment.example.com:443"
    k8s = tmp_path / "ingress.yaml"
    k8s.write_text(
        """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: pay
spec:
  tls:
    - hosts: ["pay.example.com"]
  rules:
    - host: pay.example.com
      http:
        paths: []
---
apiVersion: v1
kind: Service
metadata:
  name: payments
spec:
  ports:
    - name: https
      port: 8443
"""
    )
    found = discover_from_tree(tmp_path)
    endpoints = {item["endpoint"] for item in found}
    assert "pay.example.com:443" in endpoints
    assert "payments:8443" in endpoints


def test_filesystem_scan_is_offline_by_default(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "network-scan-targets.yaml").write_text(
        "targets:\n  - endpoint: 203.0.113.9:443\n"
    )
    result = NetworkTlsScanner(live=False).scan_filesystem(tmp_path)
    assert result["live"] is False
    assert result["probes"] == []
    assert result["targets"]
