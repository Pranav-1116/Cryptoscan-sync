"""Prepare PRIVATE disposable TLS/ACL/Sentinel fixtures, never production config.

Does not start processes. Supply a TLS-enabled redis-server separately and run
its six config files under a supervisor. Output contains credentials: keep this
outside the repository and never attach the state directory to a report.
"""

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess


def prepare(root):
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if any(root.iterdir()):
        raise ValueError("Use a new empty private directory")
    os.chmod(root, 0o700)
    old_mask = os.umask(0o077)
    try:

        def openssl(*args):
            subprocess.run(
                ["openssl", *map(str, args)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

        openssl(
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=disposable-replay-lab-ca",
            "-keyout",
            root / "ca.key",
            "-out",
            root / "ca.pem",
        )
        openssl(
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=replay-lab",
            "-keyout",
            root / "server.key",
            "-out",
            root / "server.csr",
        )
        (root / "extensions").write_text("subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n")
        openssl(
            "x509",
            "-req",
            "-in",
            root / "server.csr",
            "-CA",
            root / "ca.pem",
            "-CAkey",
            root / "ca.key",
            "-CAcreateserial",
            "-days",
            "2",
            "-extfile",
            root / "extensions",
            "-out",
            root / "server.pem",
        )
        passwords = {name: secrets.token_hex(24) for name in ("operator", "replay", "observer", "limited")}
        data_ports, sentinel_ports = [15379, 15380, 15381], [16379, 16380, 16381]
        app_commands = "+ping +info +get +set +incr +incrby +type +exists +hgetall +hset +xrange +xrevrange +xadd +multi +exec +discard +watch +unwatch +publish +subscribe +psubscribe +unsubscribe +punsubscribe +del +expire +wait"
        common = f"""bind 0.0.0.0
port 0
protected-mode yes
tls-cert-file {root / "server.pem"}
tls-key-file {root / "server.key"}
tls-ca-cert-file {root / "ca.pem"}
tls-auth-clients no
tls-protocols "TLSv1.2 TLSv1.3"
tls-replication yes
user default off
user operator on >{passwords["operator"]} ~* &* +@all
"""
        for index, port in enumerate(data_ports):
            directory = root / f"data-{port}"
            directory.mkdir()
            (root / f"redis-{port}.conf").write_text(
                common
                + f"""tls-port {port}
dir {directory}
appendonly yes
appendfsync always
save ""
min-replicas-to-write 1
min-replicas-max-lag 5
masteruser operator
masterauth {passwords["operator"]}
replica-announce-ip 127.0.0.1
replica-announce-port {port}
user replay on >{passwords["replay"]} ~zelinx:events:* ~zelinx:current_run* &zelinx:events* {app_commands}
user limited on >{passwords["limited"]} ~zelinx:events:* &zelinx:events* +ping +get +type +exists +hgetall +xrange +xrevrange +multi +exec +discard +watch +unwatch +del
"""
                + (f"replicaof 127.0.0.1 {data_ports[0]}\n" if index else "")
            )
        for port in sentinel_ports:
            (root / f"sentinel-{port}.conf").write_text(
                common
                + f"""tls-port {port}
sentinel monitor estate-lab 127.0.0.1 {data_ports[0]} 2
sentinel auth-user estate-lab operator
sentinel auth-pass estate-lab {passwords["operator"]}
sentinel sentinel-user operator
sentinel sentinel-pass {passwords["operator"]}
sentinel announce-ip 127.0.0.1
sentinel announce-port {port}
sentinel down-after-milliseconds estate-lab 1000
sentinel failover-timeout estate-lab 5000
user observer on >{passwords["observer"]} +ping +sentinel|masters +sentinel|get-master-addr-by-name +sentinel|sentinels +sentinel|replicas
"""
            )
        settings = {
            "ENVIRONMENT": "production",
            "REDIS_URL": f"rediss://replay:{passwords['replay']}@127.0.0.1:{data_ports[0]}/0",
            "REDIS_CA_CERTS": str(root / "ca.pem"),
            "REDIS_SENTINELS": json.dumps([["127.0.0.1", port] for port in sentinel_ports]),
            "REDIS_SENTINEL_MASTER": "estate-lab",
            "REDIS_SENTINEL_USERNAME": "observer",
            "REDIS_SENTINEL_PASSWORD": passwords["observer"],
        }
        (root / "lab.json").write_text(
            json.dumps(
                {
                    "disposable": True,
                    "settings": settings,
                    "passwords": passwords,
                    "data_ports": data_ports,
                    "sentinel_ports": sentinel_ports,
                }
            )
        )
    finally:
        os.umask(old_mask)
    print("Prepared six private configuration files; no process started. State:", root / "lab.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True)
    prepare(parser.parse_args().state_dir)
