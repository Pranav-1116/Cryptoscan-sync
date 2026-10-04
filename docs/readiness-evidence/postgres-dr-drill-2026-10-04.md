# PostgreSQL disaster-recovery drill

Run: `2026-10-04T13:46:20.659256+00:00`  |  Mode: `promotion`  |  Verdict: **PASS**

This report is valid only with the two PostgreSQL instance logs, the
promotion command output and the archived release/configuration digest.
It is not a simulation or a substitute for an auditor-witnessed drill.

| Check | Result | Detail |
|---|---|---|
| primary reachable | PASS | psycopg2 |
| standby reachable | PASS | psycopg2 |
| primary is writable | PASS | pg_is_in_recovery=False |
| standby is in recovery | PASS | pg_is_in_recovery=True |
| wal_level is replica/logical | PASS | replica |
| primary reports streaming standby | PASS | [{"application_name": "walreceiver", "client_addr": "127.0.0.1/32", "state": "streaming", "sync_state": "async", "sent_lsn": "0/7000060", "write_lsn": "0/7000060", "flush_lsn": "0/7000060", "replay_lsn": "0/7000060"}] |
| drill marker replicated | PASS | marker=cryptoscan-dr-b80f17d3a61d41bfb03871ad7eafceda; replication_seconds=0.001 |
| audit/evidence tables inspected | PASS | {"audit_log": 57, "evidence_records": 3, "scans": 3, "scan_jobs": 3} |
| primary:audit_log present | PASS | audit_log |
| primary:audit_log has timestamp | PASS | columns=action,actor,chain_sequence,created_at,detail,entry_hash,id,ip_address,outcome,previous_hash,target_id,target_type,updated_at |
| primary:audit_log hash fields complete | PASS | {"chain_sequence": 0, "entry_hash": 0} |
| primary:audit chain continuity | PASS | rows=57 first_previous_empty=True |
| primary:evidence_records present | PASS | evidence_records |
| primary:evidence_records has timestamp | PASS | columns=algorithm,algorithm_family,chain_hash,chain_position,class_name,compliance_status,confidence,content_hash,created_at,file_path,finding_data,highest_severity_failed,id,is_hardcoded_key,key_size,line_number,method_name,mode,nist_designation,normalization_confidence,normalization_status,normalization_version,normalized_algorithm,normalized_crypto,padding,policy_evaluated_at,policy_evaluation,policy_version,previous_hash,provenance |
| primary:evidence_records hash fields complete | PASS | {"chain_hash": 0, "chain_position": 0, "content_hash": 0} |
| promotion command succeeded | PASS | waiting for server to promote.... done
server promoted |
| standby promoted to writable | PASS | rto_seconds=0.104 |
| marker survives promotion | PASS | cryptoscan-dr-b80f17d3a61d41bfb03871ad7eafceda |
| audit_log count not lost | PASS | before=57 after=57 |
| evidence_records count not lost | PASS | before=3 after=3 |
| scans count not lost | PASS | before=3 after=3 |
| scan_jobs count not lost | PASS | before=3 after=3 |
| API ready after failover | PASS | HTTP 200 |
| worker recovery command | PASS | worker recovery probe: reconnected; scan_jobs=3 scans=3
redis_unavailable_memory_fallback |
| clean restore target has no drill marker | PASS | cryptoscan-dr-b80f17d3a61d41bfb03871ad7eafceda |
| clean restore command succeeded | PASS | restore output withheld; elapsed=0.901s |
| clean restore reachable | PASS | psycopg2 |
| clean restore contains drill marker | PASS | cryptoscan-dr-b80f17d3a61d41bfb03871ad7eafceda |
| clean_restore:audit_log present | PASS | audit_log |
| clean_restore:audit_log has timestamp | PASS | columns=action,actor,chain_sequence,created_at,detail,entry_hash,id,ip_address,outcome,previous_hash,target_id,target_type,updated_at |
| clean_restore:audit_log hash fields complete | PASS | {"chain_sequence": 0, "entry_hash": 0} |
| clean_restore:audit chain continuity | PASS | rows=57 first_previous_empty=True |
| clean_restore:evidence_records present | PASS | evidence_records |
| clean_restore:evidence_records has timestamp | PASS | columns=algorithm,algorithm_family,chain_hash,chain_position,class_name,compliance_status,confidence,content_hash,created_at,file_path,finding_data,highest_severity_failed,id,is_hardcoded_key,key_size,line_number,method_name,mode,nist_designation,normalization_confidence,normalization_status,normalization_version,normalized_algorithm,normalized_crypto,padding,policy_evaluated_at,policy_evaluation,policy_version,previous_hash,provenance |
| clean_restore:evidence_records hash fields complete | PASS | {"chain_hash": 0, "chain_position": 0, "content_hash": 0} |

**RPO seconds:** `0.0`
**RTO seconds:** `0.104`
