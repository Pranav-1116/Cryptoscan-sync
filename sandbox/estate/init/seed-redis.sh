#!/bin/sh
# Preload banking-flavored session/cache keys so the Redis scanner finds a
# live estate instead of an empty one.
set -e
redis-cli -h redis <<'EOF'
SET session:ibank:CU-1001 '{"user":"CU-1001","channel":"web","ttl":1800,"mfa":"passed"}'
SET session:ibank:CU-1003 '{"user":"CU-1003","channel":"mobile","ttl":1800,"mfa":"passed"}'
SET session:mobile:CU-1005 '{"user":"CU-1005","channel":"mobile","ttl":600,"mfa":"pending"}'
SET rate:upi:outbound:BR-001 1423
SET rate:swift:outbound:HO 87
SET fx:INR-USD 83.42
SET fx:INR-AED 22.71
SET cache:branch:BR-002:last_settlement "2026-11-16T09:30:00Z"
SET feature:pgc-migration-pilot "enabled:mobile-api"
EOF
echo "redis sandbox keys loaded"
