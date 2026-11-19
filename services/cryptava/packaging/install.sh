#!/bin/sh
# Install Cryptava on one Linux server (systemd). Needs only python3 >= 3.9.
#
#   sudo ./install.sh --server https://cryptoscan.bank.example \
#        --agent-id <id> --token <one-time-token>          # token from the console
#
#   # or, for scripted rollouts, with an admin API key in the environment:
#   sudo CRYPTAVA_PROVISION_KEY=... ./install.sh --server https://... --name mrdn-prod-dc1-swiftgw01
#
# Options: --config FILE (use your own cryptava.toml), --ca-file FILE, --no-start,
#          --asset-record FILE (this server's CMDB record: hardware identity + vendor
#          contracts, JSON — see cryptava/register.py; makes HBOM/VBOM complete)
set -eu

SERVER="" AGENT_ID="" TOKEN="" NAME="" CONFIG="" CA_FILE="" ASSET_RECORD="" START=1
while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="$2"; shift 2 ;;
    --agent-id) AGENT_ID="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;;
    --config) CONFIG="$2"; shift 2 ;;
    --ca-file) CA_FILE="$2"; shift 2 ;;
    --asset-record) ASSET_RECORD="$2"; shift 2 ;;
    --no-start) START=0; shift ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" = "0" ] || { echo "run as root (sudo)" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
  || { echo "python3 >= 3.9 is required" >&2; exit 1; }

HERE="$(cd "$(dirname "$0")/.." && pwd)"   # services/cryptava
PREFIX=/opt/cryptava

echo "==> installing the agent into $PREFIX"
rm -rf "$PREFIX.new"
mkdir -p "$PREFIX.new"
cp -R "$HERE/cryptava" "$PREFIX.new/"
cp "$HERE/README.md" "$PREFIX.new/" 2>/dev/null || true
find "$PREFIX.new" -name __pycache__ -prune -exec rm -rf {} +
rm -rf "$PREFIX" && mv "$PREFIX.new" "$PREFIX"
chmod -R go-w "$PREFIX"

cat > /usr/local/bin/cryptava <<EOF
#!/bin/sh
export PYTHONPATH="$PREFIX\${PYTHONPATH:+:\$PYTHONPATH}"
exec python3 -m cryptava "\$@"
EOF
chmod 0755 /usr/local/bin/cryptava

echo "==> configuration"
mkdir -p /etc/cryptava
if [ -n "$CONFIG" ]; then
  install -m 0644 "$CONFIG" /etc/cryptava/cryptava.toml
elif [ ! -f /etc/cryptava/cryptava.toml ] && [ ! -f /etc/cryptava/cryptava.json ]; then
  # TOML needs python >= 3.11; older pythons get the same settings as JSON
  if python3 -c 'import tomllib' 2>/dev/null; then
    install -m 0644 "$HERE/packaging/config/cryptava.toml.example" /etc/cryptava/cryptava.toml
    [ -n "$SERVER" ] && sed -i "s#^server = .*#server = \"$SERVER\"#" /etc/cryptava/cryptava.toml
    [ -n "$CA_FILE" ] && sed -i "s#^\# ca_file = .*#ca_file = \"$CA_FILE\"#" /etc/cryptava/cryptava.toml
  else
    printf '{"server": "%s"%s}\n' "$SERVER" "${CA_FILE:+, \"ca_file\": \"$CA_FILE\"}" > /etc/cryptava/cryptava.json
    chmod 0644 /etc/cryptava/cryptava.json
  fi
fi
if [ -n "$ASSET_RECORD" ]; then
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert isinstance(d, dict)' "$ASSET_RECORD" \
    || { echo "--asset-record: $ASSET_RECORD is not a JSON object" >&2; exit 2; }
  install -m 0644 "$ASSET_RECORD" /etc/cryptava/asset-record.json
  echo "    asset register record -> /etc/cryptava/asset-record.json"
fi
install -d -m 0700 /var/lib/cryptava

echo "==> enrolment"
if [ -f /var/lib/cryptava/identity.json ]; then
  echo "    already enrolled — keeping the existing identity"
elif [ -n "$AGENT_ID" ] && [ -n "$TOKEN" ]; then
  CRYPTAVA_ENROLLMENT_TOKEN="$TOKEN" cryptava enroll ${SERVER:+--server "$SERVER"} --agent-id "$AGENT_ID"
elif [ -n "$NAME" ] && [ -n "${CRYPTAVA_PROVISION_KEY:-}" ]; then
  cryptava enroll ${SERVER:+--server "$SERVER"} --name "$NAME"
else
  echo "    not enrolled yet: run  cryptava enroll --agent-id <id> --token <token>  then  systemctl start cryptava"
  START=0
fi

echo "==> first collection (nothing is sent)"
cryptava collect || true

if command -v systemctl >/dev/null; then
  install -m 0644 "$HERE/packaging/systemd/cryptava.service" /etc/systemd/system/cryptava.service
  systemctl daemon-reload
  if [ "$START" = "1" ]; then
    systemctl enable --now cryptava
    echo "==> cryptava is running:  systemctl status cryptava  ·  cryptava status"
  else
    echo "==> installed; start with:  systemctl enable --now cryptava"
  fi
fi
