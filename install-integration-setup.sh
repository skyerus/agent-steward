#!/bin/bash
set -Eeuo pipefail
umask 077

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
host=${1:?Usage: install-integration-setup.sh SIGN_IN_HOST}
if (( EUID != 0 )) || (( ${#host} > 253 )) ||
    ! [[ $host =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$ ]]; then
  echo "Run as root with a public DNS hostname reserved for integration sign-in." >&2
  exit 1
fi

base=/opt/sable/review-gateway
node=/opt/sable/node/bin/node
code=/opt/sable/integrations/lifecycle
shared=/opt/sable/agent-templates/skills
config=/var/lib/sable-claw/state/openclaw.json
gateway_unit=/etc/systemd/system/sable-agentgateway.service.d/50-connection-broker.conf
broker_unit=/etc/systemd/system/sable-connection-broker.service.d/50-sign-in.conf
git_unit=/etc/systemd/system/sable-connection-broker.service.d/60-native-git.conf
relay_config=/etc/sable-codex/Caddyfile
oauth_clients=/etc/sable-connection-broker/oauth-clients.json
policy_unit=/etc/systemd/system/sable-review-policy.service.d/50-broker-access.conf
onboarding_isolation=/etc/systemd/system/sable-claw.service.d/85-discord-onboarding-isolation.conf
admin_workspace=/var/lib/sable-codex/workspaces/integration-admin
caddy_config=/etc/caddy/Caddyfile
marker='# Managed by the Sable integration sign-in installer.'

test -x "$base/claw" && test -x "$base/agentgateway" && test -x "$node"
if ! systemctl is-active --quiet sable-native-worker.service ||
   ! test -r /run/sable-native-policy/receipt.json; then
  echo "Prepare the isolated native worker before installing Integration Admin." >&2
  exit 1
fi
test -r /opt/sable/integrations/node_modules/@modelcontextprotocol/sdk/package.json
admins=${SABLE_ADMIN_USERS:-}
if [ -z "$admins" ] && [ -r "$broker_unit" ]; then
  admins=$(sed -n 's/^Environment=SABLE_ADMIN_USERS=//p' "$broker_unit")
fi
if [ -n "${SABLE_SIGN_IN_DNS_HOOK:-}" ]; then
  "$SABLE_SIGN_IN_DNS_HOOK" "$host"
fi
getent ahostsv4 "$host" >/dev/null
if ! command -v caddy >/dev/null; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y caddy
fi
if ! grep -Fxq "$marker" "$caddy_config" &&
   ! cmp -s "$caddy_config" /usr/share/caddy/Caddyfile; then
  # Ubuntu's unmodified default site has one active file_server on port 80.
  if ! diff -q <(sed -E '/^[[:space:]]*(#|$)/d; s/^[[:space:]]+//' "$caddy_config") \
      <(printf ':80 {\nroot * /usr/share/caddy\nfile_server\n}\n') >/dev/null; then
    echo "The existing Caddy configuration does not belong to this installer." >&2
    exit 1
  fi
fi

getent group sable-reviewed >/dev/null || groupadd --system sable-reviewed
getent passwd sable-broker >/dev/null || useradd --system --user-group --no-create-home \
  --home-dir /var/lib/sable-connection-broker --shell /usr/sbin/nologin sable-broker

stage=$(mktemp -d /root/sable-agent-install.XXXXXXXX)
backup="$stage/backup"
mkdir "$backup"
files=(registry.mjs public-fetch.mjs remote.mjs broker.mjs browser-pairing.mjs github-registration.mjs github-native.mjs stdio-bridge.mjs access.mjs unix-request.mjs)
for file in "${files[@]}" review-plugin.mjs native-worker-policy.mjs schedule-tool.mjs lifecycle.test.mjs; do
  "$node" --check "$source_dir/broker/$file"
done
mkdir "$stage/deps"
cp "$source_dir/broker/"{package.json,package-lock.json} "$stage/deps/"
"$node" /opt/sable/node/bin/npm ci --prefix "$stage/deps" --omit=dev --ignore-scripts --no-audit --no-fund

python3 - "$base/agentgateway.yaml" "$config" "$stage" "$shared" "$admins" "$admin_workspace" <<'PY'
import copy
import json
from pathlib import Path
import re
import sys

gateway, claw, stage, shared, admins, admin_workspace = sys.argv[1:]
admins = list(dict.fromkeys(filter(None, admins.split(","))))
stage = Path(stage)
cfg = json.loads(Path(gateway).read_text())
app = json.loads(Path(claw).read_text())
if app.get("mcp", {}).get("servers"):
    raise SystemExit("The native worker must own the MCP transport before running this installer.")
legacy = {"gmail", "freeagent-sable", "netlify", "supabase-cms"}
registry = "integrations"
routes = cfg.setdefault("routes", [])
gateways = cfg.setdefault("gateways", {})
legacy_routes = []
managed = []
for route in routes:
    names = route.get("gateways", [])
    if len(names) != 1 or names[0] not in (legacy | {registry}):
        raise SystemExit("An existing review route is outside the installer layout.")
    name = names[0]
    if name != registry:
        legacy_routes.append(name)
    if name in managed:
        raise SystemExit("The review routes contain duplicate connection names.")
    managed.append(name)

if registry not in managed:
    if any(gateway["port"] == 17895 for gateway in gateways.values()):
        raise SystemExit("The integration management port is already assigned.")
    gateways[registry] = {"bindAddress": "127.0.0.1", "port": 17895}
    if routes:
        route = copy.deepcopy(routes[0])
        route["gateways"] = [registry]
        route["backends"][0]["mcp"]["targets"][0]["name"] = registry
    else:
        blocked = ("resources/read", "resources/list", "resources/templates/list", "prompts/get", "prompts/list")
        methods = {method: "request" for method in ("tools/call", *blocked)}
        methods["tools/list"] = "response"
        processor = {"kind": "remote", "host": "127.0.0.1:17887", "failureMode": "failClosed", "methods": methods}
        route = {"gateways": [registry], "policies": {"mcpGuardrails": {"processors": [processor]}},
                 "backends": [{"mcp": {"targets": [{"name": registry}]}}]}
    routes.append(route)

for route in routes:
    name = route["gateways"][0]
    binding = gateways[name]
    if binding["bindAddress"] != "127.0.0.1":
        raise SystemExit("The integration management stack requires loopback-only MCP routes.")
    processors = route["policies"]["mcpGuardrails"]["processors"]
    if not any(p["host"] == "127.0.0.1:17887" and p["failureMode"] == "failClosed" and
               p["methods"]["tools/call"] == "request" for p in processors):
        raise SystemExit("The integration approval policy is missing.")
    route["backends"][0]["mcp"]["targets"][0]["stdio"] = {
        "cmd": "/opt/sable/node/bin/node",
        "args": ["/opt/sable/integrations/lifecycle/stdio-bridge.mjs", name],
    }

settings = app.get("skills", {}).get("load", {}).get("extraDirs", [])
settings = list(dict.fromkeys([*settings, shared]))
discord = app.get("channels", {}).get("discord", {})
prior_dm = discord.get("allowFrom", []) if discord.get("dmPolicy") == "allowlist" else []
users = list(dict.fromkeys(str(user) for user in prior_dm if str(user).isdigit()))
bindings = app.get("bindings", [])
legacy_grants = {name: app.get("mcp", {}).get("servers", {}).get(name, {}).get("codex", {}).get("agents", [])
                 for name in legacy_routes}
existing_admin = app.get("agents", {}).get("entries", {}).get("integration-admin")
if existing_admin and existing_admin.get("workspace") != admin_workspace:
    raise SystemExit("The Integration Admin ID is already in use by another workspace.")
if existing_admin is None:
    if not admins or any(not re.fullmatch(r"[0-9]{16,22}", user) for user in admins):
        raise SystemExit("Set SABLE_ADMIN_USERS to the Discord user IDs for the initial Integration Admin.")
    for binding in bindings:
        match = binding.get("match", {})
        peer = match.get("peer", {})
        if (match.get("channel") == "discord" and match.get("accountId", "default") == "default"
                and peer.get("kind") == "direct" and peer.get("id") in admins):
            raise SystemExit("An initial admin already has a Discord DM assigned to another agent.")
    users = list(dict.fromkeys([*users, *admins]))
    admin_bindings = [{"agentId": "integration-admin", "match": {"channel": "discord", "accountId": "default",
                       "peer": {"kind": "direct", "id": user}}} for user in admins]
    bindings = [*admin_bindings, *bindings]
tool_policy = app.get("tools", {})
skill_readers = ["skills_search", "skills_read", "manage_schedule"]
delegation_tools = ["sessions_spawn", "sessions_yield", "subagents"]
native_tools = {"exec", "process", "read", "write", "edit", "apply_patch"}
admin_denials = (existing_admin or {}).get("tools", {}).get("deny", [])
profile_extensions = list(dict.fromkeys([
    *tool_policy.get("alsoAllow", []), *skill_readers, *delegation_tools,
]))
sandbox_extensions = list(dict.fromkeys([
    *tool_policy.get("sandbox", {}).get("tools", {}).get("alsoAllow", []), *skill_readers,
]))
patch = {
    "tools": {"alsoAllow": profile_extensions, "sandbox": {"tools": {"alsoAllow": sandbox_extensions}}},
    "skills": {"load": {"extraDirs": settings}},
    "channels": {"discord": {"dmPolicy": "allowlist", "allowFrom": users}},
    "bindings": bindings,
    "agents": {"entries": {"integration-admin": {
        "name": "Integration Admin", "identity": {"name": "Integration Admin"}, "workspace": admin_workspace,
        "tools": {"deny": [tool for tool in admin_denials if tool not in native_tools]},
    }}},
}
(stage / "gateway.json").write_text(json.dumps(cfg, indent=2) + "\n")
(stage / "claw-patch.json").write_text(json.dumps(patch))
(stage / "legacy").write_text(",".join(legacy_routes))
(stage / "legacy-grants").write_text(json.dumps(legacy_grants, separators=(",", ":")))
PY

claw() { runuser -u sable-claw -- "$base/claw" "$@"; }
"$base/agentgateway" -f "$stage/gateway.json" --validate-only
claw config patch --stdin --dry-run < "$stage/claw-patch.json" >/dev/null

cat > "$stage/Caddyfile" <<CADDY
$marker
$host {
    @signin {
        method GET POST
        path /connect/* /oauth/callback
    }
    handle @signin {
        reverse_proxy 127.0.0.1:17896
    }
    handle {
        respond 404
    }
}
CADDY
caddy fmt --overwrite "$stage/Caddyfile"
caddy validate --config "$stage/Caddyfile" >/dev/null
python3 - "$relay_config" "$source_dir/broker/relay-git.caddy" "$stage/git-relay.Caddyfile" <<'PYTHON'
from pathlib import Path
import sys
current, source, target = map(Path, sys.argv[1:])
text, route = current.read_text(), source.read_text()
fallback = "\trespond 404"
if route in text:
    if text.count(route) != 1:
        raise SystemExit("Duplicate native Git route")
elif "/__sable_git__/" not in text and text.count(fallback) == 1:
    text = text.replace(fallback, route + fallback)
else:
    raise SystemExit("The native relay did not match the expected layout.")
target.write_text(text)
PYTHON
caddy validate --adapter caddyfile --config "$stage/git-relay.Caddyfile" >/dev/null
printf '[Service]\nEnvironment=SABLE_SIGN_IN_ORIGIN=https://%s\nEnvironment=SABLE_LEGACY_CONNECTIONS=%s\n' \
  "$host" "$(cat "$stage/legacy")" > "$stage/broker.conf"
printf "Environment='SABLE_LEGACY_GRANTS=%s'\n" "$(cat "$stage/legacy-grants")" >> "$stage/broker.conf"
printf '[Service]\nSupplementaryGroups=\nSupplementaryGroups=sable-broker\n' > "$stage/gateway.conf"
printf '[Service]\nSupplementaryGroups=sable-broker\n' > "$stage/policy.conf"
printf '[Service]\nInaccessiblePaths=/var/lib/sable-discord-onboarding /run/sable-agent-provisioner\n' \
  > "$stage/onboarding-isolation.conf"

changed=(
  "$base/agentgateway.yaml" "$base/plugin/index.mjs" "$base/plugin/native-worker-policy.mjs" "$base/plugin/schedule-tool.mjs" "$base/plugin/openclaw.plugin.json" "$base/review-permits.py" "$config"
  "$gateway_unit" "$broker_unit" "$git_unit" "$relay_config" "$oauth_clients" "$policy_unit" "$onboarding_isolation" "$caddy_config"
  /etc/systemd/system/sable-connection-broker.service /etc/systemd/system/sable-connection-broker.socket
  /etc/systemd/system/sable-agent-provisioner.socket /etc/systemd/system/sable-agent-provisioner@.service
  /etc/systemd/system/sable-native-workspace.socket /etc/systemd/system/sable-native-workspace@.service
  "$code/native-workspace.py"
  /etc/systemd/system/sable-discord-onboarding.service /etc/systemd/system/sable-discord-onboarding.timer
  "$shared/integration-setup/SKILL.md" "$code/provision-agents.py" "$code/discord_onboarding.py" "$code/discord_access.py" "$code/schedules.py"
)
for file in "${files[@]}"; do changed+=("$code/$file"); done
for path in "${changed[@]}"; do
  if [ -f "$path" ]; then cp --parents -p "$path" "$backup"; fi
done

rollback() {
  trap - EXIT
  systemctl stop sable-claw.service || true
  systemctl stop sable-discord-onboarding.timer sable-discord-onboarding.service || true
  if [ ! -f "$backup/etc/systemd/system/sable-discord-onboarding.timer" ]; then
    systemctl disable sable-discord-onboarding.timer || true
  fi
  if [ ! -f "$backup/etc/systemd/system/sable-native-workspace.socket" ]; then
    systemctl disable --now sable-native-workspace.socket || true
  fi
  if [ ! -f "$backup/etc/systemd/system/sable-agent-provisioner.socket" ]; then
    systemctl disable --now sable-agent-provisioner.socket || true
  fi
  for path in "${changed[@]}"; do
    if [ -f "$backup$path" ]; then cp -p "$backup$path" "$path"; else rm -f "$path"; fi
  done
  if [ -d "$backup/node_modules" ]; then
    if [ -d "$code/node_modules" ]; then mv "$code/node_modules" "$stage/rollback-node_modules"; fi
    mv "$backup/node_modules" "$code/node_modules"
  fi
  systemctl daemon-reload
  if [ -f "$backup/etc/systemd/system/sable-discord-onboarding.timer" ]; then
    systemctl start sable-discord-onboarding.timer || true
  fi
  if [ -f "$backup/etc/systemd/system/sable-connection-broker.service" ]; then
    systemctl restart sable-connection-broker.service || true
  else
    systemctl disable --now sable-connection-broker.socket || true
    systemctl stop sable-connection-broker.service || true
  fi
  systemctl restart sable-review-policy.service sable-agentgateway.service sable-claw.service
  systemctl restart sable-native-relay.service || true
  systemctl reload caddy.service || true
  echo "Installation rolled back. Backup saved in $backup." >&2
  exit 1
}

trap rollback EXIT
if systemctl is-active --quiet sable-discord-onboarding.timer; then
  systemctl stop sable-discord-onboarding.timer sable-discord-onboarding.service
fi
systemctl stop sable-claw.service
install -d -m 0755 "$code" "$shared/integration-setup" "$(dirname "$gateway_unit")" "$(dirname "$broker_unit")" "$(dirname "$policy_unit")" "$(dirname "$onboarding_isolation")"
install -d -m 0700 "$(dirname "$oauth_clients")"
if [ ! -e "$oauth_clients" ]; then
  printf '[]\n' > "$oauth_clients"
fi
install -d -o sable-claw -g sable-claw -m 0700 /var/lib/sable-discord-onboarding /run/sable-agent-provisioner
install -m 0644 "$source_dir/broker/native-workspace.py" "$code/native-workspace.py"
python3 "$code/native-workspace.py" --allocate-integration-admin
if [ ! -f "$admin_workspace/AGENTS.md" ]; then
  runuser -u sable-codex -g sable-claw -- sh -c '
    set -C
    umask 007
    cat > "$1"
  ' sh "$admin_workspace/AGENTS.md" < "$source_dir/agent-admin/AGENTS.md"
fi
if [ -d "$code/node_modules" ]; then mv "$code/node_modules" "$backup/node_modules"; fi
mv "$stage/deps/node_modules" "$code/node_modules"
chmod -R go+rX "$code/node_modules"
for file in "${files[@]}"; do
  install -m 0644 "$source_dir/broker/$file" "$code/$file"
done
install -m 0644 "$source_dir/broker/sable-connection-broker.service" "$source_dir/broker/sable-connection-broker.socket" /etc/systemd/system/
install -m 0644 "$source_dir/broker/sable-agent-provisioner.socket" "$source_dir/broker/sable-agent-provisioner@.service" /etc/systemd/system/
install -m 0644 "$source_dir/broker/sable-native-workspace.socket" "$source_dir/broker/sable-native-workspace@.service" /etc/systemd/system/
install -m 0644 "$source_dir/broker/sable-discord-onboarding.service" "$source_dir/broker/sable-discord-onboarding.timer" /etc/systemd/system/
install -m 0644 "$source_dir/broker/"{provision-agents,discord_onboarding,discord_access,schedules}.py "$code/"
install -m 0644 "$source_dir/broker/review-plugin.mjs" "$base/plugin/index.mjs"
install -m 0644 "$source_dir/broker/native-worker-policy.mjs" "$base/plugin/native-worker-policy.mjs"
install -m 0644 "$source_dir/broker/schedule-tool.mjs" "$base/plugin/schedule-tool.mjs"
install -m 0644 "$source_dir/broker/openclaw.plugin.json" "$base/plugin/openclaw.plugin.json"
install -m 0644 "$source_dir/broker/review-permits.py" "$base/review-permits.py"
install -m 0644 "$source_dir/skills/integration-setup/SKILL.md" "$shared/integration-setup/SKILL.md"
install -m 0644 "$stage/gateway.json" "$base/agentgateway.yaml"
install -m 0644 "$stage/gateway.conf" "$gateway_unit"
install -m 0644 "$stage/broker.conf" "$broker_unit"
install -m 0644 "$source_dir/broker/60-native-git.conf" "$git_unit"
install -m 0644 "$stage/git-relay.Caddyfile" "$relay_config"
install -m 0644 "$stage/policy.conf" "$policy_unit"
install -m 0644 "$stage/onboarding-isolation.conf" "$onboarding_isolation"
install -m 0644 "$stage/Caddyfile" "$caddy_config"
systemctl daemon-reload
systemctl enable --now sable-connection-broker.socket sable-agent-provisioner.socket sable-native-workspace.socket
systemctl restart sable-connection-broker.service sable-review-policy.service sable-agentgateway.service sable-native-relay.service
systemctl enable --now caddy.service
systemctl reload caddy.service

claw config patch --stdin < "$stage/claw-patch.json" >/dev/null
claw config validate >/dev/null
systemctl start sable-claw.service
for attempt in {1..45}; do
  if curl -fsS --max-time 2 http://127.0.0.1:18790/healthz >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS --max-time 3 http://127.0.0.1:18790/healthz >/dev/null
for service in sable-connection-broker sable-review-policy sable-agentgateway sable-claw caddy; do
  systemctl is-active --quiet "$service.service"
done
systemctl is-active --quiet sable-agent-provisioner.socket
systemctl is-active --quiet sable-native-workspace.socket
systemctl start sable-discord-onboarding.service
systemctl enable --now sable-discord-onboarding.timer
systemctl is-active --quiet sable-discord-onboarding.timer
test "$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "https://$host/review-target/gmail/1")" = 404
test "$(curl -sS --max-time 5 --cacert /etc/sable-codex/relay.crt -o /dev/null -w '%{http_code}' \
  'https://127.0.0.1:17759/__sable_git__/example/fixture.git/info/refs?service=git-upload-pack')" = 403
if runuser -u sable-claw -- test -w /run/sable-connection-broker.sock; then exit 1; fi
python3 - "$config" <<'PY' > "$stage/agents"
import json
import sys
agents = json.load(open(sys.argv[1])).get("agents", {})
for agent in agents.get("entries", {}) or ["main"]:
    print(agent)
PY
while IFS= read -r agent; do
  claw skills list --agent "$agent" --eligible --json > "$stage/skills.json"
  grep -Fq '"integration-setup"' "$stage/skills.json"
  printf '%s can load integration-setup.\n' "$agent"
done < "$stage/agents"
trap - EXIT
printf 'Shared integration setup installed at https://%s. Backup saved in %s.\n' "$host" "$backup"
