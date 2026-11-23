import fcntl
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

from discord_access import ACCESS_TOOLS, gateway_settings, list_access, update_channel, update_dm
from discord_onboarding import Discord, DiscordError, Jobs, SetupError, actor_is_admin, advance, plan_for, status
from schedules import ScheduleError, execute_schedule
from discord_tools import describe_channel, resolve_channel, run as run_discord_tool

CLAW = "/opt/sable/review-gateway/claw"
CONFIG = Path("/var/lib/sable-claw/state/openclaw.json")
WORKSPACES = Path("/var/lib/sable-codex/workspaces")
WORKSPACE_SOCKET = "/run/sable-native-workspace.sock"
ADMIN = "integration-admin"
AGENT_ID = re.compile(r"[a-z][a-z0-9_-]{0,62}")
DISCORD_ID = re.compile(r"[0-9]{16,22}")
VIEW = 1 << 10
ONBOARDING = {"prepare_discord_server", "discord_server_setup_status", "cancel_discord_server_setup"}


class ProvisionError(Exception):
    pass


def rpc(method, params=None):
    command = [CLAW, "gateway", "call", method, "--json", "--timeout", "25000"]
    if params is not None:
        command += ["--params", json.dumps(params)]
    env = {name: value for name, value in os.environ.items() if name != "CREDENTIALS_DIRECTORY"}
    response = subprocess.run(command, env=env, capture_output=True, check=False, timeout=32)
    if response.returncode:
        if method.startswith("cron."):
            error = response.stderr.decode(errors="replace").strip()
            safe = ("not found", "no recorded inference account", "invalid cron", "does not match")
            diagnostic = next((fragment for fragment in safe if fragment.lower() in error.lower()), None)
            raise ScheduleError("OpenClaw rejected this schedule request" + (f" ({diagnostic})." if diagnostic else "."))
        raise ProvisionError("OpenClaw could not apply the agent configuration. Check the current agent list before retrying.")
    reply = json.loads(response.stdout)
    if reply.get("ok") is False:
        raise ProvisionError("OpenClaw rejected the requested agent configuration.")
    return reply


def configuration():
    return json.loads(CONFIG.read_text())


def patch(values, revision):
    if not revision:
        raise ProvisionError("OpenClaw's configuration revision was unavailable.")
    rpc("config.patch", {"raw": json.dumps(values), "baseHash": revision, "response": "summary"})


def agents(config):
    all_entries = config.get("agents", {}).get("entries", {})
    bindings = config.get("bindings", [])
    return [
        {
            "id": identity,
            "name": entry.get("identity", {}).get("name", entry.get("name", identity)),
            "discordChannels": [
                peer["id"] for binding in bindings if binding.get("agentId") == identity
                and (match := binding.get("match", {})).get("channel") == "discord"
                and (peer := match.get("peer", {})).get("kind") == "channel"
            ],
        }
        for identity, entry in sorted(all_entries.items())
    ]


def discord_channel(channel):
    secret = Path(os.environ.get("CREDENTIALS_DIRECTORY", "/run/nonexistent")) / "discord.env"
    token = next((line.partition("=")[2] for line in secret.read_text().splitlines()
                  if line.startswith("DISCORD_BOT_TOKEN=")), "") if secret.is_file() else ""
    if not re.fullmatch(r"[A-Za-z0-9_.-]{45,160}", token):
        raise ProvisionError("Configure the Discord bot credentials for this deployment before binding a channel.")
    request = urllib.request.Request(
        f"https://discord.com/api/v10/channels/{channel}",
        headers={"Authorization": f"Bot {token}", "User-Agent": "DiscordBot (https://openclaw.ai, 1.0)"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)
    except (OSError, urllib.error.URLError) as error:
        raise ProvisionError("The Discord bot cannot verify that channel.") from error


def prepare_binding(config, identity, channel):
    gateway = config.get("channels", {}).get("discord", {})
    view = discord_channel(channel)
    guild_id = view.get("guild_id")
    guild = gateway.get("guilds", {}).get(guild_id)
    if not guild or view.get("type") not in (0, 2):
        raise ProvisionError("Choose a text or voice channel in a Discord server configured for this deployment.")
    access = {str(user) for user in guild.get("users", []) if DISCORD_ID.fullmatch(str(user))}
    review = config.get("plugins", {}).get("entries", {}).get("sable-integration-review", {}).get("config", {})
    approved = set(review.get("speakers", [])) | set(review.get("speakerChannels", {}).get(channel, []))
    audience = access & approved
    bot_id = gateway.get("applicationId")
    overwrites = view.get("permission_overwrites", [])
    denied = any(entry["type"] == 0 and entry["id"] == guild_id and int(entry["deny"]) & VIEW for entry in overwrites)
    allowed = [entry for entry in overwrites if int(entry["allow"]) & VIEW]
    if not denied or not audience or any(
        entry["type"] != 1 or entry["id"] not in (audience | {bot_id}) for entry in allowed
    ):
        raise ProvisionError("Use a private channel that directly grants access only to approved members and the bot.")
    if not any(entry["id"] in audience for entry in allowed):
        raise ProvisionError("Allow at least one approved Discord user to view the private channel.")

    bindings = config.get("bindings", [])
    for binding in bindings:
        match = binding.get("match", {})
        if match.get("channel") == "discord" and match.get("peer", {}).get("id") == channel:
            if binding["agentId"] != identity:
                raise ProvisionError("This channel is already assigned to a different agent.")
            return None
    binding = {"agentId": identity, "match": {"channel": "discord", "accountId": "default",
               "peer": {"kind": "channel", "id": channel}}}
    current = guild.get("channels", {}).get(channel, {})
    if current is False or isinstance(current, dict) and current.get("enabled") is False:
        raise ProvisionError("This channel is explicitly disabled in OpenClaw.")
    settings = {**(current if isinstance(current, dict) else {}), "enabled": True, "users": sorted(audience)}
    return {"bindings": [binding, *bindings],
            "channels": {"discord": {"guilds": {guild_id: {"channels": {channel: settings}}}}}}


def provision_workspace(agent, action, **fields):
    request = json.dumps({"agent": agent, "action": action, **fields},
                         ensure_ascii=False).encode() + b"\n"
    try:
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(6)
            client.connect(WORKSPACE_SOCKET)
            client.sendall(request)
            with client.makefile("rb") as stream:
                response = json.loads(stream.readline(257))
                if response != {"ok": True}:
                    raise ValueError("Workspace request refused")
    except (OSError, ValueError):
        raise ProvisionError("The native worker workspace could not be prepared. Check its provisioning service.") from None


def execute(command):
    name, args = command["name"], command["args"]
    user = command.get("requester")
    if name == "inspect_discord_resource":
        return describe_channel(Discord(), args.get("channel"))
    if name == "resolve_discord_resource":
        return resolve_channel(Discord(), configuration(), args["agent"], args["reference"])
    if name in {"discord_read_messages", "discord_post_message"}:
        return run_discord_tool(Discord(), name, args)
    if name == "manage_schedule":
        return execute_schedule(args, configuration(), rpc,
                                os.environ.get("STATE_DIRECTORY", "/var/lib/sable-discord-onboarding"))
    if name == "discord_is_admin":
        return isinstance(user, str) and bool(DISCORD_ID.fullmatch(user)) and actor_is_admin(configuration(), user)
    if name in ONBOARDING:
        return onboarding(name, args, user)
    if not isinstance(args, dict):
        raise ProvisionError("Invalid agent configuration request.")
    if name in ACCESS_TOOLS:
        return discord_access(name, args, user)
    expected = {"list_managed_agents": set(), "create_agent": {"agentId", "name"},
                "rename_agent": {"agentId", "name"}, "bind_agent_channel": {"agentId", "channelId"},
                "set_agent_instructions": {"agentId", "instructions"},
                "deploy_agent_connector": {"agentId", "filename", "source"}}
    if name not in expected or set(args) != expected[name]:
        raise ProvisionError("Invalid agent configuration request.")
    config = configuration()
    if name == "list_managed_agents":
        return agents(config)
    require_admin(config, user)

    identity = args["agentId"]
    if not isinstance(identity, str) or not AGENT_ID.fullmatch(identity) or identity == ADMIN:
        raise ProvisionError("Choose an ID for a downstream agent.")
    display = args.get("name")
    if display is not None and (not isinstance(display, str) or len(display.strip()) > 100 or
                                not display.strip() or any(ord(char) < 32 for char in display)):
        raise ProvisionError("Choose a display name of up to 100 characters.")
    existing = next((entry for entry in agents(config) if entry["id"] == identity), None)
    configured_workspace = config.get("agents", {}).get("entries", {}).get(identity, {}).get("workspace")
    workspace = str(WORKSPACES / identity)
    if name == "create_agent":
        if existing and (existing["name"] != display.strip() or configured_workspace != workspace):
            raise ProvisionError("That agent ID is already in use. Choose another ID or rename the existing agent.")
        provision_workspace(identity, "allocate")
        if not existing:
            rpc("agents.create", {"agentId": identity, "name": display.strip(), "workspace": workspace})
        provision_workspace(identity, "share-documents")
    else:
        if not existing:
            raise ProvisionError("The downstream agent does not exist.")
        if name == "set_agent_instructions":
            if configured_workspace != workspace:
                raise ProvisionError("This agent's workspace is outside the native worker.")
            instructions = args["instructions"]
            if not isinstance(instructions, str) or not instructions.strip() or len(instructions) > 12000:
                raise ProvisionError("Provide agent instructions of up to 12,000 characters.")
            ref = {"agentId": identity, "name": "AGENTS.md"}
            before = rpc("agents.files.get", ref)
            prior = before["file"]
            version = {"expectedMissing": True} if prior["missing"] else {"expectedHash": prior["hash"]}
            after = rpc("agents.files.set", {**ref, **version, "expectedWorkspace": before["workspace"],
                                            "content": instructions})
            if after["file"]["content"] != instructions:
                raise ProvisionError("OpenClaw did not confirm the agent instructions.")
            provision_workspace(identity, "share-documents")
            return {**existing, "instructionsUpdated": True}
        if name == "deploy_agent_connector":
            if configured_workspace != workspace:
                raise ProvisionError("This agent's workspace is outside the native worker.")
            filename, source = args["filename"], args["source"]
            if (not isinstance(filename, str) or
                    not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}\.(py|mjs|sh)", filename) or
                    not isinstance(source, str) or not source.strip() or
                    len(source) > 12000 or "\x00" in source):
                raise ProvisionError("Provide a Python, JavaScript or shell connector and a simple filename.")
            provision_workspace(identity, "deploy-connector", filename=filename, source=source)
            return {"agentId": identity, "path": f".agent-connectors/{filename}"}
        revision = rpc("config.get")
        config = configuration()
        if name == "rename_agent":
            values = {"agents": {"entries": {identity: {"name": display.strip(), "identity": {"name": display.strip()}}}}}
        else:
            channel = args["channelId"]
            if not isinstance(channel, str) or not DISCORD_ID.fullmatch(channel):
                raise ProvisionError("Provide a valid Discord channel ID.")
            values = prepare_binding(config, identity, channel)
        if values:
            patch(values, revision.get("hash"))
    current = next((entry for entry in agents(configuration()) if entry["id"] == identity), None)
    if current is None:
        raise ProvisionError("OpenClaw did not confirm the downstream agent.")
    if name == "bind_agent_channel" and args["channelId"] not in current["discordChannels"]:
        raise ProvisionError("OpenClaw did not confirm the Discord channel binding.")
    return current


def require_admin(config, user):
    if not isinstance(user, str) or not DISCORD_ID.fullmatch(user) or not actor_is_admin(config, user):
        raise ProvisionError("This Discord account cannot administer this deployment.")


def discord_access(name, args, user):
    config = configuration()
    require_admin(config, user)
    if name == "list_discord_access":
        return list_access(config, gateway_settings(config), Discord())

    revision = rpc("config.get").get("hash")
    config = configuration()
    require_admin(config, user)
    update = update_dm if name == "update_discord_dm_access" else update_channel
    change, result = update(config, gateway_settings(config), Discord(), args)
    patch(change, revision)
    return result


def onboarding_db():
    state = Path(os.environ.get("STATE_DIRECTORY", "/var/lib/sable-discord-onboarding"))
    return Jobs(state / "jobs.sqlite")


def onboarding(name, args, user):
    if not isinstance(user, str) or not DISCORD_ID.fullmatch(user) or not actor_is_admin(configuration(), user):
        raise ProvisionError("This Discord account cannot administer server setup.")
    jobs = onboarding_db()
    now = int(time.time())
    if name == "prepare_discord_server":
        requested = plan_for(args, user, configuration())
        return status(jobs.begin(requested, user, now))
    if not isinstance(args, dict) or set(args) != {"requestId"}:
        raise ProvisionError("Provide the setup request ID returned by Integration Admin.")
    jobs.expire(now)
    request = jobs.get(args["requestId"], user)
    if name == "cancel_discord_server_setup" and request["state"] in (
        "awaiting_install", "permissions_needed", "retrying"
    ):
        jobs.update(request, {"state": "cancelled", "details": "{}"})
        request = jobs.get(args["requestId"], user)
    return status(request)


def background_setup():
    with open("/run/sable-agent-provisioner/mutation.lock", "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        jobs = onboarding_db()
        request = jobs.next(int(time.time()))
        if request:
            def apply(values, revision):
                try:
                    patch(values, revision)
                except ProvisionError as error:
                    raise OSError(str(error)) from error

            advance(jobs, request, Discord(), configuration, lambda: rpc("config.get")["hash"], apply)


def main():
    # The systemd socket admits the credential broker, which enforces both agent and human permissions.
    try:
        line = sys.stdin.buffer.readline(65_537)
        if not line.endswith(b"\n"):
            raise ProvisionError("Invalid agent configuration request.")
        command = json.loads(line)
        if command.get("name") == "discord_is_admin":
            response = {"ok": True, "value": execute(command)}
        else:
            with open("/run/sable-agent-provisioner/mutation.lock", "a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                response = {"ok": True, "value": execute(command)}
    except (ProvisionError, SetupError, DiscordError, ScheduleError) as error:
        response = {"ok": False, "error": str(error)}
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        response = {"ok": False, "error": "Agent provisioning did not complete. Check the current agent list before retrying."}
    print(json.dumps(response), flush=True)


if __name__ == "__main__":
    if sys.argv[1:] == ["--onboard-pending"]:
        background_setup()
    else:
        main()
