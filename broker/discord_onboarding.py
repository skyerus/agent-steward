import json
import os
from pathlib import Path
import re
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from uuid import uuid4

ADMIN = "integration-admin"
DISCORD_ID = re.compile(r"[0-9]{16,22}")
AGENT_ID = re.compile(r"[a-z][a-z0-9_-]{0,62}")
REQUEST_ID = re.compile(r"[0-9a-f]{32}")
ADMINISTRATOR = 1 << 3
MANAGE_CHANNELS = 1 << 4
MANAGE_GUILD = 1 << 5
VIEW = 1 << 10
TEXT = VIEW | (1 << 11) | (1 << 16)
VOICE = VIEW | (1 << 20) | (1 << 21)
COMMANDS = 1 << 31
DISCORD_API = "https://discord.com/api/v10"
PLUGIN = "sable-integration-review"
LIFETIME = 30 * 60


class SetupError(Exception):
    pass


class DiscordError(Exception):
    def __init__(self, status):
        self.status = status
        super().__init__(f"Discord returned HTTP {status}.")


class RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Discord:
    def __init__(self):
        path = Path(os.environ.get("CREDENTIALS_DIRECTORY", "/run/nonexistent")) / "discord.env"
        token = next((line.partition("=")[2] for line in path.read_text().splitlines()
                      if line.startswith("DISCORD_BOT_TOKEN=")), "") if path.is_file() else ""
        if not re.fullmatch(r"[A-Za-z0-9_.-]{45,160}", token):
            raise SetupError("Set up the Discord bot credential for this deployment.")
        self.headers = {"Authorization": f"Bot {token}", "User-Agent": "DiscordBot (https://openclaw.ai, 1.0)"}
        self.opener = urllib.request.build_opener(RefuseRedirect())

    def request(self, route, values=None):
        data = None if values is None else json.dumps(values).encode()
        request = urllib.request.Request(
            DISCORD_API + route, data=data,
            headers={**self.headers, "Content-Type": "application/json"},
        )
        try:
            with self.opener.open(request, timeout=6) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            raise DiscordError(error.code) from None

    def joined_guilds(self):
        cursor = "0"
        while True:
            page = self.request(f"/users/@me/guilds?limit=200&after={cursor}")
            yield from page
            if len(page) < 200:
                return
            after = max((row["id"] for row in page), key=int)
            if int(after) <= int(cursor):
                raise SetupError("Discord returned an incomplete list of joined servers.")
            cursor = after


def default_direct_user(binding):
    match = binding.get("match", {})
    peer = match.get("peer", {})
    user = peer.get("id")
    if (match.get("channel") == "discord" and match.get("accountId", "default") == "default"
            and peer.get("kind") == "direct" and isinstance(user, str) and DISCORD_ID.fullmatch(user)):
        return user
    return None


def discord_dm_routes(config):
    discord = config.get("channels", {}).get("discord", {})
    if discord.get("dmPolicy") != "allowlist":
        return {}
    allowed = set(map(str, discord.get("allowFrom", [])))
    routes = {}
    for binding in config.get("bindings", []):
        user = default_direct_user(binding)
        if user in allowed:
            routes.setdefault(user, binding.get("agentId"))
    return routes


def actor_is_admin(config, user):
    return discord_dm_routes(config).get(user) == ADMIN


def plan_for(args, user, config):
    if (not isinstance(args, dict) or set(args) - {"server", "agentIds", "allowedUsers", "voice"}):
        raise SetupError("Use a server name or ID and a list of downstream agent IDs.")
    server = args.get("server")
    if not isinstance(server, str) or not server.strip() or len(server) > 100 or any(ord(c) < 32 for c in server):
        raise SetupError("Provide the exact Discord server name or server ID.")
    ids = args.get("agentIds")
    if (not isinstance(ids, list) or not 1 <= len(ids) <= 20
            or any(not isinstance(i, str) or not AGENT_ID.fullmatch(i) or i == ADMIN for i in ids)):
        raise SetupError("Choose between one and twenty downstream agents.")
    if set(ids) - config.get("agents", {}).get("entries", {}).keys():
        raise SetupError("Create each requested downstream agent before connecting its Discord channels.")
    users = args.get("allowedUsers", [])
    if (not isinstance(users, list) or len(users) > 25
            or any(not isinstance(i, str) or not DISCORD_ID.fullmatch(i) for i in users)
            or len({user, *users}) > 25):
        raise SetupError("Use Discord user IDs for the people who can access the new channels.")
    voice = args.get("voice", False)
    if type(voice) is not bool:
        raise SetupError("Set voice to true or false.")
    if voice and any(f"{identity}-voice" in ids for identity in ids):
        raise SetupError("Choose agent IDs whose text and voice channel names are distinct.")
    gateway = config.get("channels", {}).get("discord", {})
    bot = str(gateway.get("applicationId", ""))
    if not DISCORD_ID.fullmatch(bot) or gateway.get("groupPolicy") != "allowlist":
        raise SetupError("Configure the Discord app and server allowlist before onboarding.")
    if bot in users:
        raise SetupError("The bot already has its own channel permission. Choose Discord users for the audience.")
    # A per-account guild map overrides this installation's shared Discord guild map.
    if any("guilds" in scope for scope in gateway.get("accounts", {}).values()):
        raise SetupError("This installation uses a Discord account-specific server map.")
    if voice and gateway.get("voice", {}).get("enabled") is not True:
        raise SetupError("Enable the Discord voice runtime on this deployment before requesting voice rooms.")
    return {"server": server.strip(), "agentIds": sorted(set(ids)), "users": sorted({user, *users}),
            "voice": voice, "bot": bot}


def invite_url(plan, guild=None):
    permissions = MANAGE_CHANNELS | TEXT | COMMANDS | (VOICE if plan["voice"] else 0)
    params = {"client_id": plan["bot"], "scope": "bot applications.commands",
              "integration_type": "0", "permissions": str(permissions)}
    if guild or DISCORD_ID.fullmatch(plan["server"]):
        params.update(guild_id=guild or plan["server"], disable_guild_select="true")
    return "https://discord.com/oauth2/authorize?" + urllib.parse.urlencode(params)


class Jobs:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("""CREATE TABLE IF NOT EXISTS setups (
            id TEXT PRIMARY KEY, requester TEXT NOT NULL, plan TEXT NOT NULL, expires INTEGER NOT NULL,
            guild TEXT, state TEXT NOT NULL, next_check INTEGER NOT NULL, details TEXT NOT NULL
        )""")

    def update(self, request, fields):
        values = {**dict(request), **fields}
        self.db.execute("""UPDATE setups SET guild=:guild, state=:state, next_check=:next_check,
                        details=:details WHERE id=:id""", values)
        self.db.commit()

    def expire(self, now):
        self.db.execute("""UPDATE setups SET state='expired' WHERE expires<=? AND state IN
                        ('awaiting_install', 'permissions_needed', 'retrying')""", (now,))
        self.db.commit()

    def begin(self, plan, user, now):
        self.expire(now)
        payload = json.dumps(plan, sort_keys=True)
        existing = self.db.execute("""SELECT * FROM setups WHERE requester=? AND plan=?
            AND state IN ('awaiting_install','permissions_needed','retrying','ready')
            ORDER BY expires DESC LIMIT 1""", (user, payload)).fetchone()
        if existing:
            return existing
        request_id = uuid4().hex
        self.db.execute("INSERT INTO setups VALUES (?, ?, ?, ?, NULL, 'awaiting_install', ?, '{}')",
                        (request_id, user, payload, now + LIFETIME, now))
        self.db.commit()
        return self.get(request_id, user)

    def get(self, request_id, user):
        if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
            raise SetupError("Provide the setup request ID returned by Integration Admin.")
        result = self.db.execute("SELECT * FROM setups WHERE id=? AND requester=?", (request_id, user)).fetchone()
        if not result:
            raise SetupError("This setup request is unavailable to this Discord account.")
        return result

    def next(self, now):
        self.expire(now)
        return self.db.execute("""SELECT * FROM setups
            WHERE state IN ('awaiting_install','permissions_needed','retrying') AND next_check<=?
            ORDER BY next_check LIMIT 1""", (now,)).fetchone()


def status(request):
    plan = json.loads(request["plan"])
    answer = {"requestId": request["id"], "server": plan["server"], "guildId": request["guild"],
              "state": request["state"], "expiresAt": request["expires"], **json.loads(request["details"])}
    if request["state"] in ("awaiting_install", "permissions_needed"):
        answer["installUrl"] = invite_url(plan, request["guild"])
    return answer


def resolve_guild(discord, plan, pinned):
    target = pinned or plan["server"]
    if DISCORD_ID.fullmatch(target):
        try:
            return discord.request(f"/guilds/{target}")
        except DiscordError as error:
            if error.status in (403, 404):
                return None
            raise
    exact = [row for row in discord.joined_guilds() if row["name"].casefold() == target.casefold()]
    if len(exact) > 1:
        raise SetupError("More than one joined server has that name. Start setup with the Discord server ID.")
    if exact and DISCORD_ID.fullmatch(exact[0]["id"]):
        return discord.request(f"/guilds/{exact[0]['id']}")
    return None


def member(discord, guild, user):
    try:
        return discord.request(f"/guilds/{guild}/members/{user}")
    except DiscordError as error:
        if error.status in (403, 404):
            raise SetupError("An approved user is missing from the selected Discord server.") from None
        raise


def permissions(guild, member_id, member_info):
    if guild["owner_id"] == member_id:
        return -1
    roles = {guild["id"], *member_info["roles"]}
    result = 0
    for role in guild["roles"]:
        if role["id"] in roles:
            result |= int(role["permissions"])
    return -1 if result & ADMINISTRATOR else result


def private_overwrites(guild, plan, bits):
    return [{"id": guild, "type": 0, "allow": "0", "deny": str(VIEW)},
            {"id": plan["bot"], "type": 1, "allow": str(bits), "deny": "0"}] + [
                {"id": user, "type": 1, "allow": str(bits), "deny": "0"} for user in plan["users"]
            ]


def normalized_overwrites(entries):
    return {(row["id"], row["type"], int(row.get("allow", 0)), int(row.get("deny", 0))) for row in entries}


def ensure_channel(discord, guild, current, *, name, kind, overwrites, parent=None):
    expected = normalized_overwrites(overwrites)
    matches = [row for row in current if row["name"] == name and row.get("parent_id") == parent]
    if matches:
        if len(matches) != 1 or matches[0]["type"] != kind or (
            normalized_overwrites(matches[0]["permission_overwrites"]) != expected
        ):
            raise SetupError(f"An existing Discord channel named {name} has a different type or audience.")
        return matches[0]["id"]
    values = {"name": name, "type": kind, "permission_overwrites": overwrites}
    if parent:
        values["parent_id"] = parent
    actual = discord.request(f"/guilds/{guild}/channels", values)
    if actual["name"] != name or actual["type"] != kind or actual.get("parent_id") != parent or (
        normalized_overwrites(actual["permission_overwrites"]) != expected
    ):
        raise SetupError("Discord did not confirm the expected private channel permissions.")
    return actual["id"]


def setup_channels(discord, guild, plan, request_id):
    current = discord.request(f"/guilds/{guild}/channels")
    category_name = "Agents"
    category_overwrites = private_overwrites(guild, plan, VIEW)
    expected = normalized_overwrites(category_overwrites)
    if any(row["name"] == category_name and row.get("parent_id") is None
           and (row["type"] != 4 or normalized_overwrites(row["permission_overwrites"]) != expected)
           for row in current):
        category_name = f"Agents {request_id[:8]}"
    parent = ensure_channel(discord, guild, current, name=category_name, kind=4, overwrites=category_overwrites)
    channels = []
    for agent in plan["agentIds"]:
        variants = [(agent, 0, TEXT)] + ([(f"{agent}-voice", 2, VOICE)] if plan["voice"] else [])
        for name, kind, access in variants:
            channel = ensure_channel(discord, guild, current, name=name, kind=kind,
                                     overwrites=private_overwrites(guild, plan, access), parent=parent)
            channels.append({"agentId": agent, "channelId": channel, "kind": "voice" if kind == 2 else "text"})
    return channels


def validate_server_scope(cfg, guild):
    existing = cfg["channels"]["discord"].get("guilds", {}).get(guild)
    if existing is not None and (not isinstance(existing, dict) or not existing.get("channels")):
        raise SetupError("This Discord server already has a different access policy. Use its existing channel setup.")


def configuration_patch(cfg, guild, plan, channels):
    validate_server_scope(cfg, guild)
    bindings = cfg.get("bindings", [])
    new_bindings = []
    settings = {}
    existing = cfg["channels"]["discord"].get("guilds", {}).get(guild, {})
    for room in channels:
        channel, agent = room["channelId"], room["agentId"]
        matches = [binding for binding in bindings
                   if binding.get("match", {}).get("channel") == "discord"
                   and binding["match"].get("peer", {}).get("id") == channel]
        if matches and any(binding["agentId"] != agent for binding in matches):
            raise SetupError("An existing channel routes to a different agent.")
        if not matches:
            new_bindings.append({"agentId": agent, "match": {
                "channel": "discord", "accountId": "default", "guildId": guild,
                "peer": {"kind": "channel", "id": channel}}})
        current = existing.get("channels", {}).get(channel, {})
        if current is False or isinstance(current, dict) and (
            current.get("allow") is False or current.get("enabled") is False
        ):
            raise SetupError("A requested channel is explicitly disabled in OpenClaw.")
        settings[channel] = {"enabled": True, "users": plan["users"], "requireMention": False}
    server = {"channels": settings}
    if not existing:
        server.update(users=plan["users"], requireMention=True)
    discord = {"guilds": {guild: server}}
    voice_rooms = [{"guildId": guild, "channelId": room["channelId"]}
                   for room in channels if room["kind"] == "voice"]
    if voice_rooms:
        prior_voice = cfg["channels"]["discord"]["voice"]
        auto = prior_voice.get("autoJoin", [])
        new = [room for room in voice_rooms if not any(
            row.get("guildId") == room["guildId"] and row.get("channelId") == room["channelId"] for row in auto
        )]
        discord["voice"] = {"autoJoin": [*auto, *(dict(room, whenOccupied=True) for room in new)]}
        if "allowedChannels" in prior_voice:
            allowed = prior_voice["allowedChannels"]
            discord["voice"]["allowedChannels"] = [*allowed, *(room for room in voice_rooms if room not in allowed)]
    return {"bindings": [*new_bindings, *bindings], "channels": {"discord": discord},
            "plugins": {"entries": {PLUGIN: {"config": {"speakerChannels": {
                channel: plan["users"] for channel in settings
            }}}}}}


def advance(jobs, request, discord, get_config, config_revision, patch_config, now=None):
    now = int(time.time()) if now is None else now
    plan = json.loads(request["plan"])

    def save(state, details, guild=None):
        jobs.update(request, {"state": state, "details": json.dumps(details), "next_check": now + 30,
                              "guild": guild or request["guild"]})

    try:
        cfg = get_config()
        if not actor_is_admin(cfg, request["requester"]):
            raise SetupError("The requester no longer administers this deployment.")
        if plan_for({"server": plan["server"], "agentIds": plan["agentIds"],
                     "allowedUsers": plan["users"], "voice": plan["voice"]}, request["requester"], cfg) != plan:
            raise SetupError("The Discord application or downstream agents changed. Start setup again.")
        guild = resolve_guild(discord, plan, request["guild"])
        if guild is None:
            save("awaiting_install", {})
            return
        guild_id = guild["id"]
        validate_server_scope(cfg, guild_id)
        members = {user: member(discord, guild_id, user) for user in plan["users"]}
        owner = request["requester"]
        if not permissions(guild, owner, members[owner]) & MANAGE_GUILD:
            raise SetupError("The requester needs Manage Server in the selected Discord server.")
        bot_access = permissions(guild, plan["bot"], member(discord, guild_id, plan["bot"]))
        required = MANAGE_CHANNELS | TEXT | (VOICE if plan["voice"] else 0)
        if bot_access & required != required:
            save("permissions_needed", {"message": "Authorize the bot with the requested channel permissions."}, guild_id)
            return
        jobs.update(request, {"guild": guild_id})
        request = jobs.get(request["id"], owner)
        rooms = setup_channels(discord, guild_id, plan, request["id"])
        revision = config_revision()
        current = get_config()
        if not actor_is_admin(current, owner):
            raise SetupError("The requester no longer administers this deployment.")
        patch_config(configuration_patch(current, guild_id, plan, rooms), revision)
        live = get_config()
        if any(not any(rule["agentId"] == room["agentId"] and rule["match"].get("peer", {}).get("id") == room["channelId"]
                       for rule in live.get("bindings", [])) for room in rooms):
            raise OSError("OpenClaw did not confirm the agent routes.")
        save("ready", {"channels": rooms}, guild_id)
    except SetupError as error:
        save("blocked", {"message": str(error)})
    except DiscordError as error:
        if error.status in (400, 401, 403):
            save("permissions_needed", {"message": "Discord did not allow channel provisioning. Check the bot's requested permissions."})
        else:
            save("retrying", {"message": "Discord is temporarily unavailable. Setup will retry."})
    except OSError:
        save("retrying", {"message": "Setup is waiting for Discord or OpenClaw and will retry."})
