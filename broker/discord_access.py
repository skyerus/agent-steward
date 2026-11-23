import re
from urllib.parse import quote

from discord_onboarding import (
    ADMIN, DISCORD_ID, PLUGIN, DiscordError, SetupError, default_direct_user, discord_dm_routes,
)

ACCESS_TOOLS = {"list_discord_access", "update_discord_channel_access", "update_discord_dm_access"}


def gateway_settings(config):
    discord = config.get("channels", {}).get("discord", {})
    if (discord.get("defaultAccount", "default") != "default"
            or any({"allowFrom", "dmPolicy", "guilds"} & settings.keys()
                   for settings in discord.get("accounts", {}).values())):
        raise SetupError("This deployment uses account-specific Discord access rules.")
    return discord


def managed_channels(discord, client, only_guild=None):
    for guild, server in discord.get("guilds", {}).items():
        if not DISCORD_ID.fullmatch(guild) or (only_guild and guild != only_guild):
            continue
        allowed = server.get("channels", {})
        if not allowed:
            continue
        for room in client.request(f"/guilds/{guild}/channels"):
            if room.get("type") == 0 and room["id"] in allowed:
                yield guild, server, room


def channel_users(server, room):
    settings = server["channels"][room]
    if not isinstance(settings, dict):
        raise SetupError("This Discord channel uses an unsupported access configuration.")
    users = sorted(set(map(str, settings.get("users", server.get("users", [])))))
    roles = list(map(str, settings.get("roles", server.get("roles", []))))
    if any(not DISCORD_ID.fullmatch(user) for user in users):
        raise SetupError("This channel's current user allowlist must use Discord IDs.")
    return settings, users, roles


def channel_access(guild, server, room):
    settings, users, roles = channel_users(server, room["id"])
    return {"id": room["id"], "name": room["name"], "serverId": guild, "users": users, "roles": roles,
            "enabled": settings.get("enabled") is not False and settings.get("allow") is not False}


def list_access(config, discord, client):
    return {"directMessages": [{"user": user, "agentId": agent} for user, agent in discord_dm_routes(config).items()],
            "textChannels": [channel_access(*channel) for channel in managed_channels(discord, client)]}


def human_member(client, guild, user):
    path = f"/guilds/{guild}/members/{user}" if guild else f"/users/{user}"
    try:
        record = client.request(path)
    except DiscordError as error:
        if error.status == 404:
            raise SetupError("That Discord user could not be found in the requested scope.") from None
        raise
    identity = record.get("user", record)
    if identity.get("id") != user or identity.get("bot"):
        raise SetupError("Choose a Discord user account.")


def resolve_user(client, ref, guilds, require_member=True):
    if not isinstance(ref, str) or not ref.strip() or len(ref) > 100:
        raise SetupError("Specify a Discord username, ID or mention.")
    ref = ref.strip()
    mention = re.fullmatch(r"<@!?([0-9]{16,22})>", ref)
    user = mention.group(1) if mention else ref
    if DISCORD_ID.fullmatch(user):
        if require_member:
            human_member(client, guilds[0] if len(guilds) == 1 else None, user)
        return user
    name = ref.removeprefix("@").casefold()
    matches = set()
    for guild in guilds:
        for record in client.request(f"/guilds/{guild}/members/search?query={quote(name, safe='')}&limit=100"):
            identity = record.get("user", {})
            names = (record.get("nick"), identity.get("username"), identity.get("global_name"))
            if (not identity.get("bot") and DISCORD_ID.fullmatch(identity.get("id", ""))
                    and any(isinstance(value, str) and value.casefold() == name for value in names)):
                matches.add(identity["id"])
    if len(matches) != 1:
        raise SetupError("Discord did not resolve an exact, unique user. Use their Discord ID or mention.")
    return matches.pop()


def update_channel(config, discord, client, args):
    if set(args) - {"channel", "onlyUsers", "addUsers", "removeUsers"} or not isinstance(args.get("channel"), str):
        raise SetupError("Specify the text channel and a user allowlist change.")
    ref = args["channel"].strip().removeprefix("<#").removeprefix("#").removesuffix(">")
    if DISCORD_ID.fullmatch(ref):
        room = client.request(f"/channels/{ref}")
        guild = room.get("guild_id")
        server = discord.get("guilds", {}).get(guild, {})
        candidates = [(guild, server, room)] if room.get("type") == 0 and ref in server.get("channels", {}) else []
    else:
        candidates = [channel for channel in managed_channels(discord, client)
                      if channel[2]["name"].casefold() == ref.casefold()]
    if len(candidates) != 1:
        raise SetupError("Choose one existing configured text channel by its Discord ID or mention.")
    guild, server, room = candidates[0]
    channel = room["id"]
    settings, existing, roles = channel_users(server, channel)
    prior_review = config.get("plugins", {}).get("entries", {}).get(PLUGIN, {}).get("config", {})
    disabled_here = prior_review.get("speakerChannels", {}).get(channel) == []
    if settings.get("allow") is False or (settings.get("enabled") is False and not disabled_here):
        raise SetupError("This room is disabled by a separate Discord bot policy.")
    if "onlyUsers" in args and ("addUsers" in args or "removeUsers" in args):
        raise SetupError("Use onlyUsers or an add/remove change.")
    if "onlyUsers" not in args and not (args.get("addUsers") or args.get("removeUsers")):
        raise SetupError("Choose which users to add or remove, or provide the complete allowlist.")
    def resolve(key, require_member):
        refs = args.get(key, [])
        if not isinstance(refs, list) or len(refs) > 100:
            raise SetupError("Provide a list of Discord users.")
        return {resolve_user(client, ref, [guild], require_member) for ref in refs}

    if "onlyUsers" in args:
        users = resolve("onlyUsers", True)
    else:
        if roles:
            raise SetupError("This room also allows Discord roles. Specify the full user allowlist to replace that policy.")
        add = resolve("addUsers", True)
        remove = resolve("removeUsers", False)
        if add & remove:
            raise SetupError("Choose whether to add or remove each user.")
        if not existing and not disabled_here:
            raise SetupError("This room has no user allowlist yet. Provide the complete list of people it should accept.")
        users = (set(existing) | add) - remove
    updated = sorted(users)
    change = {
        "channels": {"discord": {"guilds": {guild: {"channels": {channel: {
            "enabled": bool(updated), "users": updated, "roles": [],
        }}}}}},
        "plugins": {"entries": {PLUGIN: {"config": {"speakerChannels": {channel: updated}}}}},
    }
    return change, {"channelId": channel, "name": room["name"], "users": updated, "enabled": bool(updated)}


def update_dm(config, discord, client, args):
    if set(args) - {"user", "agentId", "revoke"} or ("agentId" in args) == (args.get("revoke") is True):
        raise SetupError("Specify the user and their agent, or revoke the user's DM access.")
    if discord.get("dmPolicy") != "allowlist":
        raise SetupError("Discord DMs must use the deployment allowlist.")
    routes = discord_dm_routes(config)
    allowed = set(map(str, discord.get("allowFrom", [])))
    if allowed != routes.keys():
        raise SetupError("All existing approved DM users must have an explicit agent route.")
    agent = args.get("agentId")
    if agent is not None and (not isinstance(agent, str) or agent not in config.get("agents", {}).get("entries", {})):
        raise SetupError("Choose an existing agent ID.")
    guilds = [guild for guild in discord.get("guilds", {}) if DISCORD_ID.fullmatch(guild)]
    user = resolve_user(client, args.get("user"), guilds, require_member=False)
    bindings = [binding for binding in config.get("bindings", []) if default_direct_user(binding) != user]
    if agent is None:
        routes.pop(user, None)
    else:
        human_member(client, None, user)
        routes[user] = agent
        bindings.insert(0, {"agentId": agent, "match": {"channel": "discord", "accountId": "default",
                         "peer": {"kind": "direct", "id": user}}})
    if ADMIN not in routes.values():
        raise SetupError("Keep at least one Discord user routed to Integration Admin.")
    change = {"bindings": bindings, "channels": {"discord": {"allowFrom": list(routes)}}}
    return change, {"user": user, "agentId": agent, "admin": agent == ADMIN}
