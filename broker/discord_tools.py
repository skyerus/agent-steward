"""Discord operations on exact channels authorised by the integration broker."""
import re
import urllib.parse
from discord_onboarding import DISCORD_ID, Discord, SetupError

TEXT_CHANNELS = {0, 5}
THREADS = {10, 11, 12}


def read_channel(discord, channel):
    if not isinstance(channel, str) or not DISCORD_ID.fullmatch(channel):
        raise SetupError("Provide an exact Discord channel ID.")
    metadata = discord.request(f"/channels/{channel}")
    if metadata.get("id") != channel or metadata.get("type") not in TEXT_CHANNELS | THREADS:
        raise SetupError("Choose a Discord text channel or thread.")
    if not DISCORD_ID.fullmatch(str(metadata.get("guild_id", ""))):
        raise SetupError("Choose a Discord server channel.")
    return metadata


def describe_channel(discord, channel):
    channel = read_channel(discord, channel)
    guild = discord.request(f"/guilds/{channel['guild_id']}")
    if guild.get("id") != channel["guild_id"]:
        raise SetupError("Discord returned an unexpected server.")
    return {"channel": channel["id"], "name": channel["name"], "guild": guild["id"], "server": guild["name"],
            **({"parent": channel["parent_id"]} if channel["type"] in THREADS and channel.get("parent_id") else {})}


def resolve_channel(discord, config, agent, reference):
    if DISCORD_ID.fullmatch(reference):
        return describe_channel(discord, reference)
    name = reference.lstrip("#")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,99}", name):
        raise SetupError("Use an exact channel name, mention or ID.")
    peers = []
    for binding in config.get("bindings", []):
        match = binding.get("match", {})
        peer = match.get("peer", {})
        if binding.get("agentId") == agent and match.get("channel") == "discord" and peer.get("kind") == "channel":
            server = match.get("guildId")
            if not server and DISCORD_ID.fullmatch(str(peer.get("id", ""))):
                server = discord.request(f"/channels/{peer['id']}").get("guild_id")
            peers.append(server)
    guilds = {item for item in peers if isinstance(item, str) and DISCORD_ID.fullmatch(item)}
    if len(guilds) != 1:
        raise SetupError("This agent is not bound to exactly one Discord server. Use the channel mention or ID.")
    guild, = guilds
    choices = [item for item in discord.request(f"/guilds/{guild}/channels")
               if item.get("name") == name and item.get("type") in TEXT_CHANNELS]
    if len(choices) != 1:
        raise SetupError("The channel name is missing or ambiguous. Use its Discord mention or ID.")
    return describe_channel(discord, choices[0]["id"])


def run(discord, operation, args):
    meta = read_channel(discord, args.get("channel"))
    if meta["guild_id"] != args.get("guild"):
        raise SetupError("The channel is outside this Discord server grant.")
    if "parentChannel" in args and (meta["type"] not in THREADS or meta.get("parent_id") != args["parentChannel"]):
        raise SetupError("The thread is outside the approved parent channel.")
    uri = f"/channels/{meta['id']}/messages"
    if operation == "discord_read_messages":
        limit = args.get("limit", 10)
        if type(limit) is not int or not 1 <= limit <= 25:
            raise SetupError("Read between 1 and 25 messages.")
        rows = discord.request(uri + "?" + urllib.parse.urlencode({"limit": limit}))
        return [{"id": entry["id"], "content": entry.get("content", "")[:2000],
                  "author": entry.get("author", {}).get("username", ""), "timestamp": entry.get("timestamp"),
                 **({"thread": entry["thread"]["id"]} if isinstance(entry.get("thread"), dict) and
                     DISCORD_ID.fullmatch(str(entry["thread"].get("id", ""))) else {})}
                for entry in rows]
    if operation == "discord_post_message":
        content = args.get("content")
        if not isinstance(content, str) or not content.strip() or len(content) > 2000:
            raise SetupError("Provide a Discord message of up to 2,000 characters.")
        body = {"content": content, "allowed_mentions": {"parse": [], "replied_user": False}}
        if "replyTo" in args:
            if not re.fullmatch(r"[0-9]{16,22}", str(args["replyTo"])):
                raise SetupError("Use the exact message ID in this channel.")
            body["message_reference"] = {"message_id": args["replyTo"], "channel_id": meta["id"],
                                         "guild_id": meta["guild_id"], "fail_if_not_exists": True}
        result = discord.request(uri, body)
        return {"id": result["id"], "channel": result["channel_id"]}
    raise SetupError("Unknown Discord operation.")
