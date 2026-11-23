import unittest
from discord_onboarding import SetupError
from discord_tools import describe_channel, resolve_channel, run

GUILD = "111111111111111111"
PARENT = "222222222222222222"
THREAD = "333333333333333333"
FOREIGN = "444444444444444444"
MESSAGE = "555555555555555555"


class FakeDiscord:
    def __init__(self):
        self.calls = []

    def request(self, route, values=None):
        self.calls.append((route, values))
        if route == f"/guilds/{GUILD}":
            return {"id": GUILD, "name": "Fixture"}
        if route == f"/guilds/{GUILD}/channels":
            return [{"id": PARENT, "name": "bug-reports", "type": 0}]
        if route == f"/channels/{PARENT}":
            return {"id": PARENT, "guild_id": GUILD, "name": "bug-reports", "type": 0}
        if route == f"/channels/{THREAD}":
            return {"id": THREAD, "guild_id": GUILD, "name": "Issue", "type": 11, "parent_id": PARENT}
        if route == f"/channels/{THREAD}/messages?limit=2":
            return [{"id": MESSAGE, "content": "Issue description", "author": {"username": "Fixture"}}]
        if route == f"/channels/{THREAD}/messages" and values:
            return {"id": MESSAGE, "channel_id": THREAD}
        raise AssertionError(route)


class DiscordToolsTest(unittest.TestCase):
    def test_resolves_channel_names_only_within_one_bound_server(self):
        config = {"bindings": [{"agentId": "fixture", "match": {"channel": "discord", "guildId": GUILD,
                   "peer": {"kind": "channel", "id": PARENT}}}]}
        self.assertEqual(resolve_channel(FakeDiscord(), config, "fixture", "#bug-reports")["channel"], PARENT)
        with self.assertRaises(SetupError):
            resolve_channel(FakeDiscord(), config, "unbound", "#bug-reports")

    def test_reads_messages_and_returns_real_parent_as_scope_metadata(self):
        client = FakeDiscord()
        resource = describe_channel(client, THREAD)
        self.assertEqual(resource["parent"], PARENT)
        info = run(client, "discord_read_messages", {"channel": THREAD, "guild": GUILD, "limit": 2})
        self.assertEqual(info[0]["content"], "Issue description")

    def test_reply_is_exactly_scoped_and_does_not_ping(self):
        client = FakeDiscord()
        run(client, "discord_post_message", {
            "channel": THREAD, "guild": GUILD, "parentChannel": PARENT,
            "replyTo": MESSAGE, "content": "Test reply",
        })
        sent = client.calls[-1][1]
        self.assertEqual(sent["message_reference"]["channel_id"], THREAD)
        self.assertEqual(sent["allowed_mentions"], {"parse": [], "replied_user": False})

    def test_declines_other_server_or_parent_before_sending(self):
        for changed in ({"guild": FOREIGN}, {"parentChannel": FOREIGN}):
            client = FakeDiscord()
            args = {"channel": THREAD, "guild": GUILD, "parentChannel": PARENT, "content": "blocked", **changed}
            with self.assertRaises(SetupError):
                run(client, "discord_post_message", args)
            self.assertEqual(client.calls, [(f"/channels/{THREAD}", None)])
