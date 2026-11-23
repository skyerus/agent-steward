import copy
import unittest

from discord_access import gateway_settings, list_access, update_channel, update_dm
from discord_onboarding import ADMIN, PLUGIN, SetupError, actor_is_admin
from test_discord_onboarding import ADMIN_USER, MEMBER, GUILD, configuration, merge

CHANNEL = "888888888888888888"
OTHER_CHANNEL = "999999999999999999"
VOICE = "123456789012345678"
NEW_USER = "923456789012345678"


class DiscordFixture:
    rooms = [
        {"id": CHANNEL, "name": "general-agent", "guild_id": GUILD, "type": 0},
        {"id": OTHER_CHANNEL, "name": "accounting-agent", "guild_id": GUILD, "type": 0},
        {"id": VOICE, "name": "general-agent-voice", "guild_id": GUILD, "type": 2},
    ]
    identities = {
        ADMIN_USER: {"id": ADMIN_USER, "username": "skye"},
        MEMBER: {"id": MEMBER, "username": "odneme", "global_name": "Eric"},
        NEW_USER: {"id": NEW_USER, "username": "member"},
    }

    def request(self, path):
        if path.startswith(f"/guilds/{GUILD}/channels"):
            return self.rooms
        if "/members/search?" in path:
            return [{"user": identity} for identity in self.identities.values()]
        if path.startswith("/channels/"):
            return next(room for room in self.rooms if room["id"] == path.split("/")[-1])
        user = path.split("/")[-1]
        return self.identities[user]


class TestDiscordAccess(unittest.TestCase):
    def setUp(self):
        self.client = DiscordFixture()
        self.config = configuration()
        self.config["agents"]["entries"]["main"] = {}
        self.settings = gateway_settings(self.config)
        self.settings["guilds"] = {GUILD: {"users": [ADMIN_USER, MEMBER], "channels": {
            CHANNEL: {"enabled": True, "requireMention": False},
            OTHER_CHANNEL: {"enabled": True}, VOICE: {"enabled": True},
        }}}

    def update_channel(self, args):
        patch, result = update_channel(self.config, self.settings, self.client, {"channel": "#general-agent", **args})
        merge(self.config, patch)
        return result

    def update_dm(self, args):
        patch, result = update_dm(self.config, self.settings, self.client, args)
        merge(self.config, patch)
        return result

    def test_channel_update_uses_members_and_preserves_other_rooms(self):
        before = copy.deepcopy(self.settings)
        result = self.update_channel({"addUsers": [f"<@{NEW_USER}>"], "removeUsers": ["@odneme"]})
        self.assertEqual(result["users"], [ADMIN_USER, NEW_USER])
        current = self.settings["guilds"][GUILD]["channels"]
        self.assertEqual(current[OTHER_CHANNEL], before["guilds"][GUILD]["channels"][OTHER_CHANNEL])
        self.assertEqual(current[VOICE], before["guilds"][GUILD]["channels"][VOICE])
        self.assertFalse(current[CHANNEL]["requireMention"])
        self.assertEqual(self.config["plugins"]["entries"][PLUGIN]["config"]["speakerChannels"][CHANNEL],
                         [ADMIN_USER, NEW_USER])
        self.assertEqual(len(list_access(self.config, self.settings, self.client)["textChannels"]), 2)

    def test_empty_list_disables_and_admin_can_restore(self):
        result = self.update_channel({"onlyUsers": []})
        self.assertFalse(result["enabled"])
        self.assertTrue(self.update_channel({"addUsers": ["Eric"]})["enabled"])

    def test_dm_changes_admin_authority_without_affecting_guild_access(self):
        before = copy.deepcopy(self.settings["guilds"])
        self.assertFalse(self.update_dm({"user": "Eric", "agentId": "main"})["admin"])
        self.assertFalse(actor_is_admin(self.config, MEMBER))
        self.assertTrue(self.update_dm({"user": "Eric", "agentId": ADMIN})["admin"])
        self.assertTrue(actor_is_admin(self.config, MEMBER))
        self.update_dm({"user": ADMIN_USER, "revoke": True})
        self.assertFalse(actor_is_admin(self.config, ADMIN_USER))
        self.assertEqual(self.settings["guilds"], before)
        with self.assertRaisesRegex(SetupError, "Keep at least one"):
            self.update_dm({"user": MEMBER, "revoke": True})

    def test_does_not_override_role_access_on_relative_change(self):
        self.settings["guilds"][GUILD]["roles"] = [NEW_USER]
        with self.assertRaisesRegex(SetupError, "also allows Discord roles"):
            self.update_channel({"removeUsers": [MEMBER]})
        self.assertEqual(self.update_channel({"onlyUsers": ["skye"]})["users"], [ADMIN_USER])
        self.assertEqual(self.settings["guilds"][GUILD]["channels"][CHANNEL]["roles"], [])
