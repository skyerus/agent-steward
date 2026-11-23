import copy
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from discord_onboarding import (
    ADMIN, DISCORD_ID, MANAGE_CHANNELS, MANAGE_GUILD, PLUGIN, TEXT, VIEW, VOICE,
    DiscordError, Jobs, SetupError, advance, invite_url, plan_for, status,
)

ADMIN_USER = "111111111111111111"
MEMBER = "222222222222222222"
BOT = "333333333333333333"
GUILD = "444444444444444444"
OLD_GUILD = "555555555555555555"
BOT_ROLE = "666666666666666666"
ADMIN_ROLE = "777777777777777777"


def merge(base, patch):
    for key, value in patch.items():
        if isinstance(value, dict):
            merge(base.setdefault(key, {}), value)
        else:
            base[key] = value


def configuration():
    return {
        "agents": {"entries": {ADMIN: {}, "rack": {}}},
        "bindings": [{"agentId": ADMIN, "match": {"channel": "discord", "accountId": "default",
                     "peer": {"kind": "direct", "id": ADMIN_USER}}}],
        "plugins": {"entries": {PLUGIN: {"config": {"speakers": [ADMIN_USER]}}}},
        "channels": {"discord": {"applicationId": BOT, "dmPolicy": "allowlist", "allowFrom": [ADMIN_USER],
                     "groupPolicy": "allowlist", "voice": {"enabled": True, "allowedChannels": []},
                     "guilds": {OLD_GUILD: {"users": [ADMIN_USER], "channels": {"old": {"allow": True}}}}}},
    }


class FixtureDiscord:
    def __init__(self):
        self.installed = False
        self.ambiguous = False
        self.requester_permissions = MANAGE_GUILD
        self.bot_permissions = MANAGE_CHANNELS | TEXT | VOICE
        self.channels = []

    def joined_guilds(self):
        if self.installed:
            yield {"id": GUILD, "name": "RACK"}
        if self.ambiguous:
            yield {"id": OLD_GUILD, "name": "Rack"}

    def request(self, route, values=None):
        if not self.installed:
            raise DiscordError(403)
        if route == f"/guilds/{GUILD}":
            return {"id": GUILD, "owner_id": MEMBER, "roles": [
                {"id": BOT_ROLE, "permissions": str(self.bot_permissions)},
                {"id": ADMIN_ROLE, "permissions": str(self.requester_permissions)},
            ]}
        if route.startswith(f"/guilds/{GUILD}/members/"):
            user = route.rsplit("/", 1)[1]
            return {"roles": [BOT_ROLE] if user == BOT else [ADMIN_ROLE] if user == ADMIN_USER else []}
        if route == f"/guilds/{GUILD}/channels":
            if values is None:
                return copy.deepcopy(self.channels)
            channel = {**values, "id": str(800_000_000_000_000_000 + len(self.channels))}
            self.channels.append(channel)
            return channel
        raise AssertionError(route)


class OnboardingTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.jobs = Jobs(Path(self.temp.name) / "jobs.sqlite")
        self.addCleanup(self.jobs.db.close)
        self.cfg = configuration()
        self.discord = FixtureDiscord()
        self.plan = plan_for({"server": "RACK", "agentIds": ["rack"], "allowedUsers": [MEMBER],
                              "voice": True}, ADMIN_USER, self.cfg)
        self.now = 1000
        self.job = self.jobs.begin(self.plan, ADMIN_USER, self.now)

    def step(self, override=None):
        advance(self.jobs, self.job, self.discord, lambda: self.cfg, lambda: "rev",
                override or (lambda values, _: merge(self.cfg, values)), self.now)
        self.job = self.jobs.get(self.job["id"], ADMIN_USER)
        self.now += 30
        return status(self.job)

    def test_one_approval_then_private_channels_and_scoped_users(self):
        first = self.step()
        self.assertEqual(first["state"], "awaiting_install")
        self.assertFalse(self.discord.channels)
        self.assertEqual(urlsplit(first["installUrl"]).hostname, "discord.com")
        self.assertNotIn("guild_id", parse_qs(urlsplit(first["installUrl"]).query))
        self.discord.installed = True
        ready = self.step()
        self.assertEqual(ready["state"], "ready")
        self.assertEqual(ready["guildId"], GUILD)
        self.assertEqual([room["kind"] for room in ready["channels"]], ["text", "voice"])
        self.assertEqual([channel["type"] for channel in self.discord.channels], [4, 0, 2])
        for channel in self.discord.channels:
            self.assertEqual(channel["permission_overwrites"][0],
                             {"id": GUILD, "type": 0, "allow": "0", "deny": str(VIEW)})
        scoped = self.cfg["plugins"]["entries"][PLUGIN]["config"]
        self.assertEqual(scoped["speakers"], [ADMIN_USER])
        self.assertEqual(set(scoped["speakerChannels"]), {room["channelId"] for room in ready["channels"]})
        self.assertEqual(self.cfg["channels"]["discord"]["guilds"][OLD_GUILD]["users"], [ADMIN_USER])
        self.assertTrue(all(room["enabled"] for room in self.cfg["channels"]["discord"]["guilds"][GUILD]["channels"].values()))
        self.assertTrue(self.cfg["channels"]["discord"]["voice"]["autoJoin"][0]["whenOccupied"])

    def test_bot_permission_failure_returns_guild_specific_link(self):
        self.discord.installed = True
        self.discord.bot_permissions &= ~MANAGE_CHANNELS
        result = self.step()
        self.assertEqual(result["state"], "permissions_needed")
        query = parse_qs(urlsplit(result["installUrl"]).query)
        self.assertEqual(query["guild_id"], [GUILD])
        self.assertEqual(query["disable_guild_select"], ["true"])
        self.assertFalse(self.discord.channels)

    def test_requester_must_manage_target_server(self):
        self.discord.installed = True
        self.discord.requester_permissions = 0
        self.assertEqual(self.step()["state"], "blocked")
        self.assertFalse(self.discord.channels)

    def test_retry_reuses_private_channels_after_partial_success(self):
        self.discord.installed = True

        def unavailable(*_):
            raise OSError("fixture gateway unavailable")

        self.assertEqual(self.step(unavailable)["state"], "retrying")
        self.assertEqual(len(self.discord.channels), 3)
        self.assertEqual(self.step()["state"], "ready")
        self.assertEqual(len(self.discord.channels), 3)

    def test_ambiguous_name_and_wrong_requester_fail_closed(self):
        self.discord.installed = self.discord.ambiguous = True
        self.assertEqual(self.step()["state"], "blocked")
        self.assertFalse(self.discord.channels)
        with self.assertRaises(SetupError):
            self.jobs.get(self.job["id"], MEMBER)

    def test_configured_id_is_pinned_and_retry_does_not_duplicate_job(self):
        link = invite_url(dict(self.plan, server=GUILD))
        query = parse_qs(urlsplit(link).query)
        self.assertEqual(query["guild_id"], [GUILD])
        self.assertEqual(self.jobs.begin(self.plan, ADMIN_USER, self.now)["id"], self.job["id"])
        self.assertIsNotNone(DISCORD_ID.fullmatch(query["client_id"][0]))


if __name__ == "__main__":
    unittest.main()
