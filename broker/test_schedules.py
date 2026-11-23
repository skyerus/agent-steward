from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from uuid import uuid4

from schedules import ScheduleError, execute_schedule


class TestSchedules(unittest.TestCase):
    def setUp(self):
        state = TemporaryDirectory()
        self.addCleanup(state.cleanup)
        self.state = Path(state.name)
        self.jobs = {}
        self.scope = dict(agent="rack", user="123456789012345678", account="default",
                          channel="223456789012345678", surface="text",
                          session="agent:rack:discord:channel:223456789012345678")
        self.other = dict(self.scope, agent="main", channel="323456789012345678",
                          session="agent:main:discord:channel:323456789012345678")
        self.cfg = {
            "agents": {"entries": {"rack": {"runtime": "codex"}, "main": {"runtime": "claude-code"}}},
            "bindings": [
                {"agentId": self.scope["agent"], "match": {"channel": "discord", "peer": {"kind": "channel", "id": self.scope["channel"]}}},
                {"agentId": self.other["agent"], "match": {"channel": "discord", "accountId": "default"}},
            ],
            "channels": {"discord": {"guilds": {"guild": {"channels": {s["channel"]: {"enabled": True}
                             for s in (self.scope, self.other)}}}}},
            "plugins": {"entries": {"sable-integration-review": {"config": {"speakers": [self.scope["user"]]}}}},
        }
        self.evidence = [{"role": "user", "source": "authenticated Discord user", "text": "Every Monday, list my integrations."}]

    def rpc(self, method, args):
        if method == "cron.add":
            self.assertEqual(args["payload"]["kind"], "agentTurn")
            self.assertNotIn("model", args["payload"])
            self.assertNotIn("runtime", args["payload"])
            self.assertEqual(args["delivery"], {"mode": "none"})
            self.assertTrue(args["sessionTarget"].startswith("session:agent:"))
            job = {**args, "id": str(uuid4()), "configRevision": "original"}
            self.jobs[job["id"]] = job
            return job
        if method == "cron.list":
            return {"jobs": list(self.jobs.values())}
        job = self.jobs[args["id"]]
        if method == "cron.get":
            return job
        self.assertEqual(args["expectedConfigRevision"], job["configRevision"])
        if method == "cron.remove":
            del self.jobs[job["id"]]
            return {"removed": True}
        self.assertEqual(method, "cron.update")
        job.update(args["patch"], configRevision=str(uuid4()))
        return job

    def call(self, action, args, scope=None):
        return execute_schedule({"action": action, "args": args, "scope": self.scope if scope is None else scope,
                                 "conversation": self.evidence}, self.cfg, self.rpc, self.state)

    def test_ownership_live_revision_and_no_harness_pin(self):
        data = dict(name="Weekly list", task="List integrations", cron="0 12 * * 1")
        first = self.call("create", data)
        second = self.call("create", data, self.other)
        self.assertNotEqual(first["id"], second["id"])
        ident = {"id": first["id"]}
        self.assertEqual([row["id"] for row in self.call("list", {})["schedules"]], [first["id"]])
        with self.assertRaisesRegex(ScheduleError, "no matching"):
            self.call("remove", ident, self.other)
        with self.assertRaisesRegex(ScheduleError, "advertised fields"):
            self.call("create", {**data, "agentId": "main"})
        self.assertFalse(self.call("update", {**ident, "enabled": False})["enabled"])
        self.assertTrue(self.call("update", {**ident, "enabled": True})["enabled"])
        self.jobs[first["id"]]["state"] = {"runningAtMs": 1795359300000}
        narrowed = {"agent": "rack", "session": self.scope["session"]}
        run = {**ident, "startedAt": 1795359300000}
        self.assertEqual(self.call("authorize_run", run, narrowed)["conversation"], self.evidence)
        with self.assertRaisesRegex(ScheduleError, "does not match"):
            self.call("authorize_run", {**run, "startedAt": 1}, narrowed)
        guild = self.cfg["channels"]["discord"]["guilds"]["guild"]
        guild["users"] = ["423456789012345678"]
        with self.assertRaisesRegex(ScheduleError, "does not match"):
            self.call("authorize_run", run, narrowed)
        del guild["users"]
        self.jobs[first["id"]]["configRevision"] = "someone-edited-the-definition"
        with self.assertRaisesRegex(ScheduleError, "does not match"):
            self.call("authorize_run", run, narrowed)
        self.assertTrue(self.call("remove", ident)["removed"])


if __name__ == "__main__":
    unittest.main()
