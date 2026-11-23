"""Conversation-owned schedules using OpenClaw's authenticated local Gateway RPC."""

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3


class ScheduleError(Exception):
    pass


JOB_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
DISCORD_ID = re.compile(r"[0-9]{16,22}")
TOOL_CAP = [
    "exec", "process", "bundle-mcp", "skills_search", "skills_read",
    "sessions_spawn", "sessions_yield", "subagents",
]


def permitted(config, scope):
    agent, user, room, account = (scope.get(field, "") for field in ("agent", "user", "channel", "account"))
    if not isinstance(agent, str) or agent not in config.get("agents", {}).get("entries", {}):
        return False
    if not all(isinstance(value, str) and DISCORD_ID.fullmatch(value) for value in (user, room)):
        return False
    if account != "default" or scope.get("surface") not in ("text", "voice"):
        return False
    session = scope.get("session", "")
    if not isinstance(session, str) or not session.startswith(f"agent:{agent}:discord:"):
        return False
    discord = config.get("channels", {}).get("discord", {})
    review = config.get("plugins", {}).get("entries", {}).get("sable-integration-review", {}).get("config", {})
    matching = [entry for entry in config.get("bindings", [])
                if (match := entry.get("match", {})).get("channel") == "discord"
                and match.get("accountId", "default") == account]
    if (scope["surface"] == "text" and discord.get("dmPolicy") == "allowlist"
            and user in map(str, discord.get("allowFrom", []))
            and any(entry.get("agentId") == agent and entry["match"].get("peer") == {"kind": "direct", "id": user}
                    for entry in matching)):
        # Direct-message keys, on default or per-peer routing, need not include the room ID.
        return ":direct:" in session or ":dm:" in session
    configured = [(guild, value, channel) for guild, value in discord.get("guilds", {}).items()
                  if isinstance((channel := value.get("channels", {}).get(room)), dict)]
    if agent == "integration-admin" or len(configured) != 1:
        return False
    guild, server_config, room_config = configured[0]
    if any(settings.get("enabled") is False or settings.get("allow") is False
           for settings in (discord, server_config, room_config)):
        return False
    allowed_users = room_config.get("users", server_config.get("users"))
    if allowed_users is not None and user not in map(str, allowed_users):
        return False
    explicit_channel = [entry for entry in matching if entry["match"].get("peer") == {"kind": "channel", "id": room}]
    if explicit_channel:
        routed = explicit_channel[0].get("agentId")
    else:
        relevant = [entry for entry in matching if "peer" not in entry["match"]
                    and entry["match"].get("guildId", guild) == guild]
        # Require an unambiguous account/guild binding. Role-based routing needs a dedicated channel binding
        # before it can provide durable authorization without replaying live Discord role lookups.
        if any(entry["match"].keys() - {"channel", "accountId", "guildId"} for entry in relevant):
            return False
        guild_default = [entry for entry in relevant if entry["match"].get("guildId") == guild]
        routed = next((entry.get("agentId") for entry in (guild_default or relevant)), None)
    return routed == agent and room in session.split(":") and user in map(str,
        review.get("speakerChannels", {}).get(room, review.get("speakers", [])))


def schedule_time(args):
    if ("at" in args) == ("cron" in args):
        raise ScheduleError("Provide one schedule time, using an ISO timestamp or a cron expression.")
    if "at" in args:
        try:
            timestamp = datetime.fromisoformat(args["at"].replace("Z", "+00:00"))
            if timestamp.utcoffset() is None or timestamp <= datetime.now(timezone.utc):
                raise ValueError()
            return {"kind": "at", "at": timestamp.isoformat()}
        except (AttributeError, ValueError):
            raise ScheduleError("Use a future ISO 8601 timestamp with a timezone.") from None
    value = args["cron"]
    if not isinstance(value, str) or len(value.split()) != 5 or len(value) > 160:
        raise ScheduleError("Use a five-field cron expression.")
    zone = args.get("timezone")
    if zone is not None and (not isinstance(zone, str) or len(zone) > 80):
        raise ScheduleError("Provide an IANA timezone for that schedule.")
    return {"kind": "cron", "expr": value, **({"tz": zone} if zone else {})}


def changes(args, inherit_local_tools=False):
    patch = {}
    for field, limit in (("name", 100), ("task", 12000)):
        if field not in args:
            continue
        value = args[field]
        if not isinstance(value, str) or not value.strip() or len(value) > limit:
            raise ScheduleError(f"Provide a valid schedule {field}.")
        if field == "name":
            patch[field] = value.strip()
        else:
            patch["payload"] = {"kind": "agentTurn", "message": value, "toolsAllow": ["*"] if inherit_local_tools else TOOL_CAP}
    if {"at", "cron", "timezone"} & args.keys():
        patch["schedule"] = schedule_time(args)
    if "enabled" in args:
        if type(args["enabled"]) is not bool:
            raise ScheduleError("Enabled must be true or false.")
        patch["enabled"] = args["enabled"]
    return patch


def verified_evidence(conversation):
    if (not isinstance(conversation, list) or not conversation or len(json.dumps(conversation)) > 26000
            or conversation[-1].get("role") != "user"):
        raise ScheduleError("The authenticated scheduling request could not be retained.")
    if any(set(message) != {"role", "source", "text"} or message["role"] not in ("user", "assistant")
           or not isinstance(message["text"], str) for message in conversation):
        raise ScheduleError("The scheduling conversation could not be verified.")
    return conversation


def owned_native(job, scope):
    return (job.get("agentId") == scope["agent"] and job.get("sessionTarget") == f"session:{scope['session']}"
            and job.get("payload", {}).get("kind") == "agentTurn"
            and job.get("delivery", {}).get("mode") == "none"
            and isinstance(job.get("configRevision"), str))


def summary(job):
    fields = ("id", "name", "schedule", "enabled", "deleteAfterRun")
    return {**{key: job.get(key) for key in fields},
            "lastRunStatus": job.get("state", {}).get("lastRunStatus"),
            "nextRunAtMs": job.get("state", {}).get("nextRunAtMs")}


def execute_schedule(message, config, rpc, state_dir):
    action, args, scope = (message.get(key) for key in ("action", "args", "scope"))
    if (not isinstance(args, dict) or not isinstance(scope, dict)
            or (action != "authorize_run" and not permitted(config, scope))):
        raise ScheduleError("A currently authorised Discord conversation is required.")
    with sqlite3.connect(Path(state_dir) / "schedules.sqlite") as db:
        db.row_factory = sqlite3.Row
        db.execute("""CREATE TABLE IF NOT EXISTS schedules (
            id TEXT PRIMARY KEY, agent TEXT NOT NULL, session TEXT NOT NULL,
            revision TEXT NOT NULL, grant_json TEXT NOT NULL
        )""")
        return execute_owned(db, action, args, scope, message, config, rpc)


def execute_owned(db, action, args, scope, message, config, rpc):
    if action == "list":
        reject_fields(args, set())
        job_ids = {row["id"] for row in db.execute("SELECT id FROM schedules WHERE agent=? AND session=?",
                                                  (scope["agent"], scope["session"]))}
        if not job_ids:
            return {"schedules": []}
        offset, visible = 0, []
        while job_ids:
            page = rpc("cron.list", {"includeDisabled": True, "agentId": scope["agent"], "limit": 100, "offset": offset})
            for job in page["jobs"]:
                if (identifier := job.get("id")) in job_ids:
                    job_ids.remove(identifier)
                    if owned_native(job, scope):
                        visible.append(summary(job))
            next_offset = page.get("nextOffset")
            if type(next_offset) is not int or next_offset <= offset:
                if not page.get("hasMore"):
                    db.executemany("DELETE FROM schedules WHERE id=? AND agent=? AND session=?",
                                   [(identifier, scope["agent"], scope["session"]) for identifier in job_ids])
                break
            offset = next_offset
        return {"schedules": visible}
    if action == "create":
        reject_fields(args, {"name", "task", "cron", "at", "timezone", "enabled", "keepAfterRun"})
        patch = changes(args, message.get("inheritLocalTools") is True)
        if not {"schedule", "name", "payload"} <= patch.keys():
            raise ScheduleError("Provide a name, task and schedule time.")
        evidence = verified_evidence(message.get("conversation"))
        enabled = patch.pop("enabled", True)
        created = rpc("cron.add", {**patch, "agentId": scope["agent"], "sessionKey": scope["session"],
            "sessionTarget": f"session:{scope['session']}", "wakeMode": "now", "delivery": {"mode": "none"},
            "enabled": False, "deleteAfterRun": patch["schedule"]["kind"] == "at" and args.get("keepAfterRun") is not True})
        job_id = created.get("id")
        if not isinstance(job_id, str) or not JOB_ID.fullmatch(job_id):
            raise ScheduleError("OpenClaw did not return a schedule ID.")
        try:
            job = read_job(rpc, job_id, scope)
            save_grant(db, job, scope, evidence)
        except Exception:
            rpc("cron.remove", {"id": job_id})
            raise
        if enabled:
            job = rpc("cron.update", {"id": job_id, "expectedConfigRevision": job["configRevision"], "patch": {"enabled": True}})
            save_grant(db, job, scope, evidence)
        return summary(job)

    job_id = args.get("id")
    if not isinstance(job_id, str) or not JOB_ID.fullmatch(job_id):
        raise ScheduleError("Use an ID returned by this conversation's schedule list.")
    row = db.execute("SELECT * FROM schedules WHERE id=? AND agent=? AND session=?",
                     (job_id, scope["agent"], scope["session"])).fetchone()
    if not row:
        raise ScheduleError("This conversation has no matching schedule.")
    job = read_job(rpc, job_id, scope)
    grant = json.loads(row["grant_json"])
    if action == "authorize_run":
        if (not permitted(config, grant["scope"]) or type(args.get("startedAt")) is not int
                or job["configRevision"] != row["revision"] or job.get("enabled") is not True
                or job.get("state", {}).get("runningAtMs") != args.get("startedAt")):
            raise ScheduleError("The current native occurrence does not match the saved authorization.")
        return {**grant, "revision": row["revision"], "task": job["payload"]["message"]}
    if action == "get":
        reject_fields(args, {"id"})
        return {**summary(job), "task": job["payload"]["message"]}
    if action == "remove":
        reject_fields(args, {"id"})
        outcome = rpc("cron.remove", {"id": job_id, "expectedConfigRevision": job["configRevision"]})
        if not outcome.get("removed"):
            raise ScheduleError("OpenClaw did not remove the schedule.")
        db.execute("DELETE FROM schedules WHERE id=?", (job_id,))
        return {"id": job_id, "removed": True}
    if action == "update":
        reject_fields(args, {"id", "name", "task", "cron", "at", "timezone", "enabled"})
        patch = changes(args, message.get("inheritLocalTools") is True)
        if not patch:
            raise ScheduleError("Provide a schedule change.")
        if "task" in args:
            grant = {"scope": scope, "conversation": verified_evidence(message.get("conversation"))}
        elif job["configRevision"] != row["revision"]:
            raise ScheduleError("The schedule changed outside Discord. Include the intended task to reauthorise it.")
        if "schedule" in patch:
            patch["deleteAfterRun"] = patch["schedule"]["kind"] == "at" and job.get("deleteAfterRun") is True
        updated = rpc("cron.update", {"id": job_id, "expectedConfigRevision": job["configRevision"], "patch": patch})
        save_grant(db, updated, grant["scope"], grant["conversation"])
        return summary(updated)
    raise ScheduleError("Unknown schedule action.")


def reject_fields(args, allowed):
    if args.keys() - allowed:
        raise ScheduleError("Use only the schedule tool's advertised fields.")


def read_job(rpc, job_id, scope):
    job = rpc("cron.get", {"id": job_id})
    if not owned_native(job, scope):
        raise ScheduleError("The native schedule no longer belongs to this conversation.")
    return job


def save_grant(db, job, scope, evidence):
    if not owned_native(job, scope):
        raise ScheduleError("OpenClaw did not confirm the schedule's owner and revision.")
    db.execute("""INSERT INTO schedules VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE
        SET revision=excluded.revision, grant_json=excluded.grant_json""",
        (job["id"], scope["agent"], scope["session"], job["configRevision"],
         json.dumps({"scope": scope, "conversation": evidence})))
    db.commit()
