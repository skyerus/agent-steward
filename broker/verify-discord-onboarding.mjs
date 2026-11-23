import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const requester = process.argv[2];
assert.match(requester, /^[0-9]{16,22}$/);
const client = new Client({ name: "discord-onboarding-smoke", version: "1" });
const transport = new StdioClientTransport({
  command: process.execPath, args: ["/opt/sable/integrations/lifecycle/stdio-bridge.mjs", "integrations"],
});
const opts = { timeout: 20_000 };
await client.connect(transport, opts);
const admin = { __sableActor: { agent: "integration-admin", user: requester } };
const downstream = { __sableActor: { agent: "accounting", user: requester } };
const invoke = (name, args) => client.callTool({ name, arguments: args }, undefined, opts);
async function expected(name, args) {
  const result = await invoke(name, args);
  assert.equal(result.isError ?? false, false, result.content[0].text);
  return JSON.parse(result.content[0].text);
}

const guild = "123456789012345678";
const test = { server: guild, agentIds: ["accounting"] };
let requestId;
try {
  assert.equal((await invoke("prepare_discord_server", { ...test, ...downstream })).isError, true);
  const draft = await expected("prepare_discord_server", { ...test, ...admin });
  requestId = draft.requestId;
  assert.equal(draft.state, "awaiting_install");
  const url = new URL(draft.installUrl);
  assert.equal(url.origin, "https://discord.com");
  assert.equal(url.searchParams.get("guild_id"), guild);
  assert.equal(url.searchParams.get("disable_guild_select"), "true");
  assert.ok(Number(url.searchParams.get("permissions")) & 16);
  const nextBefore = execFileSync("/usr/bin/python3", ["-c", `
import sqlite3, sys
db=sqlite3.connect("file:/var/lib/sable-discord-onboarding/jobs.sqlite?mode=ro", uri=True)
print(db.execute("SELECT next_check FROM setups WHERE id=?", (sys.argv[1],)).fetchone()[0])
`, requestId], { encoding: "utf8" }).trim();
  execFileSync("/usr/bin/systemctl", ["start", "sable-discord-onboarding.service"], { timeout: 30_000 });
  const pending = await expected("discord_server_setup_status", { requestId, ...admin });
  assert.equal(pending.state, "awaiting_install");
  const nextAfter = execFileSync("/usr/bin/python3", ["-c", `
import sqlite3, sys
db=sqlite3.connect("file:/var/lib/sable-discord-onboarding/jobs.sqlite?mode=ro", uri=True)
print(db.execute("SELECT next_check FROM setups WHERE id=?", (sys.argv[1],)).fetchone()[0])
`, requestId], { encoding: "utf8" }).trim();
  // The timer may already have polled between create and the first read.
  assert.ok(Number(nextAfter) > Number(nextBefore) || Number(nextAfter) > Date.now() / 1000);
  console.log("Admin-only invite, Discord join verification and pending setup status passed on the live VPS.");
} finally {
  try {
    if (requestId) {
      assert.equal((await expected("cancel_discord_server_setup", { requestId, ...admin })).state, "cancelled");
    }
  } finally {
    await client.close();
  }
}
