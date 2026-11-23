import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Registry } from "./registry.mjs";

const expectedOrigin = new URL(process.argv[2]).origin;
const administrator = process.argv[3];
assert.match(administrator, /^[0-9]{16,22}$/);
const installed = "/opt/sable/integrations/lifecycle/stdio-bridge.mjs";
const options = { timeout: 45_000 };
const terminal = new StdioClientTransport({ command: process.execPath, args: [installed, "integrations"] });
const client = new Client({ name: "integration-sign-in-smoke", version: "1" });
await client.connect(terminal, options);
const requester = "123456789012345678";
const otherRequester = "234567890123456789";
const admin = { __sableActor: { agent: "integration-admin", user: administrator } };
const actor = { __sableActor: { agent: "accounting", user: requester } };
const newAgent = "rbac-fixture-" + randomBytes(6).toString("hex");
const other = { __sableActor: { agent: newAgent, user: otherRequester } };
const invoke = (name, args = {}) => client.callTool({ name, arguments: args }, undefined, options);
async function ok(name, args) {
  const outcome = await invoke(name, args);
  assert.equal(outcome.isError ?? false, false, outcome.content[0].text);
  return JSON.parse(outcome.content[0].text);
}

let connection;
let created = false;
try {
  assert.equal((await invoke("create_agent", { agentId: newAgent, name: "RBAC Fixture", ...actor })).isError, true);
  assert.equal((await invoke("list_managed_agents", { __sableActor: { agent: "integration-admin", user: otherRequester } })).isError, true);
  assert.equal((await ok("create_agent", { agentId: newAgent, name: "RBAC Fixture", ...admin })).id, newAgent);
  created = true;
  const configured = await ok("set_agent_instructions", { agentId: newAgent, instructions: "# RBAC fixture\n", ...admin });
  assert.equal(configured.instructionsUpdated, true);
  const renamed = await ok("rename_agent", { agentId: newAgent, name: "Renamed RBAC Fixture", ...admin });
  assert.equal(renamed.name, "Renamed RBAC Fixture");
  assert.deepEqual(await ok("list_connections", other), []);
  const current = await ok("list_connections", actor);
  assert.ok(current.some(row => row.id === "gmail"), "Accounting retained its legacy access");
  const setup = { label: "Browser pairing smoke", endpoint: "https://fixture.example.com/mcp" };
  assert.equal((await invoke("add_connection", { ...setup, agentId: newAgent, ...actor })).isError, true);
  connection = await ok("add_connection", { ...setup, ...actor });
  const ref = { id: connection.id, revision: connection.revision };
  assert.equal(connection.ownerAgent, "accounting");
  assert.equal((await invoke("list_connection_tools", { ...ref, ...other })).isError, true);
  assert.equal((await invoke("grant_connection_access", { ...ref, agentId: newAgent, ...actor })).isError, true);
  assert.equal((await invoke("grant_connection_access", { ...ref, agentId: newAgent, ...admin })).isError, true);
  const directBegin = await invoke("begin_sign_in", ref);
  assert.equal(directBegin.isError, true);
  const { sign_in_url: url } = await ok("begin_sign_in", { ...ref, ...actor });
  assert.equal(new URL(url).origin, expectedOrigin);
  const first = await fetch(url);
  const second = await fetch(url);
  for (const page of [first, second]) assert.equal(page.status, 200);
  const extractCode = page => /<strong>([0-9]{8})<\/strong>/.exec(page)?.[1];
  const [firstCode, secondCode] = await Promise.all([first.text().then(extractCode), second.text().then(extractCode)]);
  assert.ok(firstCode);
  assert.ok(secondCode);
  assert.notEqual(firstCode, secondCode);
  const session = page => page.headers.get("set-cookie").split(";")[0];
  assert.match(second.headers.get("set-cookie"), /Secure; HttpOnly; SameSite=Lax/);
  const refresh = page => fetch(url, { headers: { Cookie: session(page) } }).then(response => response.text());

  const unauthorized = await invoke("confirm_sign_in", { ...ref, code: secondCode,
    __sableActor: { agent: "accounting", user: otherRequester } });
  assert.equal(unauthorized.isError, true);
  assert.doesNotMatch(await refresh(second), /Continue to provider sign-in/);
  assert.deepEqual(await ok("confirm_sign_in", { ...ref, code: secondCode, ...actor }), { browser_verified: true });
  const approvedPage = await fetch(url, { headers: { Cookie: session(second) } });
  assert.equal(approvedPage.headers.get("referrer-policy"), "same-origin");
  assert.match(await approvedPage.text(), /Continue to provider sign-in/);
  assert.doesNotMatch(await refresh(first), /Continue to provider sign-in/);
  const unpairedPost = await fetch(url, { method: "POST", headers: {
    Origin: expectedOrigin, Cookie: session(first),
  } });
  assert.equal(unpairedPost.status, 400);
  const badCallback = await fetch(expectedOrigin + "/oauth/callback?state=invalid&code=fixture", {
    headers: { Cookie: session(second) },
  });
  assert.equal(badCallback.status, 400);
  assert.deepEqual((await ok("list_connections", actor)).filter(row => row.id !== connection.id), current);

  // The fixture exercises grant enforcement without sending credentials to a real provider.
  const store = new Registry("/var/lib/sable-connection-broker/connections.sqlite");
  try {
    store.credentials(store.get(connection.id, connection.revision), { tokens: { access_token: "verification-fixture" } });
  } finally {
    store.db.close();
  }
  await ok("grant_connection_access", { ...ref, agentId: newAgent, ...admin });
  assert.deepEqual((await ok("list_connections", other)).map(row => row.id), [connection.id]);
  assert.equal((await invoke("delete_connection", { ...ref, ...actor })).isError, true);
  await ok("revoke_connection_access", { ...ref, agentId: newAgent, ...admin });
  assert.deepEqual(await ok("list_connections", other), []);
  console.log("Admin created, configured and renamed a downstream agent. Private ownership, browser pairing, sharing and revocation passed.");
} finally {
  try {
    if (connection) await ok("delete_connection", { id: connection.id, revision: connection.revision, ...admin });
  } finally {
    try {
      if (created) {
        execFileSync("/usr/sbin/runuser", ["-u", "sable-claw", "--", "/opt/sable/review-gateway/claw",
          "gateway", "call", "agents.delete", "--json", "--params", JSON.stringify({ agentId: newAgent, deleteFiles: true })],
        { stdio: "pipe", timeout: 35_000 });
      }
    } finally {
      await client.close();
    }
  }
}
