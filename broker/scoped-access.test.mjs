import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Registry } from "./registry.mjs";
import { ScopedAccess } from "./scoped-access.mjs";
import { newBrowserId } from "./browser-pairing.mjs";

const owner = { user: "111111111111111111", agent: "integration-admin" };
const worker = { user: "222222222222222222", agent: "fresh-worker" };
const guild = "333333333333333333";
const channel = "444444444444444444";
const config = { origin: "https://connect.example.com", isAdmin: async user => user === owner.user };

test("the agent's browser link grants no access until a Discord administrator pairs and approves it", async () => {
  const directory = mkdtempSync(join(tmpdir(), "scoped-grants-"));
  const database = join(directory, "fixture.sqlite");
  const registry = new Registry(database);
  let store;
  try {
    store = new ScopedAccess(registry, config);
    const row = registry.add("Example GitHub", "https://github.example.com/mcp", owner.agent, { fixture: true });
    const grant = { agent: worker.agent, provider: "github", connection: row.id, revision: row.revision,
      resource: "example/project", permission: "read", label: row.label };
    const result = store.request(worker, grant);
    assert.match(result.approval_url, /^https:\/\/connect\.example\.com\/connect\/access\/[\w-]{43}$/);
    assert.equal(store.status(result.request, worker, false).status, "approval_required");
    const browser = newBrowserId();
    const code = store.code(result.request, browser);
    await assert.rejects(store.approve(result.request, browser, async () => {}), /administrator browser/);
    await assert.rejects(store.pair(result.request, worker, code), /Integration Admin/);
    assert(!store.allows(worker.agent, "github", row.id, row.revision, grant.resource, "read"));
    await store.pair(result.request, owner, code);
    await assert.rejects(store.approve(result.request, newBrowserId(), async () => {}), /administrator browser/);
    assert(!store.allows(worker.agent, "github", row.id, row.revision, grant.resource, "read"));
    await store.approve(result.request, browser, async (scope, user) => {
      assert.deepEqual(scope, grant);
      assert.equal(user, owner.user);
    });
    registry.db.close();
    const reopened = new Registry(database);
    store = new ScopedAccess(reopened, config);
    assert.equal(await store.browserAdmin(browser), owner.user);
    assert.equal(store.status(result.request, worker, false).status, "approved");
    assert(store.allows(worker.agent, "github", row.id, row.revision, grant.resource, "read"));
    assert(!store.allows(worker.agent, "github", row.id, row.revision, grant.resource, "write"));
    assert(!store.allows(worker.agent, "github", row.id, row.revision, "example/other", "read"));
    assert(!store.allows("another-agent", "github", row.id, row.revision, grant.resource, "read"));
    reopened.edit(row.id, row.revision, { endpoint: "https://new.example.com/mcp" });
    assert(!store.allows(worker.agent, "github", row.id, row.revision + 1, grant.resource, "read"));
    reopened.db.close();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("standing grants apply to future downstream agents and thread writes stay separate from parent writes", async () => {
  let adminsEnabled=true;
  const store = new ScopedAccess(new Registry(":memory:"), {
    ...config, isAdmin: async user => adminsEnabled && user === owner.user,
  });
  const grant = { agent: "*", provider: "discord", connection: guild, revision: 1, resource: channel,
    permission: "read", threadPermission: "write", label: "Test server / Bugs" };
  const request=store.request(owner,grant);
  const browser=newBrowserId();
  await store.pair(request.request,owner,store.code(request.request,browser));
  await store.approve(request.request,browser,async () => {});
  assert(store.allows("future-worker","discord",guild,1,channel,"read"));
  assert(!store.allows("future-worker","discord",guild,1,channel,"write"));
  assert(store.allowsDiscordThread("future-worker",guild,channel,"write"));
  assert(!store.allowsDiscordThread("future-worker",guild,"555555555555555555","write"));
  assert(!store.allows(owner.agent,"discord",guild,1,channel,"read"));
  const another=store.request(owner,{...grant,resource:"555555555555555555"});
  adminsEnabled=false;
  await assert.rejects(store.approve(another.request,browser,async () => {}),/administrator browser/);
  assert.equal(store.remove(grant),1);
  assert(!store.allows("future-worker","discord",guild,1,channel,"read"));
});

test("an approval cannot attach to a changed GitHub connection", async () => {
  const registry = new Registry(":memory:");
  const store = new ScopedAccess(registry, config);
  const row = registry.add("Example GitHub", "https://github.example.com/mcp", owner.agent, { fixture: true });
  const grant = { agent: worker.agent, provider: "github", connection: row.id, revision: row.revision,
    resource: "example/project", permission: "write", label: row.label };
  const { request }=store.request(worker,grant);
  const browser=newBrowserId();
  await store.pair(request,owner,store.code(request,browser));
  await assert.rejects(store.approve(request,browser,async () => {
    registry.edit(row.id,row.revision,{endpoint:"https://new.example.com/mcp"});
  }),/destination changed/);
  assert(!store.allows(worker.agent,"github",row.id,row.revision,grant.resource,"write"));
});

test("MCP grants are scoped to exact operations, destination revision, and agent", async () => {
  const registry = new Registry(":memory:");
  const store = new ScopedAccess(registry, config);
  const publisher = "publisher";
  const row = registry.add("Provider MCP", "https://provider.example.com/mcp", publisher, { fixture: true });
  const scope = { agent: worker.agent, provider: "mcp", connection: row.id, revision: row.revision,
    resource: row.id, permission: "invoke", label: row.label, tools: ["get_data", "list_data"] };
  const { request } = store.request(worker, scope);
  assert.deepEqual(store.mcpGrants(worker.agent, row.id, row.revision), new Set());
  assert.throws(() => store.request(worker, { ...scope, tools: ["*", "list_data"] }), /Specify an exact/);

  const browser = newBrowserId();
  await store.pair(request, owner, store.code(request, browser));
  await store.approve(request, browser, async () => {});
  assert.deepEqual(store.mcpGrants(worker.agent, row.id, row.revision), new Set(scope.tools));
  assert.deepEqual(store.mcpGrants("other-worker", row.id, row.revision), new Set());
  assert.deepEqual(store.mcpGrants(worker.agent, row.id, row.revision + 1), new Set());
  assert(store.sharedConnection({ ...row, owner_agent: publisher }));
  assert.equal(store.status(request, worker, false).status, "approved");

  assert.equal(store.remove({ ...scope, resource: "get_data" }), 1);
  assert.equal(store.status(request, worker, false).status, "inactive");
  assert.deepEqual(store.mcpGrants(worker.agent, row.id, row.revision), new Set(["list_data"]));

  const standing = store.request(owner, { ...scope, agent: "*", tools: ["*"] });
  await store.approve(standing.request, browser, async () => {});
  assert(store.mcpGrants("future-agent", row.id, row.revision).has("*"));
  assert(!store.mcpGrants(owner.agent, row.id, row.revision).has("*"));
  registry.edit(row.id, row.revision, { endpoint: "https://new.example.com/mcp" });
  assert.deepEqual(store.mcpGrants("future-agent", row.id, row.revision + 1), new Set());
  assert.equal(store.status(standing.request, owner, true).status, "inactive");
});
