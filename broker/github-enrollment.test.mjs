import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { Access, adminAgent } from "./access.mjs";
import { newBrowserId } from "./browser-pairing.mjs";
import { GithubGit, githubInstallation, mintInstallationToken } from "./github-native.mjs";
import { githubMcpEndpoint } from "./github-registration.mjs";
import { Registry } from "./registry.mjs";
import { RemoteConnectors } from "./remote.mjs";

const requester = "123456789012345678";
const actor = { agent: adminAgent, user: requester };
const pem = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs8", format: "pem" });
const permissions = mode => ({ contents: mode, issues: mode, pull_requests: mode });

test("GitHub installs through browser pairing and keeps the signing key bound to the approved account", async () => {
  const registry = new Registry(":memory:");
  const entry = registry.add("GitHub", githubMcpEndpoint, adminAgent);
  const row = registry.get(entry.id);
  let selection = "selected";
  let account = "wrong-owner";
  let calls = 0;
  const remote = new RemoteConnectors(registry, { origin: "https://connect.example.com", fetch: async (url, request) => {
    if (url === "https://api.github.com/app-manifests/registration/conversions") {
      assert.equal(request.method, "POST");
      return Response.json({ id: 18, slug: "fixture", pem }, { status: 201 });
    }
    calls += 1;
    assert.equal(url, "https://api.github.com/users/example/installation");
    assert.match(request.headers.Authorization, /^Bearer ey/);
    assert(!request.headers.Authorization.includes(pem));
    return Response.json({ id: 22, app_id: 18, account: { login: account, type: "User" },
      repository_selection: selection, permissions: permissions("write") });
  } });
  const ticket = remote.begin(row, requester, actor, { method: "github_installation", access: "write", account: "example" });
  assert(!JSON.stringify(ticket).includes("PRIVATE KEY"));
  const pending = remote.pending(ticket.sign_in_url.split("/").pop());
  const browser = newBrowserId();
  const code = pending.pairing.codeFor(browser);
  assert.throws(() => remote.confirm(row, "123456789012345679", code, actor), /requester/);
  remote.confirm(row, requester, code, actor);
  assert(pending.pairing.canContinue(browser));
  assert(!pending.pairing.canContinue(newBrowserId()));
  assert.deepEqual(remote.manifest(pending).data.default_permissions, permissions("write"));
  await remote.finishManifest(pending, pending.registrationState, "registration");
  assert.equal(registry.get(entry.id).credential, null);
  await assert.rejects(remote.finishGitHubInstallation(pending), /all repositories/);
  account = "EXAMPLE";
  await assert.rejects(remote.finishGitHubInstallation(pending), /all repositories/);
  selection = "all";
  await remote.finishGitHubInstallation(pending);
  assert.equal(calls, 3);
  assert.throws(() => remote.pending(pending.link), /expired/);
  await assert.rejects(remote.finishManifest(pending, pending.registrationState, "registration"), /expired/);
  const saved = githubInstallation(registry.get(entry.id));
  assert.equal(saved.installationId, "22");
  assert.equal(saved.account, "example");
  assert.equal(saved.privateKey, pem);
  assert(!JSON.stringify(registry.list()).includes("PRIVATE KEY"));

  const access = new Access(registry, user => user === requester);
  assert((await access.snapshot(actor)).can(row.id, "share"));
  const other = { agent: "downstream", user: requester };
  assert(!(await access.snapshot(other)).can(row.id, "use"));
  registry.grant(row.id, other.agent);
  assert((await access.snapshot(other)).can(row.id, "use"));
  assert(!(await access.snapshot(other)).can(row.id, "share"));
});

test("the pinned read-only credential bounds token creation and native pushes", async () => {
  const row = { id: "fixture", revision: 1, endpoint: githubMcpEndpoint, credential: JSON.stringify({
    kind: "github_installation", account: "example", ownerType: "Organization", access: "read",
    appId: "18", installationId: "22", privateKey: pem,
  }) };
  const installation = githubInstallation(row);
  assert.equal(await mintInstallationToken(installation, { fetch: async (url, request) => {
    assert.equal(url, "https://api.github.com/app/installations/22/access_tokens");
    assert.deepEqual(JSON.parse(request.body), { permissions: permissions("read") });
    return Response.json({ token: "ghs_fixture" }, { status: 201 });
  } }), "ghs_fixture");
  const git = new GithubGit({ checkGrant: async () => row });
  assert.throws(() => git.open(row, actor, "example/rack", {
    ref: "refs/heads/branch", oldCommit: "0".repeat(40), newCommit: "a".repeat(40),
  }), /read-only/);
});
