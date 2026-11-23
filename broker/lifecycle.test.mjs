import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Registry } from "./registry.mjs";
import { resolvePublic, scopedFetch } from "./public-fetch.mjs";
import { RemoteConnectors } from "./remote.mjs";
import { BrowserPairing, newBrowserId } from "./browser-pairing.mjs";
import { Access, adminAgent } from "./access.mjs";
import { githubMcpEndpoint } from "./github-registration.mjs";

const original = "https://old.example.com/mcp";
const replacement = "https://new.example.com/mcp";
const origin = "https://connect.example.com";
const requester = "123456789012345678";
const secondUser = "234567890123456789";

test("destination changes clear the old grant, including when changed back", () => {
  const registry = new Registry(":memory:");
  const { id } = registry.add("Example", original);
  const row = registry.get(id, 1);
  registry.credentials(row, { tokens: { access_token: "synthetic-first" } });
  assert.equal(registry.edit(id, 1, { label: "Renamed" }).status, "connected");
  assert.equal(registry.edit(id, 1, { endpoint: "https://OLD.example.com:443/mcp" }).revision, 1);
  const changed = registry.edit(id, 1, { endpoint: replacement });
  assert.equal(changed.status, "sign_in_required");
  assert.equal(changed.revision, 2);
  assert.equal(registry.get(id).credential, null);
  assert.throws(() => registry.credentials(row, { tokens: { access_token: "stale-refresh" } }), /changed/);
  assert.throws(() => registry.edit(id, 1, { label: "Stale" }), /destination changed/);
  registry.edit(id, 2, { endpoint: original });
  assert.equal(registry.get(id, 3).credential, null);
});

test("old names do not carry credentials, and deleted legacy routes stay retired across restarts", () => {
  const path = mkdtempSync(join(tmpdir(), "sable-connections-"));
  try {
    const db = join(path, "registry.sqlite");
    const registry = new Registry(db, { gmail: "Gmail", netlify: "Netlify" });
    assert.equal(registry.get("gmail").legacy, 1);
    registry.delete("gmail", 1);
    registry.edit("netlify", 1, { endpoint: replacement });
    const added = registry.add("Gmail", original);
    assert.notEqual(added.id, "gmail");
    const reopened = new Registry(db, { gmail: "Gmail", netlify: "Netlify" });
    assert.throws(() => reopened.get("gmail"), /does not exist/);
    assert.equal(reopened.get("netlify", 2).legacy, 0);
    assert.equal(reopened.get(added.id).credential, null);
    reopened.db.close();
    registry.db.close();
  } finally {
    rmSync(path, { recursive: true, force: true });
  }
});

test("destination checks deny private, loopback, link-local and mixed DNS answers", async () => {
  const dns = (...addresses) => async () => addresses.map(address => ({ address }));
  for (const address of ["127.9.0.1", "10.0.0.7", "169.254.169.254", "192.168.0.1", "100.64.0.2"]) {
    await assert.rejects(resolvePublic(original, dns(address)), /public addresses/);
    await assert.rejects(resolvePublic(original, dns("8.8.8.8", address)), /public addresses/);
  }
  await assert.rejects(resolvePublic("https://127.1/mcp", dns("8.8.8.8")), /public DNS/);
  assert.equal(await resolvePublic(original, dns("8.8.8.8")), "8.8.8.8");
});

test("authorization can go only to the exact resource or pinned token endpoint", () => {
  const tokenEndpoint = "https://issuer.example.com/token";
  const received = [];
  const fetch = scopedFetch(original, () => ({ authorizationServerMetadata: { token_endpoint: tokenEndpoint } }),
    request => received.push([request.url, request.headers.get("authorization")]));
  const init = { method: "POST", headers: { Authorization: "Bearer synthetic-token" } };
  fetch(original, init);
  fetch(tokenEndpoint, init);
  assert.throws(() => fetch(replacement, init), /credential binding/);
  assert.throws(() => fetch(original + "/different-path", init), /credential binding/);
  assert.throws(() => fetch(tokenEndpoint + "?changed=1", init), /credential binding/);
  assert.deepEqual(received.map(row => row[0]), [original, tokenEndpoint]);
});

test("fresh OAuth binds the new grant and stale sign-in cannot attach after an edit", async () => {
  const registry = new Registry(":memory:");
  const requests = [];
  const issuer = "https://login.example.com/";
  const fetch = async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const resource = url.hostname === "old.example.com" ? original : replacement;
    if (request.method === "GET" && url.pathname === "/mcp") return new Response(null, { status: 401 });
    if (url.pathname.startsWith("/.well-known/oauth-protected-resource")) {
      return Response.json({ resource, authorization_servers: [issuer] });
    }
    if (url.pathname === "/.well-known/oauth-authorization-server") {
      return Response.json({
        issuer, authorization_endpoint: issuer + "authorize", token_endpoint: issuer + "token",
        registration_endpoint: issuer + "register", response_types_supported: ["code"],
        code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["none"],
      });
    }
    if (url.pathname === "/register") {
      return Response.json({ ...await request.json(), client_id: "synthetic-client" });
    }
    if (url.pathname === "/token") {
      const body = new URLSearchParams(await request.text());
      const endpoint = body.get("resource");
      requests.push([endpoint, body.get("code")]);
      assert.ok(body.get("code_verifier"), "OAuth must submit its PKCE verifier");
      return Response.json({ access_token: endpoint === original ? "old-fixture-token" : "new-fixture-token",
        token_type: "Bearer", refresh_token: "fixture-refresh", expires_in: 3600 });
    }
    if (url.pathname === "/mcp") {
      assert.equal(request.headers.get("authorization"), "Bearer new-fixture-token");
      const message = await request.json();
      if (message.method === "notifications/initialized") return new Response(null, { status: 202 });
      const result = {
        initialize: { protocolVersion: message.params.protocolVersion,
          capabilities: { tools: {} }, serverInfo: { name: "fixture", version: "1" } },
        "tools/list": { tools: [{ name: "read_status", inputSchema: { type: "object" } }] },
        "tools/call": { content: [{ type: "text", text: "result from replacement" }] },
      }[message.method];
      return Response.json({ jsonrpc: "2.0", id: message.id, result });
    }
    throw new Error("Unexpected fixture request " + request.url);
  };
  const remote = new RemoteConnectors(registry, { origin, fetch, resolve: async () => "8.8.8.8" });
  const { id } = registry.add("Example", original);
  const begin = async revision => {
    const { sign_in_url } = remote.begin(registry.get(id, revision), requester);
    const pending = remote.pending(sign_in_url.split("/").at(-1));
    const authorization = await remote.authorize(pending);
    assert.equal(new URL(sign_in_url).origin, origin);
    assert.equal(authorization.searchParams.get("redirect_uri"), origin + "/oauth/callback");
    assert.equal(authorization.searchParams.get("code_challenge_method"), "S256");
    return [pending, authorization.searchParams.get("state")];
  };
  const [first, stale] = await begin(1);
  registry.edit(id, 1, { endpoint: replacement });
  await assert.rejects(remote.finish(first, stale, issuer, "stale-code"), /destination changed/);
  assert.equal(requests.length, 0);
  assert.equal(registry.get(id).credential, null);
  const [fresh, state] = await begin(2);
  await remote.finish(fresh, state, issuer, "new-code");
  const signedIn = registry.get(id, 2);
  assert.equal(JSON.parse(signedIn.credential).tokens.access_token, "new-fixture-token");
  assert.deepEqual(requests, [[replacement, "new-code"]]);
  assert.equal((await remote.tools(signedIn)).tools[0].name, "read_status");
  assert.equal((await remote.tools(signedIn, { name: "read_status" })).content[0].text, "result from replacement");
  await assert.rejects(remote.finish(fresh, state, issuer, "replayed"), /no longer current/);
});

test("only the requesting Discord account can pair its chosen browser", () => {
  const pairing = new BrowserPairing(requester);
  const first = newBrowserId();
  const second = newBrowserId();
  const selected = pairing.codeFor(second);
  assert.notEqual(pairing.codeFor(first), selected);
  assert.equal(pairing.canContinue(second), false);
  assert.throws(() => pairing.confirm("234567890123456789", selected), /requester/);
  pairing.confirm(requester, selected);
  assert.equal(pairing.canContinue(second), true);
  assert.equal(pairing.canContinue(first), false);
  assert.equal(pairing.canContinue(undefined), false);
  assert.throws(() => pairing.confirm(requester, selected), /requester/);
});

test("a configured OAuth client is used only at its registered provider", async () => {
  const registry = new Registry(":memory:");
  const issuer = "https://login.example.com/";
  const clients = [{
    endpoint: original, issuer, authorizationEndpoint: issuer + "authorize", tokenEndpoint: issuer + "token",
    clientId: "fixture-client", clientSecret: "fixture-secret",
  }];
  let discoveredToken = issuer + "token";
  let exchanges = 0;
  const fetch = async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    if (request.method === "GET" && request.url === original) return new Response(null, { status: 401 });
    if (url.pathname.startsWith("/.well-known/oauth-protected-resource")) {
      return Response.json({ resource: original, authorization_servers: [issuer] });
    }
    if (url.pathname === "/.well-known/oauth-authorization-server") {
      return Response.json({
        issuer, authorization_endpoint: issuer + "authorize", token_endpoint: discoveredToken,
        response_types_supported: ["code"], code_challenge_methods_supported: ["S256"],
      });
    }
    if (request.url === issuer + "token") {
      exchanges++;
      const body = new URLSearchParams(await request.text());
      assert.equal(body.get("client_id"), "fixture-client");
      assert.equal(body.get("client_secret"), "fixture-secret");
      assert.ok(body.get("code_verifier"));
      return Response.json({ access_token: "fixture-scoped-access", token_type: "Bearer" });
    }
    assert.fail("The client reached an unexpected host or endpoint.");
  };
  const build = options => new RemoteConnectors(registry, { origin, fetch, resolve: async () => "8.8.8.8", ...options });
  const { id } = registry.add("Configured client", original);
  const row = registry.get(id, 1);
  const pending = remote => remote.pending(remote.begin(row, requester).sign_in_url.split("/").at(-1));
  const unregistered = build();
  await assert.rejects(unregistered.authorize(pending(unregistered)), /requires a registered OAuth client/);
  const remote = build({ clients });
  discoveredToken = "https://wrong.example.com/token";
  await assert.rejects(remote.authorize(pending(remote)), /does not match the registered client/);
  discoveredToken = issuer + "token";
  const attempt = pending(remote);
  const auth = await remote.authorize(attempt);
  assert.equal(auth.searchParams.get("client_id"), "fixture-client");
  assert.equal(auth.searchParams.get("code_challenge_method"), "S256");
  assert.doesNotMatch(auth.href, /fixture-secret/);
  await remote.finish(attempt, auth.searchParams.get("state"), issuer, "fixture-code");
  assert.doesNotMatch(registry.get(id, 1).credential, /fixture-secret/);
  assert.equal(exchanges, 1);
});

test("GitHub setup stores the client privately and binds it to the original connection revision", async () => {
  const registry = new Registry(":memory:");
  const issuer = "https://github.com/login/oauth";
  const fixtureClientSecret = "fixture-secret-from-provider";
  let conversions = 0;
  const fetch = async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    if (request.url === githubMcpEndpoint && request.method === "GET") {
      return new Response(null, { status: 401 });
    }
    if (url.pathname.startsWith("/.well-known/oauth-protected-resource")) {
      return Response.json({ resource: githubMcpEndpoint, authorization_servers: [issuer] });
    }
    if (url.pathname === "/.well-known/oauth-authorization-server/login/oauth") {
      return Response.json({
        issuer, authorization_endpoint: issuer + "/authorize", token_endpoint: issuer + "/access_token",
        response_types_supported: ["code"], code_challenge_methods_supported: ["S256"],
      });
    }
    if (request.url === "https://api.github.com/app-manifests/fixture-code/conversions") {
      assert.equal(request.method, "POST");
      conversions++;
      return Response.json({
        slug: "private-fixture", client_id: "fixture-client-id", client_secret: fixtureClientSecret,
        pem: "unused-fixture-private-key",
      }, { status: 201 });
    }
    if (request.url === issuer + "/access_token") {
      const body = new URLSearchParams(await request.text());
      assert.equal(body.get("client_secret"), fixtureClientSecret);
      assert.ok(body.get("code_verifier"));
      return Response.json({ access_token: "fixture-scoped-access", token_type: "Bearer" });
    }
    assert.fail("Unexpected fixture URL");
  };
  const remote = new RemoteConnectors(registry, { origin, fetch, resolve: async () => "8.8.8.8" });
  const { id } = registry.add("GitHub", githubMcpEndpoint);
  const row = registry.get(id, 1);
  assert.equal((await remote.diagnose(row)).method, "github_manifest");
  const result = await remote.beginClientSetup(row, requester, { agent: adminAgent }, { access: "write" });
  const attempt = remote.pending(result.sign_in_url.split("/").at(-1));
  const manifest = remote.manifest(attempt);
  assert.equal(manifest.data.public, false);
  assert.equal(manifest.data.default_permissions.contents, "write");
  assert.equal(manifest.data.redirect_url, origin + "/oauth/callback");
  assert.equal(new URL(manifest.target).origin, "https://github.com");
  assert.doesNotMatch(JSON.stringify(result), /fixture-secret/);
  const state = attempt.registrationState;
  await remote.finishManifest(attempt, state, "fixture-code");
  await assert.rejects(remote.finishManifest(attempt, state, "fixture-code"), /Invalid or expired/);
  assert.equal(conversions, 1);
  assert.equal(remote.registeredClient(row).installUrl, "https://github.com/apps/private-fixture/installations/new");
  assert.doesNotMatch(JSON.stringify(registry.list()), /fixture-secret|unused-fixture-private-key/);
  const auth = await remote.authorize(attempt);
  assert.equal(auth.searchParams.get("client_id"), "fixture-client-id");
  assert.doesNotMatch(auth.href, /fixture-secret/);
  await remote.finish(attempt, auth.searchParams.get("state"), issuer, "fixture-oauth-code");
  assert.equal(registry.list()[0].status, "connected");
  assert.doesNotMatch(registry.get(id, 1).credential, /fixture-secret/);
  registry.edit(id, 1, { endpoint: replacement });
  assert.equal(registry.oauthClient(row), undefined);
  assert.equal(registry.get(id, 2).credential, null);
});

test("Casbin scopes permissions to the authenticated agent, user and connection", async () => {
  const registry = new Registry(":memory:", { gmail: "Company mail" });
  registry.migrateLegacyAccess({ gmail: ["main", "accounting"] });
  const operators = new Set([requester]);
  const access = new Access(registry, user => operators.has(user));
  const owner = { agent: "rack", user: requester };
  const recipient = { agent: "accounting", user: requester };
  const admin = { agent: adminAgent, user: requester };
  const wrongHuman = { agent: adminAgent, user: secondUser };
  const allow = async (actor, resource, action) => (await access.snapshot(actor)).can(resource, action);
  await assert.rejects(access.snapshot({ agent: "*", user: requester }), /authenticated/);

  assert.equal(await allow(owner, "gmail", "use"), false);
  assert.equal(await allow(recipient, "gmail", "use"), true);
  assert.equal(await allow(owner, "registry", "create"), true);
  assert.equal(await allow(owner, "agents", "agents"), false);
  assert.equal(await allow(admin, "agents", "agents"), true);
  assert.equal(await allow(wrongHuman, "agents", "agents"), false);
  operators.add(secondUser);
  assert.equal(await allow(wrongHuman, "agents", "agents"), true);
  operators.delete(secondUser);
  assert.equal(await allow(wrongHuman, "agents", "agents"), false);

  const { id } = registry.add("RACK fixture", original, owner.agent);
  assert.equal(await allow(owner, id, "use"), true);
  assert.equal(await allow(owner, id, "manage"), true);
  assert.equal(await allow(owner, id, "share"), false);
  assert.equal(await allow(recipient, id, "use"), false);
  assert.equal(await allow(admin, id, "use"), false);
  assert.equal(await allow(admin, id, "share"), true);
  assert.equal(await allow(wrongHuman, id, "share"), false);

  registry.credentials(registry.get(id, 1), { tokens: { access_token: "synthetic" } });
  registry.grant(id, recipient.agent);
  assert.equal(await allow(recipient, id, "use"), true);
  assert.equal(await allow(owner, id, "manage"), false);
  registry.edit(id, 1, { endpoint: replacement });
  assert.equal(await allow(recipient, id, "use"), false);
  assert.equal(await allow(owner, id, "use"), true);
  assert.equal(registry.get(id, 2).credential, null);

  registry.revoke(id, owner.agent);
  assert.equal(await allow(owner, id, "use"), false);
  assert.equal(await allow(owner, id, "manage"), false);
  assert.equal(await allow(admin, id, "manage"), true);
  registry.revoke("gmail", recipient.agent);
  registry.migrateLegacyAccess({ gmail: ["main", "accounting"] });
  assert.equal(await allow(recipient, "gmail", "use"), false);
});
