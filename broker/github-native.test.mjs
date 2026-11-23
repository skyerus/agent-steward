import assert from "node:assert/strict";
import { generateKeyPairSync, verify } from "node:crypto";
import { once } from "node:events";
import test from "node:test";
import { GithubGit, githubInstallation, installationTools, mintInstallationToken, verifyAccountInstallation } from "./github-native.mjs";
import { githubMcpEndpoint } from "./github-registration.mjs";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const installation = {
  kind: "github_installation", appId: "13", installationId: "29",
  repository: "example/rack", repositoryId: 40,
  privateKey: privateKey.export({ type: "pkcs8", format: "pem" }),
};
const row = { id: "test", endpoint: githubMcpEndpoint, revision: 1, credential: JSON.stringify(installation) };
const actor = { agent: "fixture", user: "123456789012345678" };

test("GitHub App tokens are signed by the broker and narrowed to one repository", async () => {
  assert.equal(githubInstallation({ ...row, endpoint: "https://example.com/mcp" }), undefined);
  const token = await mintInstallationToken(installation, {
    permissions: { contents: "read" },
    fetch: async (url, init) => {
      assert.equal(url, "https://api.github.com/app/installations/29/access_tokens");
      assert.deepEqual(JSON.parse(init.body), { repository_ids: [40], permissions: { contents: "read" } });
      const [header, payload, signature] = init.headers.Authorization.slice(7).split(".");
      assert.equal(JSON.parse(Buffer.from(payload, "base64url")).iss, "13");
      assert(verify("RSA-SHA256", Buffer.from(header + "." + payload), publicKey, Buffer.from(signature, "base64url")));
      return Response.json({ token: "ghs_fixture" }, { status: 201 });
    },
  });
  assert.equal(token, "ghs_fixture");
});

test("native Git reads require a live reviewed permit, original destination and current grant", async () => {
  let now = 0;
  let revoked = false;
  const transferCalls = [];
  const access = new GithubGit({
    now: () => now,
    checkGrant: async permit => {
      assert.equal(permit.actor, actor);
      if (revoked) throw new Error("Revoked");
      return row;
    },
    mint: async (value, options) => {
      assert.equal(value.repository, installation.repository);
      assert.deepEqual(options, { repository: "example/rack", permissions: { contents: "read" } });
      return "ghs_fixture";
    },
    transfer: async (request, endpoint, token, response) => {
      assert.equal(token, "ghs_fixture");
      transferCalls.push([request.method, endpoint.path]);
      response.writeHead(200).end("pack");
    },
  });
  assert.throws(() => access.open(row, actor, "example/other"), /authorized for that repository/);
  assert.throws(() => access.open({ ...row, credential: null }, actor, installation.repository), /authorized for that repository/);
  const lease = access.open(row, actor, installation.repository);
  assert(!JSON.stringify(lease).includes("ghs_fixture"));
  assert(!lease.remote.includes(lease.permit));
  const server = access.server().listen(0, "127.0.0.1");
  await once(server, "listening");
  const base = `http://127.0.0.1:${server.address().port}/__sable_git__/`;
  const read = "example/rack.git/info/refs?service=git-upload-pack";
  const send = (path, options) => fetch(base + path, { ...options, headers: { [lease.header]: lease.permit,
    ...(options?.headers ?? {}) } });
  try {
    assert.equal((await fetch(base + read)).status, 403);
    assert.equal((await send("example/rack.git/info/refs?service=git-receive-pack")).status, 403);
    assert.equal((await send("example/other.git/info/refs?service=git-upload-pack")).status, 403);
    assert.equal((await send("example/rack.git/git-upload-pack")).status, 403);
    assert.equal((await send(read)).status, 200);
    assert.equal((await send("example/rack.git/git-upload-pack", { method: "POST", body: "test",
      headers: { "Content-Type": "application/x-git-upload-pack-request" } })).status, 200);
    revoked = true;
    assert.equal((await send(read)).status, 403);
    revoked = false;
    now = 120_000;
    assert.equal((await send(read)).status, 403);
    assert.deepEqual(transferCalls, [
      ["GET", "/example/rack.git/info/refs?service=git-upload-pack"],
      ["POST", "/example/rack.git/git-upload-pack"],
    ]);
  } finally {
    server.close();
  }
});

test("unmodified Git can clone and pull through the reviewed transport", async () => {
  const { execFile, spawnSync } = await import("node:child_process");
  const { mkdtempSync, writeFileSync, readFileSync, mkdirSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { promisify } = await import("node:util");
  const run = promisify(execFile);
  const dir = mkdtempSync(join(tmpdir(), "sable-git-fixture-"));
  const git = (options, ...args) => run("git", ["-c", "user.name=Fixture", "-c",
    "user.email=git@example.invalid", "-c", "credential.helper=", ...args], options);
  const repo = join(dir, "source");
  const repos = join(dir, "remote", "example");
  const clone = join(dir, "checkout");
  mkdirSync(repo);
  mkdirSync(repos, { recursive: true });
  const access = new GithubGit({
    checkGrant: async () => row,
    mint: async () => "ghs_fixture",
    transfer: async (request, endpoint, token, response, input) => {
      assert.equal(token, "ghs_fixture");
      const url = new URL(endpoint.path, "https://example.invalid");
      const data = input ?? Buffer.alloc(0);
      const backend = spawnSync("git", ["http-backend"], {
        input: data, env: { ...process.env, GIT_PROJECT_ROOT: join(dir, "remote"),
          GIT_HTTP_EXPORT_ALL: "1", REMOTE_USER: "fixture", PATH_INFO: url.pathname, QUERY_STRING: url.search.slice(1),
          REQUEST_METHOD: request.method, CONTENT_TYPE: request.headers["content-type"] ?? "",
          CONTENT_LENGTH: String(data.length), HTTP_GIT_PROTOCOL: request.headers["git-protocol"] ?? "" },
      });
      assert.equal(backend.status, 0, backend.stderr.toString());
      const split = backend.stdout.indexOf("\r\n\r\n");
      assert(split > 0);
      response.writeHead(200, { "Content-Type": endpoint.type }).end(backend.stdout.subarray(split + 4));
    },
  });
  const server = access.server().listen(0, "127.0.0.1");
  try {
    await once(server, "listening");
    await git({ cwd: repo }, "init", "-b", "main");
    writeFileSync(join(repo, "fixture.txt"), "first\n");
    await git({ cwd: repo }, "add", ".");
    await git({ cwd: repo }, "commit", "-m", "initial");
    const upstream = join(repos, "rack.git");
    await git({ cwd: dir }, "clone", "--bare", repo, upstream);
    const remote = `http://127.0.0.1:${server.address().port}/__sable_git__/example/rack.git`;
    const config = permit => ({ cwd: dir, env: { ...process.env,
      SABLE_FIXTURE_GIT_HEADER: `${permit.header}: ${permit.permit}` } });
    await git(config(access.open(row, actor, installation.repository)),
      "--config-env=http.extraHeader=SABLE_FIXTURE_GIT_HEADER", "clone", remote, clone);
    assert.equal(readFileSync(join(clone, "fixture.txt"), "utf8"), "first\n");
    writeFileSync(join(repo, "fixture.txt"), "second\n");
    await git({ cwd: repo }, "commit", "-am", "second");
    await git({ cwd: repo }, "push", upstream, "main");
    const verified = await git({ cwd: repo }, "rev-parse", "HEAD");
    const next = config(access.open(row, actor, installation.repository));
    await git({ ...next, cwd: clone }, "--config-env=http.extraHeader=SABLE_FIXTURE_GIT_HEADER", "pull", "--ff-only");
    assert.equal((await git({ cwd: clone }, "rev-parse", "HEAD")).stdout.trim(), verified.stdout.trim());
    writeFileSync(join(clone, "local-fix.txt"), "locally verified\n");
    await git({ cwd: clone }, "add", "local-fix.txt");
    await git({ cwd: clone }, "commit", "-m", "candidate update");
    const target = (await git({ cwd: clone }, "rev-parse", "HEAD")).stdout.trim();
    const changes = { oldCommit: "0".repeat(40), newCommit: target, ref: "refs/heads/reviewed-fix" };
    const push = lease => ({ ...config(lease), cwd: clone });
    const denied = access.open(row, actor, installation.repository, changes);
    await assert.rejects(git(push(denied), "--config-env=http.extraHeader=SABLE_FIXTURE_GIT_HEADER",
      "push", "origin", "HEAD:refs/heads/wrong-fix"));
    assert.equal((await git({ cwd: upstream }, "branch", "--list", "wrong-fix")).stdout.trim(), "");
    const admitted = access.open(row, actor, installation.repository, changes);
    await git(push(admitted), "--config-env=http.extraHeader=SABLE_FIXTURE_GIT_HEADER",
      "push", "origin", "HEAD:refs/heads/reviewed-fix");
    assert.equal((await git({ cwd: upstream }, "rev-parse", changes.ref)).stdout.trim(), target);
    const persisted = readFileSync(join(clone, ".git", "config"), "utf8");
    assert(persisted.includes(remote));
    assert(!persisted.includes("ghs_fixture") && !persisted.includes("X-Sable-Git-Permit"));
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the official MCP route uses the same app installation without returning its credential", async () => {
  let calls = 0;
  const fakeGitHub = async (input, options) => {
    const request = new Request(input, options);
    if (request.url === "https://api.github.com/app/installations/29/access_tokens") {
      assert.deepEqual(await request.json(), { repository_ids: [40] });
      return Response.json({ token: "ghs_fixture" }, { status: 201 });
    }
    assert.equal(request.url, githubMcpEndpoint);
    assert.equal(request.headers.get("authorization"), "Bearer ghs_fixture");
    const message = await request.json();
    if (message.method === "notifications/initialized") return new Response(null, { status: 202 });
    const success = {
      initialize: { serverInfo: { name: "Fixture", version: "1" }, capabilities: { tools: {} },
        protocolVersion: message.params?.protocolVersion },
      "tools/call": { content: [{ type: "text", text: "RACK fixture content" }] },
    };
    if (message.method === "tools/call") {
      calls += 1;
      assert.equal(message.params.name, "get_file_contents");
      assert.deepEqual(message.params.arguments, { owner: "example", repo: "rack", path: "README.md" });
    }
    return Response.json({ jsonrpc: "2.0", id: message.id, result: success[message.method] });
  };
  const response = await installationTools(row, installation, { name: "get_file_contents",
    arguments: { owner: "example", repo: "rack", path: "README.md" } }, fakeGitHub);
  assert.equal(calls, 1);
  assert.equal(response.content[0].text, "RACK fixture content");
});

test("an account-wide installation can use different owned repos and narrows each Git operation", async () => {
  const account = { ...installation, repository: undefined, repositoryId: undefined, account: "example" };
  const accountRow = { ...row, credential: JSON.stringify(account) };
  const access = new GithubGit({ checkGrant: async () => accountRow });
  assert(access.open(accountRow, actor, "example/alpha").remote.endsWith("/example/alpha.git"));
  assert(access.open(accountRow, actor, "example/beta").remote.endsWith("/example/beta.git"));
  assert.throws(() => access.open(accountRow, actor, "another/alpha"), /authorized for that repository/);
  await assert.rejects(mintInstallationToken(account, { repository: "another/alpha" }), /outside this GitHub installation/);
  const permissions = { contents: "write", issues: "write", pull_requests: "write" };
  const state = { account: { type: "User", login: "Example" }, repository_selection: "all", permissions };
  await verifyAccountInstallation(account, async url => {
    assert.equal(url, "https://api.github.com/app/installations/29");
    return Response.json(state);
  });
  await assert.rejects(verifyAccountInstallation(account, async () => Response.json({ ...state,
    repository_selection: "selected" })), /all repositories/);
  await mintInstallationToken(account, { repository: "example/beta", permissions: { contents: "write" },
    fetch: async (_, init) => {
      assert.deepEqual(JSON.parse(init.body), { repositories: ["beta"], permissions: { contents: "write" } });
      return Response.json({ token: "ghs_fixture" }, { status: 201 });
    },
  });
});
