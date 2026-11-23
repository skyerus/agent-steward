import { createPrivateKey, randomBytes, sign } from "node:crypto";
import http from "node:http";
import https from "node:https";
import { pipeline } from "node:stream/promises";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { githubMcpEndpoint } from "./github-registration.mjs";
import { ConnectionError } from "./registry.mjs";
import { publicFetch, resolvePublic } from "./public-fetch.mjs";

const githubApi = "https://api.github.com";
const gitPrefix = "/__sable_git__/";
const workerRelay = "https://127.0.0.1:17759";
const timeout = { timeout: 30_000 };
const repositoryPattern = /^[a-z\d][a-z\d-]{0,38}\/[a-z\d_][a-z\d_.-]{0,99}$/;
const gitRead = { contents: "read" };
const gitWrite = { contents: "write" };
const accountPattern = /^[a-z\d][a-z\d-]{0,38}$/;
const githubPermissions = ["contents", "issues", "pull_requests"];
const commitPattern = /^[0-9a-f]{40}$/;
const zeroCommit = "0".repeat(40);

function validRepository(repository) {
  return typeof repository === "string" && repositoryPattern.test(repository) && !repository.endsWith(".git");
}

function allowsRepository(installation, repository) {
  return Boolean(installation && validRepository(repository) &&
    (installation.repository === repository || installation.account === repository.split("/")[0]));
}

function validatePush(push) {
  const parts = typeof push.ref === "string" ? push.ref.split("/") : [];
  if (parts.length < 3 || parts[0] !== "refs" || !["heads", "tags"].includes(parts[1]) ||
      push.ref.length > 255 || push.ref.includes("..") || push.ref.endsWith(".") ||
      parts.slice(2).some(part => !/^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(part) || part.endsWith(".lock")) ||
      !commitPattern.test(push.oldCommit) || !commitPattern.test(push.newCommit) || push.newCommit === zeroCommit) {
    throw new ConnectionError("Give one branch or tag and its exact before and after commit IDs.");
  }
}
const agentIdentity = { name: "sable-integration-broker", version: "1.0.0" };

export function githubInstallation(row) {
  if (row.endpoint !== githubMcpEndpoint || !row.credential) return undefined;
  const value = JSON.parse(row.credential);
  if (value.kind !== "github_installation") return undefined;
  const accountGrant = typeof value.account === "string" && accountPattern.test(value.account) &&
    value.repository === undefined && value.repositoryId === undefined &&
    (value.ownerType === undefined || ["User", "Organization"].includes(value.ownerType)) &&
    (value.access === undefined || ["read", "write"].includes(value.access));
  const repositoryGrant = value.account === undefined && validRepository(value.repository) &&
    Number.isSafeInteger(value.repositoryId) && value.repositoryId > 0;
  if (!/^\d+$/.test(value.appId) || !/^\d+$/.test(value.installationId) ||
      accountGrant === repositoryGrant || typeof value.privateKey !== "string") {
    throw new ConnectionError("This GitHub App installation needs to be connected again.");
  }
  return value;
}

const encode = value => Buffer.from(JSON.stringify(value)).toString("base64url");

function appAuthorization(installation) {
  const now = Math.floor(Date.now() / 1000);
  const data = encode({ alg: "RS256", typ: "JWT" }) + "." +
    encode({ iss: installation.appId, iat: now - 60, exp: now + 480 });
  const jwt = data + "." + sign("RSA-SHA256", Buffer.from(data), createPrivateKey(installation.privateKey)).toString("base64url");
  return { Authorization: `Bearer ${jwt}`, Accept: "application/vnd.github+json",
    "Content-Type": "application/json", "User-Agent": agentIdentity.name };
}

function requireAccountGrant(installation, grant) {
  const mode = installation.access ?? "write";
  if (grant.account?.login?.toLowerCase() !== installation.account ||
      grant.account?.type !== (installation.ownerType ?? "User") ||
      grant.repository_selection !== "all" || grant.suspended_at ||
      githubPermissions.some(permission => grant.permissions?.[permission] !== mode)) {
    throw new ConnectionError(`Install the app on all repositories of ${installation.account} with the requested ${mode} permissions.`);
  }
}

export async function discoverAccountInstallation({ account, organization, access }, app, fetch = publicFetch) {
  if (typeof account !== "string" || !accountPattern.test(account) ||
      !["read", "write"].includes(access) || organization && organization !== account ||
      !/^\d+$/.test(app?.appId) || typeof app?.privateKey !== "string") {
    throw new ConnectionError("Invalid GitHub App setup.");
  }
  const ownerType = organization ? "Organization" : "User";
  const installation = { kind: "github_installation", account, ownerType, access,
    appId: app.appId, privateKey: app.privateKey };
  let headers;
  try {
    headers = appAuthorization(installation);
  } catch {
    throw new ConnectionError("GitHub returned an invalid app signing key.");
  }
  const endpoint = organization ? "orgs" : "users";
  const response = await fetch(`${githubApi}/${endpoint}/${account}/installation`, { headers });
  if (!response.ok) {
    await response.body?.cancel();
    throw new ConnectionError(`GitHub has not verified the installation on ${account}. Complete installation and retry.`);
  }
  const grant = await response.json();
  if (!Number.isSafeInteger(grant.id) || grant.id <= 0 || String(grant.app_id) !== app.appId) {
    throw new ConnectionError("GitHub returned a different application installation.");
  }
  requireAccountGrant(installation, grant);
  return { ...installation, installationId: String(grant.id) };
}

export async function verifyAccountInstallation(installation, fetch = publicFetch) {
  const response = await fetch(`${githubApi}/app/installations/${installation.installationId}`, {
    headers: appAuthorization(installation),
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw new ConnectionError("GitHub could not verify the App installation.");
  }
  const grant = await response.json();
  requireAccountGrant(installation, grant);
}

export async function mintInstallationToken(installation, { repository, permissions, fetch = publicFetch } = {}) {
  if (repository && !allowsRepository(installation, repository)) {
    throw new ConnectionError("Repository is outside this GitHub installation.");
  }
  if (installation.access === "read") {
    if (Object.values(permissions ?? {}).some(value => value === "write")) {
      throw new ConnectionError("This GitHub connection is read-only.");
    }
    permissions ??= Object.fromEntries(githubPermissions.map(permission => [permission, "read"]));
  }
  const target = installation.repository ? { repository_ids: [installation.repositoryId] }
    : repository ? { repositories: [repository.split("/")[1]] } : {};
  const response = await fetch(`${githubApi}/app/installations/${installation.installationId}/access_tokens`, {
    method: "POST", headers: appAuthorization(installation),
    body: JSON.stringify({ ...target, ...(permissions && { permissions }) }),
  });
  if (response.status !== 201) {
    await response.body?.cancel();
    throw new ConnectionError("GitHub could not authorize this App installation for the repository. Check the app's repository access.");
  }
  const result = await response.json();
  if (!/^ghs_[A-Za-z0-9_.-]+$/.test(result.token ?? "")) {
    throw new ConnectionError("GitHub did not return an installation credential.");
  }
  return result.token;
}

export async function installationTools(row, installation, call, fetch = publicFetch) {
  const { owner, repo } = call?.arguments ?? {};
  const repository = typeof owner === "string" && typeof repo === "string"
    ? `${owner}/${repo}`.toLowerCase() : undefined;
  const token = await mintInstallationToken(installation, { repository, fetch });
  const client = new Client(agentIdentity);
  const transport = new StreamableHTTPClientTransport(new URL(row.endpoint), {
    requestInit: { headers: { Authorization: `Bearer ${token}` }, redirect: "error" },
    reconnectionOptions: { maxRetries: 0 },
    fetch: (input, init) => {
      const request = new Request(input, init);
      if (request.url !== githubMcpEndpoint) throw new ConnectionError("GitHub MCP request was outside the registered endpoint.");
      return fetch(request);
    },
  });
  try {
    await client.connect(transport, timeout);
    const output = call ? await client.callTool(call, undefined, timeout) : await client.listTools({}, timeout);
    if (JSON.stringify(output).includes(token)) throw new Error("Unexpected credential in GitHub response.");
    return output;
  } catch {
    throw new ConnectionError("GitHub could not complete this MCP request with the repo-scoped App installation.");
  } finally {
    await client.close().catch(() => {});
  }
}

function gitEndpoint(method, url, permit) {
  const service = permit.push ? "git-receive-pack" : "git-upload-pack";
  const repoPath = `${permit.repository}.git`;
  const refs = `${repoPath}/info/refs?service=${service}`;
  if (method === "GET" && url === gitPrefix + refs) {
    return { path: "/" + refs, type: `application/x-${service}-advertisement` };
  }
  const rpc = `${repoPath}/${service}`;
  if (method === "POST" && url === gitPrefix + rpc) {
    return { path: "/" + rpc, type: `application/x-${service}-result`, requestType: `application/x-${service}-request` };
  }
}

function pushMatches(body, push) {
  const header = body.subarray(0, 4).toString("latin1");
  if (!/^[0-9a-f]{4}$/.test(header)) return false;
  const length = Number.parseInt(header, 16);
  if (length < 5 || body.length < length + 8 || body.subarray(length, length + 8).toString("latin1") !== "0000PACK") return false;
  const [command, capabilities, ...extra] = body.subarray(4, length).toString("latin1").split("\0");
  return extra.length === 0 && typeof capabilities === "string" &&
    !/(?:^|\s)push-options(?=\s|$)/.test(capabilities) &&
    command === `${push.oldCommit} ${push.newCommit} ${push.ref}`;
}

async function gitRequestBody(request, endpoint, push) {
  if (request.method !== "POST") return undefined;
  if (request.headers["content-type"] !== endpoint.requestType) throw new ConnectionError("Invalid Git request type.");
  const maxBytes = push ? 32 * 1024 * 1024 : 1024 * 1024;
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxBytes) throw new ConnectionError("Git request exceeds the broker transfer limit.");
    chunks.push(chunk);
  }
  const body = Buffer.concat(chunks);
  if (!body.length || push && !pushMatches(body, push)) {
    throw new ConnectionError("The Git operation differs from the reviewed branch and commit IDs.");
  }
  return body;
}

async function fetchGit(request, destination, token, response, input) {
  const url = new URL(destination.path, "https://github.com");
  const ip = await resolvePublic(url);
  const headers = {
    Authorization: "Basic " + Buffer.from("x-access-token:" + token).toString("base64"),
    "User-Agent": agentIdentity.name, "Accept-Encoding": "identity",
  };
  if (request.headers["git-protocol"] === "version=2") headers["Git-Protocol"] = "version=2";
  if (input) {
    headers["Content-Type"] = destination.requestType;
    headers["Content-Length"] = String(input.length);
  }
  const signal = AbortSignal.timeout(240_000);
  const upstream = await new Promise((resolve, reject) => {
    const outbound = https.request(url, { method: request.method, headers, agent: false, signal,
      lookup: (_hostname, options, done) => options.all
        ? done(null, [{ address: ip, family: 4 }]) : done(null, ip, 4),
    }, resolve);
    outbound.on("error", reject);
    outbound.end(input);
  });
  if (upstream.statusCode !== 200 || upstream.headers["content-type"]?.split(";")[0] !== destination.type) {
    upstream.destroy();
    response.writeHead(upstream.statusCode === 401 || upstream.statusCode === 403 ? 403 : 502).end();
    return;
  }
  response.writeHead(200, { "Content-Type": destination.type, "Cache-Control": "no-store" });
  await pipeline(upstream, response);
}

export class GithubGit {
  constructor({ checkGrant, mint = mintInstallationToken, transfer = fetchGit, now = Date.now }) {
    this.checkGrant = checkGrant;
    this.mint = mint;
    this.transfer = transfer;
    this.now = now;
    this.permits = new Map();
    this.activePushes = 0;
  }

  open(row, actor, repository, push) {
    const installation = githubInstallation(row);
    if (push) {
      validatePush(push);
      if (installation?.access === "read") throw new ConnectionError("This GitHub connection is read-only.");
    }
    if (!allowsRepository(installation, repository)) {
      throw new ConnectionError("This connection has no GitHub App installation authorized for that repository.");
    }
    const now = this.now();
    for (const [key, item] of this.permits) if (item.expires <= now) this.permits.delete(key);
    if (this.permits.size >= 128) throw new ConnectionError("Too many active Git operations. Try again shortly.");
    const permit = randomBytes(32).toString("base64url");
    this.permits.set(permit, { id: row.id, revision: row.revision, actor, repository, push,
      expires: now + 120_000, remaining: push ? 2 : 8 });
    return { remote: workerRelay + gitPrefix + repository + ".git", permit,
      expires_in_seconds: 120, header: "X-Sable-Git-Permit",
      instructions: "Use command-scoped Git config and /etc/sable-codex/relay.crt as the TLS CA. Keep the permit out of persisted Git config, remote URLs, and chat." };
  }

  server() {
    return http.createServer(async (request, response) => {
      const presented = request.headers["x-sable-git-permit"];
      const permit = typeof presented === "string" && /^[\w-]{43}$/.test(presented) ? this.permits.get(presented) : undefined;
      const endpoint = permit && gitEndpoint(request.method, request.url, permit);
      if (!endpoint || permit.expires <= this.now() || permit.remaining <= 0 ||
          permit.push && request.method === "POST" && permit.pushStarted) {
        response.writeHead(403).end();
        return;
      }
      const push = permit.push && request.method === "POST";
      if (push && this.activePushes >= 2) {
        response.writeHead(503).end();
        return;
      }
      permit.remaining -= 1;
      if (push) {
        permit.pushStarted = true;
        this.activePushes += 1;
      }
      request.setTimeout(60_000, () => request.destroy());
      try {
        const row = await this.checkGrant(permit);
        const installation = githubInstallation(row);
        if (!allowsRepository(installation, permit.repository)) throw new ConnectionError("Repository grant changed.");
        const body = await gitRequestBody(request, endpoint, permit.push);
        const token = await this.mint(installation, { repository: permit.repository,
          permissions: permit.push ? gitWrite : gitRead });
        const current = await this.checkGrant(permit);
        if (current.credential !== row.credential || permit.expires <= this.now()) {
          throw new ConnectionError("Repository grant changed.");
        }
        await this.transfer(request, endpoint, token, response, body);
        console.info(JSON.stringify({ event: permit.push ? "reviewed-git-push" : "reviewed-git-read", agent: permit.actor.agent,
          repository: permit.repository, ...(permit.push && { ref: permit.push.ref }), status: response.statusCode }));
      } catch {
        if (response.headersSent) response.destroy();
        else response.writeHead(403).end();
      } finally {
        if (push) this.activePushes -= 1;
      }
    });
  }
}
