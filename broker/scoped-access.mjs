import { createHash, randomBytes } from "node:crypto";
import { adminAgent, agentIdPattern, discordIdPattern } from "./access.mjs";
import { BrowserPairing, isBrowserId } from "./browser-pairing.mjs";
import { ConnectionError } from "./registry.mjs";

const requestLifetime = 30 * 60_000;
const sessionLifetime = 7 * 24 * 60 * 60_000;
const repoPattern = /^[a-z0-9][a-z0-9-]{0,38}\/[a-z0-9_][a-z0-9_.-]{0,99}$/;
const sessionKey = value => createHash("sha256").update(value).digest("hex");
export const approvalCookie = "__Host-steward-approval";

export class ScopedAccess {
  constructor(registry, { origin, isAdmin, now = Date.now }) {
    this.registry = registry;
    this.db = registry.db;
    this.origin = origin;
    this.isAdmin = isAdmin;
    this.now = now;
    this.challenges = new Map();
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS scoped_integration_requests (
        id TEXT PRIMARY KEY, requester TEXT NOT NULL, requesting_agent TEXT NOT NULL,
        scope TEXT NOT NULL, expires INTEGER NOT NULL, approved INTEGER
      );
      CREATE TABLE IF NOT EXISTS scoped_integration_grants (
        agent TEXT NOT NULL, provider TEXT NOT NULL, connection TEXT NOT NULL,
        revision INTEGER NOT NULL, resource TEXT NOT NULL, permission TEXT NOT NULL,
        PRIMARY KEY(agent, provider, connection, resource)
      );
      CREATE TABLE IF NOT EXISTS integration_approval_sessions (
        digest TEXT PRIMARY KEY, user TEXT NOT NULL, expires INTEGER NOT NULL
      );
    `);
    if (!this.db.prepare("PRAGMA table_info(scoped_integration_grants)").all().some(field => field.name === "thread_permission")) {
      this.db.exec("ALTER TABLE scoped_integration_grants ADD COLUMN thread_permission TEXT");
    }
  }

  request(actor, scope) {
    if (!["read", "write"].includes(scope.permission) ||
        (scope.agent !== "*" && !agentIdPattern.test(scope.agent)) ||
        !["github", "discord"].includes(scope.provider) ||
        (scope.threadPermission !== undefined && (scope.provider !== "discord" || !["read","write"].includes(scope.threadPermission))) ||
        (scope.provider === "github" && (!repoPattern.test(scope.resource) || scope.resource.endsWith(".git"))) ||
        (scope.provider === "discord" && !discordIdPattern.test(scope.resource))) {
      throw new ConnectionError("Specify an exact agent, resource, and read or write permission.");
    }
    const now = this.now();
    this.db.prepare("DELETE FROM scoped_integration_requests WHERE expires<=? AND approved IS NULL").run(now);
    const pending = this.db.prepare("SELECT count(*) AS count FROM scoped_integration_requests WHERE approved IS NULL").get();
    if (pending.count >= 100) throw new ConnectionError("Too many pending access requests.");
    const id = randomBytes(32).toString("base64url");
    this.db.prepare("INSERT INTO scoped_integration_requests VALUES(?,?,?,?,?,NULL)")
      .run(id, actor.user, actor.agent, JSON.stringify(scope), now + requestLifetime);
    return { request: id, approval_url: `${this.origin}/connect/access/${id}`, expires_in_seconds: requestLifetime / 1000 };
  }

  load(id) {
    const row = this.db.prepare("SELECT * FROM scoped_integration_requests WHERE id=?").get(id);
    if (!row || !row.approved && row.expires <= this.now()) throw new ConnectionError("The access request is missing or expired.");
    return { ...row, scope: JSON.parse(row.scope) };
  }

  status(id, actor, administrator) {
    const row = this.load(id);
    if (!administrator && (row.requester !== actor.user || row.requesting_agent !== actor.agent)) {
      throw new ConnectionError("This request belongs to another conversation.");
    }
    if (!row.approved) return { status: "approval_required" };
    const { agent, provider, connection, revision, resource, permission, threadPermission } = row.scope;
    const active = this.list().some(grant => grant.agent === agent && grant.provider === provider &&
      grant.connection === connection && grant.revision === revision && grant.resource === resource &&
      grant.permission === permission && (grant.threadPermission ?? undefined) === threadPermission);
    return active ? { status: "approved", grant: row.scope, revision } : { status: "inactive" };
  }

  code(id, browser) {
    const row = this.load(id);
    if (row.approved) throw new ConnectionError("This access request was already approved.");
    for (const [key, item] of this.challenges) if (item.expires <= this.now()) this.challenges.delete(key);
    let entry = this.challenges.get(id);
    if (!entry) {
      entry = { pairing: new BrowserPairing(id), expires: row.expires };
      this.challenges.set(id, entry);
    }
    return entry.pairing.codeFor(browser);
  }

  async pair(id, actor, code) {
    if (actor.agent !== adminAgent || !await this.isAdmin(actor.user)) {
      throw new ConnectionError("Pair the browser from your authorised Integration Admin DM.");
    }
    if (this.load(id).approved) throw new ConnectionError("This access request was already approved.");
    const entry = this.challenges.get(id);
    if (!entry) throw new ConnectionError("Open the access request in your browser first.");
    entry.pairing.confirm(id, code);
    const digest = sessionKey(entry.pairing.approved);
    this.challenges.delete(id);
    const now = this.now();
    this.db.prepare("DELETE FROM integration_approval_sessions WHERE expires<=?").run(now);
    this.db.prepare("INSERT INTO integration_approval_sessions VALUES(?,?,?) ON CONFLICT(digest) DO UPDATE SET user=excluded.user,expires=excluded.expires")
      .run(digest, actor.user, now + sessionLifetime);
    return { browser_paired: true, session_seconds: sessionLifetime / 1000 };
  }

  async browserAdmin(browser) {
    if (!isBrowserId(browser)) return;
    const session = this.db.prepare("SELECT user FROM integration_approval_sessions WHERE digest=? AND expires>?")
      .get(sessionKey(browser), this.now());
    if (session && await this.isAdmin(session.user)) return session.user;
  }

  async approve(id, browser, verify) {
    const user = await this.browserAdmin(browser);
    if (!user) throw new ConnectionError("Sign in with an authorised administrator browser.");
    const { scope, approved } = this.load(id);
    if (approved) return scope;
    await verify(scope, user);
    if (!await this.browserAdmin(browser)) throw new ConnectionError("The approving administrator no longer has access.");
    this.db.exec("BEGIN IMMEDIATE");
    try {
      if (scope.provider === "github") this.registry.get(scope.connection, scope.revision);
      const changed = this.db.prepare("UPDATE scoped_integration_requests SET approved=? WHERE id=? AND approved IS NULL AND expires>?")
        .run(this.now(), id, this.now());
      if (!changed.changes) throw new ConnectionError("The request was already handled or expired.");
      this.db.prepare(`INSERT INTO scoped_integration_grants
        (agent,provider,connection,revision,resource,permission,thread_permission) VALUES(?,?,?,?,?,?,?)
        ON CONFLICT(agent,provider,connection,resource) DO UPDATE SET revision=excluded.revision,
          permission=excluded.permission,thread_permission=excluded.thread_permission`)
        .run(scope.agent, scope.provider, scope.connection, scope.revision, scope.resource, scope.permission, scope.threadPermission ?? null);
      this.db.exec("COMMIT");
      return scope;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  allows(agent, provider, connection, revision, resource, permission) {
    return Boolean(this.db.prepare(`SELECT 1 FROM scoped_integration_grants
      WHERE (agent=? OR agent='*' AND ?<>?) AND provider=? AND connection=? AND revision=? AND resource=?
      AND (permission='write' OR ?='read')`).get(agent, agent, adminAgent, provider, connection, revision, resource, permission));
  }

  hasDiscordThreadGrant(agent, guild) {
    return Boolean(this.db.prepare(`SELECT 1 FROM scoped_integration_grants
      WHERE (agent=? OR agent='*' AND ?<>?) AND provider='discord' AND connection=? AND revision=1
      AND thread_permission IS NOT NULL`).get(agent, agent, adminAgent, guild));
  }

  allowsDiscordThread(agent, guild, parent, permission) {
    return Boolean(this.db.prepare(`SELECT 1 FROM scoped_integration_grants
      WHERE (agent=? OR agent='*' AND ?<>?) AND provider='discord' AND connection=? AND revision=1 AND resource=?
      AND (thread_permission='write' OR thread_permission='read' AND ?='read')`).get(agent, agent, adminAgent, guild, parent, permission));
  }

  remove(scope) {
    return this.db.prepare(`DELETE FROM scoped_integration_grants
      WHERE agent=? AND provider=? AND connection=? AND revision=? AND resource=?`)
      .run(scope.agent, scope.provider, scope.connection, scope.revision, scope.resource).changes;
  }

  list() {
    return this.db.prepare(`SELECT agent,provider,connection,revision,resource,permission,thread_permission AS threadPermission FROM scoped_integration_grants
      WHERE provider='discord' OR EXISTS (SELECT 1 FROM connections
      WHERE id=connection AND connections.revision=scoped_integration_grants.revision AND deleted=0)
      ORDER BY provider,agent,resource`).all();
  }
}
