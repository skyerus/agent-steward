import { randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

export class ConnectionError extends Error {}

export function httpsEndpoint(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new ConnectionError("Provide a valid HTTPS endpoint.");
  }
  if (url.protocol !== "https:" || url.port || url.username || url.password || url.hash ||
      url.hostname.endsWith(".") || !url.hostname.includes(".")) {
    throw new ConnectionError("The endpoint must use a public HTTPS hostname on port 443.");
  }
  return url;
}

export class Registry {
  constructor(path, legacy = {}) {
    this.db = new DatabaseSync(path);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA secure_delete = ON;
      PRAGMA foreign_keys = ON;
      CREATE TABLE IF NOT EXISTS connections (
        id TEXT PRIMARY KEY,
        label TEXT NOT NULL,
        endpoint TEXT,
        revision INTEGER NOT NULL DEFAULT 1,
        legacy INTEGER NOT NULL DEFAULT 0,
        deleted INTEGER NOT NULL DEFAULT 0,
        credential TEXT,
        owner_agent TEXT
      );
      CREATE TABLE IF NOT EXISTS connection_grants (
        connection TEXT NOT NULL REFERENCES connections(id),
        agent TEXT NOT NULL,
        PRIMARY KEY (connection, agent)
      );
      CREATE TABLE IF NOT EXISTS connection_oauth_clients (
        connection TEXT PRIMARY KEY REFERENCES connections(id),
        revision INTEGER NOT NULL,
        endpoint TEXT NOT NULL,
        registration TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS registry_migrations (name TEXT PRIMARY KEY);
    `);
    if (!this.db.prepare("PRAGMA table_info(connections)").all().some(field => field.name === "owner_agent")) {
      this.db.exec("ALTER TABLE connections ADD COLUMN owner_agent TEXT");
    }
    const insert = this.db.prepare("INSERT OR IGNORE INTO connections(id,label,legacy) VALUES(?,?,1)");
    for (const [id, label] of Object.entries(legacy)) insert.run(id, label);
  }

  migrateLegacyAccess(seed) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const once = this.db.prepare("INSERT OR IGNORE INTO registry_migrations VALUES('scoped-access-v1')").run();
      if (once.changes === 1) {
        for (const [connection, agents] of Object.entries(seed)) {
          const row = this.db.prepare("SELECT legacy,deleted FROM connections WHERE id=?").get(connection);
          if (row?.legacy && !row.deleted) for (const agent of agents) this.grant(connection, agent);
        }
      }
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  accessRows() {
    return this.db.prepare(`
      SELECT id,owner_agent,
        EXISTS(SELECT 1 FROM connection_grants WHERE connection=id AND agent=owner_agent) AS owner_active,
        EXISTS(SELECT 1 FROM connection_grants WHERE connection=id AND agent IS NOT owner_agent) AS shared
      FROM connections WHERE deleted=0`
    ).all();
  }

  grants(id) {
    const query = `SELECT connection,agent FROM connection_grants JOIN connections
      ON connections.id=connection WHERE deleted=0`;
    return id === undefined
      ? this.db.prepare(query).all()
      : this.db.prepare(query + " AND connection=? ORDER BY agent").all(id);
  }

  grant(id, agent) {
    this.db.prepare("INSERT OR IGNORE INTO connection_grants VALUES(?,?)").run(id, agent);
  }

  revoke(id, agent) {
    this.db.prepare("DELETE FROM connection_grants WHERE connection=? AND agent=?").run(id, agent);
  }

  describe(row) {
    return {
      id: row.id, label: row.label, endpoint: row.endpoint, revision: row.revision,
      ownerAgent: row.owner_agent,
      status: row.legacy ? "connected" : row.credential ? "connected" : "sign_in_required",
    };
  }

  list() {
    return this.db.prepare("SELECT * FROM connections WHERE deleted=0 ORDER BY label,id").all()
      .map(row => this.describe(row));
  }

  get(id, revision) {
    const row = this.db.prepare("SELECT * FROM connections WHERE id=? AND deleted=0").get(id);
    if (!row) throw new ConnectionError("Connection does not exist.");
    if (revision !== undefined && row.revision !== revision) {
      throw new ConnectionError("The connection destination changed. List connections again.");
    }
    return row;
  }

  add(label, endpoint, owner = null, credential = null) {
    const id = randomUUID();
    const url = httpsEndpoint(endpoint).href;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("INSERT INTO connections(id,label,endpoint,owner_agent,credential) VALUES(?,?,?,?,?)")
        .run(id, label, url, owner, credential === null ? null : JSON.stringify(credential));
      if (owner) this.grant(id, owner);
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
    return this.describe(this.get(id));
  }

  edit(id, revision, { label, endpoint }) {
    const row = this.get(id, revision);
    const url = endpoint === undefined ? row.endpoint : httpsEndpoint(endpoint).href;
    if (url === row.endpoint) {
      this.db.prepare("UPDATE connections SET label=? WHERE id=? AND revision=?")
        .run(label ?? row.label, id, revision);
    } else {
      this.db.exec("BEGIN IMMEDIATE");
      try {
        this.db.prepare(`
          UPDATE connections SET label=?,endpoint=?,legacy=0,credential=NULL,revision=revision+1
          WHERE id=? AND revision=?`
        ).run(label ?? row.label, url, id, revision);
        this.db.prepare("DELETE FROM connection_grants WHERE connection=? AND agent IS NOT ?").run(id, row.owner_agent);
        this.db.prepare("DELETE FROM connection_oauth_clients WHERE connection=?").run(id);
        this.db.exec("COMMIT");
      } catch (error) {
        this.db.exec("ROLLBACK");
        throw error;
      }
    }
    return this.describe(this.get(id));
  }

  delete(id, revision) {
    this.get(id, revision);
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare(`
        UPDATE connections SET deleted=1,legacy=0,credential=NULL,endpoint=NULL,revision=revision+1
        WHERE id=? AND revision=?`
      ).run(id, revision);
      this.db.prepare("DELETE FROM connection_oauth_clients WHERE connection=?").run(id);
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  oauthClient(row) {
    const stored = this.db.prepare(`
      SELECT registration FROM connection_oauth_clients
      WHERE connection=? AND revision=? AND endpoint=?`
    ).get(row.id, row.revision, row.endpoint);
    return stored && JSON.parse(stored.registration);
  }

  registerOAuthClient(row, registration) {
    const saved = this.db.prepare(`
      INSERT INTO connection_oauth_clients(connection,revision,endpoint,registration)
      SELECT id,revision,endpoint,? FROM connections
      WHERE id=? AND revision=? AND endpoint=? AND deleted=0 AND legacy=0 AND credential IS NULL
      ON CONFLICT(connection) DO NOTHING`
    ).run(JSON.stringify(registration), row.id, row.revision, row.endpoint);
    if (!saved.changes) throw new ConnectionError("The connection changed or already has an OAuth client.");
  }

  credentials(row, data) {
    const result = this.db.prepare(`
      UPDATE connections SET credential=? WHERE id=? AND revision=? AND endpoint=? AND legacy=0 AND deleted=0`
    ).run(data === null ? null : JSON.stringify(data), row.id, row.revision, row.endpoint);
    if (result.changes !== 1) throw new ConnectionError("The connection changed. Start sign-in again.");
  }
}
