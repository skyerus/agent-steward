import { readFileSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import process from "node:process";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { ConnectionError, Registry } from "./registry.mjs";
import { RemoteConnectors } from "./remote.mjs";
import { isBrowserId, newBrowserId, pairingCookie } from "./browser-pairing.mjs";
import { Access, actorField, adminAgent, agentIdPattern, requireAccess, validActor } from "./access.mjs";
import { unixRequest } from "./unix-request.mjs";
import { githubMcpEndpoint } from "./github-registration.mjs";
import { githubInstallation, GithubGit, installationTools } from "./github-native.mjs";
import { ScopedAccess, approvalCookie, mcpToolPattern } from "./scoped-access.mjs";

const knownLegacy = Object.freeze({
  gmail: "Gmail",
  "freeagent-sable": "FreeAgent",
  netlify: "Netlify",
  "supabase-cms": "Supabase CMS",
});
const legacy = Object.fromEntries((process.env.SABLE_LEGACY_CONNECTIONS ?? "").split(",")
  .filter(name => Object.hasOwn(knownLegacy, name))
  .map(name => [name, knownLegacy[name]]));
const identity = { name: "sable-integration-broker", version: "1.0.0" };
const legacySocketDirectory = process.env.SABLE_LEGACY_SOCKET_DIR ?? "/run";
const registry = new Registry(process.argv[2], legacy);
registry.migrateLegacyAccess(JSON.parse(process.env.SABLE_LEGACY_GRANTS ?? "{}"));
const credentialDir = process.env.CREDENTIALS_DIRECTORY;
const clients = credentialDir ? JSON.parse(readFileSync(join(credentialDir, "oauth-clients.json"), "utf8")) : [];
const remote = new RemoteConnectors(registry, { origin: process.env.SABLE_SIGN_IN_ORIGIN, clients });
const signInHost = new URL(remote.origin).host;
const scopedAccess = new ScopedAccess(registry, {
  origin: remote.origin,
  isAdmin: user => provision("discord_is_admin", {}, user),
});
const access = new Access(registry, user => provision("discord_is_admin", {}, user), row => scopedAccess.sharedConnection(row));
const queues = new Map();
const githubGitEnabled = process.env.SABLE_NATIVE_GIT === "1";
const gitAccess = new GithubGit({
  checkGrant: async ({ actor, id, revision, repository, push }) => {
    await requireGit(actor, id, revision, repository, push ? "write" : "read");
    return registry.get(id, revision);
  },
});

function serialized(id, work) {
  const previous = queues.get(id) ?? Promise.resolve();
  const next = previous.then(work, work);
  queues.set(id, next);
  return next.finally(() => {
    if (queues.get(id) === next) queues.delete(id);
  });
}

const id = { type: "string", minLength: 1, maxLength: 64, description: "Connection ID from list_connections." };
const revision = { type: "integer", minimum: 1, description: "Destination revision from list_connections." };
const label = { type: "string", minLength: 1, maxLength: 100 };
const endpoint = { type: "string", maxLength: 2048, description: "Public HTTPS OAuth MCP endpoint." };
const name = { type: "string", minLength: 1, maxLength: 100 };
const agentId = { type: "string", minLength: 1, maxLength: 63, pattern: agentIdPattern.source };
const channelId = { type: "string", minLength: 16, maxLength: 22, pattern: "^[0-9]{16,22}$" };
const discordUsers = { type: "array", maxItems: 100, items: name };
const instructions = { type: "string", minLength: 1, maxLength: 12_000 };
const requestId = { type: "string", minLength: 32, maxLength: 32, pattern: "^[0-9a-f]{32}$" };
const callArguments = { type: "object" };
const accessRequest = { type: "string", minLength: 43, maxLength: 43, pattern: "^[A-Za-z0-9_-]{43}$" };
const permission = { type: "string", maxLength: 5, pattern: "^(read|write)$" };
const provider = { type: "string", maxLength: 7, pattern: "^(github|discord|mcp)$" };
const resource = { type: "string", minLength: 1, maxLength: 141 };
const audience = { type: "string", maxLength: 14, pattern: "^(agent|all-downstream)$" };

function tool(name, description, properties = {}, required = Object.keys(properties)) {
  return { name, description, inputSchema: { type: "object", properties, required, additionalProperties: false } };
}

const management = [
  tool("list_connections", "Read current integration names, IDs, destination revisions, and sign-in status."),
  tool("diagnose_connection", "Read safe sign-in diagnostics for an accessible connection. Discover its supported onboarding method or set verify to check a connected MCP server without running a provider tool.", {
    id, revision, verify: { type: "boolean" },
  }, ["id", "revision"]),
  tool("add_connection", "Create a disconnected integration for yourself. Integration Admin can optionally set the owning agent.", { label, endpoint, agentId }, ["label", "endpoint"]),
  tool("edit_connection", "Rename an integration or replace its destination. Replacing the destination invalidates its credential and requires a fresh sign-in.", { id, revision, label, endpoint }, ["id", "revision"]),
  tool("delete_connection", "Remove an integration and prevent its credential from being used by the broker.", { id, revision }),
  tool("begin_sign_in", "Create a one-time browser sign-in link for a disconnected integration. Give the link to the requester.", { id, revision }),
  tool("begin_oauth_client_setup", "Start paired browser setup for a connection you manage that needs a registered OAuth client. The broker handles all credentials. For GitHub, access sets repository permissions and organization selects the app owner if specified.", {
    id, revision,
    organization: { type: "string", maxLength: 39, pattern: "^[a-zA-Z0-9][a-zA-Z0-9-]*$" },
    access: { type: "string", maxLength: 5, pattern: "^(read|write)$" },
  }, ["id", "revision"]),
  tool("confirm_sign_in", "Pair the requester's browser using the eight-digit code the requester just sent in Discord.", { id, revision,
    code: { type: "string", minLength: 8, maxLength: 8, pattern: "^[0-9]{8}$" } }),
  tool("list_connection_tools", "Read authorized tool names and schemas on a connected MCP server. Integration Admin can inspect the full catalog to prepare scoped access.", { id, revision }),
  tool("call_connection_tool", "Run the named tool with these arguments on this integration and destination revision.", { id, revision, name, arguments: callArguments }),
  ...(githubGitEnabled ? [
    tool("begin_github_installation",
      "Integration Admin only. Start paired registration of a private GitHub App for native Git and GitHub MCP. The account owner installs it on all repositories of the named account and verifies in the paired browser. Registration keeps the signing key in the broker. Use only the explicitly requested read or write permissions.",
      { id, revision, account: { type: "string", maxLength: 39, pattern: "^[a-z0-9][a-z0-9-]*$" },
        access: { type: "string", maxLength: 5, pattern: "^(read|write)$" },
        organization: { type: "boolean" } }, ["id", "revision", "account", "access"]),
    tool("authorize_git_read",
      "Clone or fetch a GitHub repository through native Git. Returns an expiring Git permit and remote for the approved repository.",
      { id, revision, repository: { type: "string", minLength: 3, maxLength: 140 } }),
    tool("authorize_git_push",
      "Push one explicit Git branch or tag update. Review the exact ref and before and after commit IDs. A push may replace history. Forty zeroes as oldCommit means creating a new ref.",
      { id, revision, repository: { type: "string", minLength: 3, maxLength: 140 },
        ref: { type: "string", minLength: 11, maxLength: 255 },
        oldCommit: { type: "string", maxLength: 40, pattern: "^[0-9a-f]{40}$" },
        newCommit: { type: "string", maxLength: 40, pattern: "^[0-9a-f]{40}$" } }),
  ] : []),
  tool("request_integration_access",
    "Request browser approval for the current agent. GitHub resource is owner/repo. Discord resource is a channel name, mention or ID. Both take read or write permission. For any MCP connection, pass its exact label or ID as resource and either exact tool names from the catalog or allTools for explicitly requested whole-connection access. An administrator may target another agent or all-downstream. Return the link and check its status before proceeding.",
    { provider, resource, permission, agentId, audience, threadPermission: permission,
      tools: { type: "array", minItems: 1, maxItems: 30, items: { ...name, pattern: mcpToolPattern.source } },
      allTools: { type: "boolean" } }, ["provider","resource"]),
  tool("integration_access_status", "Check the status of a scoped integration access request.", { request: accessRequest }),
  tool("pair_approval_browser", "Integration Admin only. Pair the approval browser with the eight-digit code sent in the current authorised DM.",
    { request: accessRequest, code: { type: "string", minLength: 8, maxLength: 8, pattern: "^[0-9]{8}$" } }),
  tool("list_scoped_integration_access", "Integration Admin only. List persistent resource grants."),
  tool("revoke_scoped_integration_access", "Integration Admin only. Revoke an exact resource grant. Use * for the all-downstream rule.",
    { provider, resource, id, revision, subject: { type: "string", minLength: 1, maxLength: 63 } }),
  tool("discord_read_messages", "Read recent messages from an approved Discord channel or exact thread.",
    { channel: channelId, guild: channelId, limit: { type: "integer", minimum: 1, maximum: 25 } }, ["channel","guild"]),
  tool("discord_post_message", "Post or reply in an approved Discord channel or exact thread. Mentions are disabled.",
    { channel: channelId, guild: channelId, content: { type: "string", minLength: 1, maxLength: 2000 }, replyTo: channelId },
    ["channel","guild","content"]),
  tool("list_connection_access", "Integration Admin only. See which agents can use a connection.", { id, revision }),
  tool("grant_connection_access", "Integration Admin only. Share one connection with another agent.", { id, revision, agentId }),
  tool("revoke_connection_access", "Integration Admin only. Remove an agent's access to one connection.", { id, revision, agentId }),
  tool("list_managed_agents", "Integration Admin only. Read the configured agents and their Discord bindings."),
  tool("create_agent", "Integration Admin only. Create a downstream agent with an empty, isolated workspace. Approved standing grants apply automatically.", { agentId, name }),
  tool("rename_agent", "Integration Admin only. Change a downstream agent's display name.", { agentId, name }),
  tool("set_agent_instructions", "Integration Admin only. Replace a downstream agent's AGENTS.md with its approved role and operating instructions.", { agentId, instructions }),
  tool("deploy_agent_connector",
    "Integration Admin only. Install or replace one reviewed connector source file in a downstream agent's native workspace. It runs only as an ordinary workspace program and all integration calls still go through the broker. Supply source code without credentials.",
    { agentId, filename: { type: "string", maxLength: 85, pattern: "^[a-z0-9][a-z0-9_-]{0,62}\\.(py|mjs|sh)$" },
      source: { type: "string", minLength: 1, maxLength: 12000 } }),
  tool("bind_agent_channel", "Integration Admin only. Route an existing approved private Discord channel to a downstream agent.", { agentId, channelId }),
  tool("prepare_discord_server", "Integration Admin only. Prepare an official Discord install link for a named server or server ID. Once installation is verified, create private channels for the specified existing agents and allow only the designated users. The requester is always included.", {
    server: name,
    agentIds: { type: "array", minItems: 1, maxItems: 20, items: agentId },
    allowedUsers: { type: "array", maxItems: 24, items: channelId },
    voice: { type: "boolean" },
  }, ["server", "agentIds"]),
  tool("discord_server_setup_status", "Integration Admin only. Read current progress and the Discord install link for a server setup request.", { requestId }),
  tool("cancel_discord_server_setup", "Integration Admin only. Stop a pending Discord server setup before further provisioning.", { requestId }),
  tool("list_discord_access", "Integration Admin only. List who can message the bot in each configured text channel and which agents users can DM."),
  tool("update_discord_channel_access", "Integration Admin only. Change who the bot accepts messages from in an existing text channel. Use its name, ID or mention. Add or remove named users, IDs or mentions, or give the complete allowlist with onlyUsers. An empty onlyUsers disables the bot in the channel. Discord room visibility is managed separately.", {
    channel: name, addUsers: discordUsers, removeUsers: discordUsers, onlyUsers: discordUsers,
  }, ["channel"]),
  tool("update_discord_dm_access", "Integration Admin only. Assign a Discord user to a specific agent in DMs, or revoke their DM access. Routing a user to integration-admin gives them administrator privileges.", {
    user: name, agentId, revoke: { type: "boolean" },
  }, ["user"]),
];
const byName = new Map(management.map(value => [value.name, value]));

class ToolInputError extends ConnectionError {}

function validInput(value, schema) {
  switch (schema.type) {
    case "string":
      return typeof value === "string" && value.trim().length >= (schema.minLength ?? 1) && value.length <= schema.maxLength &&
        (!schema.pattern || new RegExp(schema.pattern).test(value));
    case "integer":
      return Number.isSafeInteger(value) && value >= schema.minimum && value <= (schema.maximum ?? Number.MAX_SAFE_INTEGER);
    case "boolean":
      return typeof value === "boolean";
    case "array":
      return Array.isArray(value) && value.length >= (schema.minItems ?? 0) && value.length <= schema.maxItems &&
        value.every(item => validInput(item, schema.items));
    case "object":
      return value && typeof value === "object" && !Array.isArray(value);
  }
}

function validateFields(schema, fields, values) {
  const missing = schema.required.filter(key => !fields.includes(key));
  if (missing.length) throw new ToolInputError(`Missing required tool arguments: ${missing.join(", ")}.`);
  if (fields.some(key => !Object.hasOwn(schema.properties, key))) {
    throw new ToolInputError("Unexpected tool arguments. Use the advertised input schema.");
  }
  for (const [key, value] of Object.entries(values)) {
    if (!validInput(value, schema.properties[key])) throw new ToolInputError(`Invalid value for tool argument ${key}.`);
  }
}

function validated(call) {
  const definition = byName.get(call.name)?.inputSchema;
  const { [actorField]: actor, ...args } = call.arguments ?? {};
  if (!validActor(actor)) throw new ConnectionError("An authenticated Discord agent and requester are required.");
  if (!definition) throw new ConnectionError("Unknown integration management tool.");
  validateFields(definition, Object.keys(args), args);
  return { args, actor };
}

const result = value => ({ content: [{ type: "text", text: JSON.stringify(value) }] });
const agentTools = new Set(["list_managed_agents", "create_agent", "rename_agent", "set_agent_instructions", "deploy_agent_connector", "bind_agent_channel",
  "prepare_discord_server", "discord_server_setup_status", "cancel_discord_server_setup",
  "list_discord_access", "update_discord_channel_access", "update_discord_dm_access"]);
const sharingTools = new Set(["list_connection_access", "grant_connection_access", "revoke_connection_access"]);
const usageTools = new Set(["list_connection_tools", "call_connection_tool", "authorize_git_read", "authorize_git_push"]);
const permissionFor = name => sharingTools.has(name) ? "share" : usageTools.has(name) ? "use" : "manage";

function requireConnectionCall(policy, actor, row, name, toolName) {
  if (name === "diagnose_connection" && policy.can(row.id, "use")) return;
  if (name === "list_connection_tools" || name === "call_connection_tool") {
    return requireMcpAccess(policy, actor, row, name === "call_connection_tool" ? toolName : undefined);
  }
  if (name === "begin_github_installation") requireAccess(policy, row.id, "share");
  requireAccess(policy, row.id, permissionFor(name));
}

function requireMcpAccess(policy, actor, row, operation) {
  if (policy.can(row.id, "use") || (operation === undefined && policy.can(row.id, "share"))) return;
  const grants = scopedAccess.mcpGrants(actor.agent, row.id, row.revision);
  if (grants.has("*")) return;
  if (operation === undefined ? grants.size > 0 : grants.has(operation)) return grants;
  throw new ConnectionError("This agent needs browser approval for that integration tool.");
}

function mcpConnection(row, call) {
  if (row.legacy) {
    if (!Object.hasOwn(legacy, row.id)) throw new ConnectionError("This connection has no configured connector.");
    return withLegacy(row.id, call);
  }
  const installation = githubInstallation(row);
  return installation ? installationTools(row, installation, call) : remote.tools(row, call);
}

async function provision(name, args, requester) {
  try {
    const output = await unixRequest(process.env.SABLE_PROVISIONER_SOCKET ?? "/run/sable-agent-provisioner.sock", { name, args, requester }, 45_000);
    if (!output.ok) throw new ConnectionError(output.error);
    return output.value;
  } catch (error) {
    if (error instanceof ConnectionError) throw error;
    throw new ConnectionError("The agent provisioning service is unavailable.");
  }
}

const scopedTools = new Set(["request_integration_access", "integration_access_status", "pair_approval_browser",
  "list_scoped_integration_access", "revoke_scoped_integration_access", "discord_read_messages", "discord_post_message"]);
const gitTools = new Set(["authorize_git_read","authorize_git_push"]);
const accessManagement = "integration-access";

async function requireGit(actor, connection, revision, repository, mode) {
  if (scopedAccess.allows(actor.agent, "github", connection, revision, repository, mode)) return;
  requireAccess(await access.snapshot(actor), connection, "use");
}

function adminCanManage(policy) {
  return policy.can(accessManagement, "share");
}

async function checkScopedTarget(scope, user) {
  if (scope.agent !== "*") {
    const agents = await provision("list_managed_agents", {}, user);
    if (!agents.some(item => item.id === scope.agent)) throw new ConnectionError("The target agent no longer exists.");
  }
  if (scope.provider === "discord") {
    const target = await provision("inspect_discord_resource", { channel: scope.resource }, user);
    if (scope.connection !== target.guild) throw new ConnectionError("The Discord channel belongs to a different server.");
    return;
  }
  const row = registry.get(scope.connection, scope.revision);
  if (scope.provider === "mcp") {
    if (!row.legacy && !row.credential) throw new ConnectionError("Complete provider sign-in before granting access.");
    if (!scope.tools.includes("*")) {
      const available = new Set((await mcpConnection(row)).tools.map(tool => tool.name));
      if (scope.tools.some(tool => !available.has(tool))) {
        throw new ConnectionError("One or more requested tools are missing from the connector catalog. Check the exact names.");
      }
    }
    return;
  }
  const app = githubInstallation(row);
  if (!app || scope.permission === "write" && app.access === "read" ||
      !(app.repository === scope.resource || app.account === scope.resource.split("/")[0])) {
    throw new ConnectionError("The GitHub App lacks the requested repository or permission.");
  }
}

async function discordScope(actor, args, mode) {
  if (scopedAccess.allows(actor.agent, "discord", args.guild, 1, args.channel, mode)) return {};
  if (scopedAccess.hasDiscordThreadGrant(actor.agent, args.guild)) {
    const target = await provision("inspect_discord_resource", { channel: args.channel }, actor.user);
    if (target.guild === args.guild && target.parent &&
        scopedAccess.allowsDiscordThread(actor.agent, args.guild, target.parent, mode)) {
      return { parentChannel: target.parent };
    }
  }
  throw new ConnectionError("Request browser approval for this Discord channel or thread.");
}

async function manageScoped(tool, args, actor, policy) {
  const administrator = adminCanManage(policy);
  switch (tool) {
    case "request_integration_access": {
      if (args.agentId !== undefined && args.agentId !== actor.agent || args.audience === "all-downstream") {
        requireAccess(policy, accessManagement, "share");
      }
      const agent = args.audience === "all-downstream" ? "*" : args.agentId ?? actor.agent;
      const scope = { provider: args.provider, agent, resource: args.resource, permission: args.permission };
      if (scope.provider === "mcp") {
        if (args.permission !== undefined || args.threadPermission !== undefined ||
            Boolean(args.tools) === Boolean(args.allTools)) {
          throw new ConnectionError("Specify exact MCP tools or explicitly request the whole connection.");
        }
        const visible = registry.list();
        const matches = visible.filter(row => row.id === args.resource || row.label === args.resource);
        if (matches.length !== 1) throw new ConnectionError("Use the exact integration label or connection ID.");
        const row = matches[0];
        scope.connection = row.id;
        scope.revision = row.revision;
        scope.label = row.label;
        scope.destination = row.endpoint ? new URL(row.endpoint).origin : `Bundled connector: ${row.id}`;
        scope.resource = row.id;
        scope.permission = "invoke";
        scope.tools = args.allTools ? ["*"] : args.tools;
        await checkScopedTarget(scope, actor.user);
        return result(scopedAccess.request(actor, scope));
      }
      if (!args.permission || args.tools !== undefined || args.allTools !== undefined ||
          (scope.provider !== "discord" && args.threadPermission !== undefined)) {
        throw new ConnectionError("Specify read or write for the GitHub repository or Discord channel.");
      }
      if (scope.provider === "github") {
        scope.resource = scope.resource.toLowerCase().trim();
        const account = scope.resource.split("/")[0];
        const rows = registry.list().filter(item => item.endpoint === githubMcpEndpoint && item.status === "connected");
        const matches = rows.filter(item => {
          const app = githubInstallation(registry.get(item.id));
          return app?.account === account || app?.repository === scope.resource;
        });
        if (matches.length !== 1) {
          throw new ConnectionError("Connect one GitHub App for that account through Integration Admin, then request access.");
        }
        const row = matches[0];
        scope.connection = row.id;
        scope.revision = row.revision;
        scope.label = row.label;
        await checkScopedTarget(scope, actor.user);
      } else {
        const reference = /^<#([0-9]{16,22})>$/.exec(scope.resource)?.[1] ?? scope.resource;
        const target = await provision("resolve_discord_resource", { agent: agent === "*" ? actor.agent : agent, reference }, actor.user);
        scope.resource = target.channel;
        scope.connection = target.guild;
        scope.revision = 1;
        scope.label = `${target.server} / #${target.name}`;
        if (args.threadPermission !== undefined) {
          if (target.parent) throw new ConnectionError("Set thread permissions on the parent text channel.");
          scope.threadPermission = args.threadPermission;
        }
      }
      return result(scopedAccess.request(actor, scope));
    }
    case "integration_access_status":
      return result(scopedAccess.status(args.request, actor, administrator));
    case "pair_approval_browser":
      return result(await scopedAccess.pair(args.request, actor, args.code));
    case "list_scoped_integration_access":
      requireAccess(policy, accessManagement, "share");
      return result(scopedAccess.list());
    case "revoke_scoped_integration_access":
      requireAccess(policy, accessManagement, "share");
      return result({ revoked: scopedAccess.remove({ agent: args.subject, provider: args.provider, connection: args.id,
        revision: args.revision, resource: args.resource }) === 1 });
    default: {
      const mode = tool === "discord_post_message" ? "write" : "read";
      const scope = await discordScope(actor, args, mode);
      return result(await provision(tool, { ...args, ...scope }, actor.user));
    }
  }
}

async function manage(call) {
  const { args, actor } = validated(call);
  if (scopedTools.has(call.name)) return manageScoped(call.name, args, actor, await access.snapshot(actor));
  if (call.name === "list_connections") {
    const policy = await access.snapshot(actor);
    return result(registry.list().filter(row => policy.can(row.id, "use") || policy.can(row.id, "manage") ||
      scopedAccess.mcpGrants(actor.agent, row.id, row.revision).size > 0));
  }
  if (call.name === "add_connection") {
    const policy = await access.snapshot(actor);
    requireAccess(policy, "registry", "create");
    let owner = actor.agent;
    if (actor.agent === adminAgent || args.agentId !== undefined && args.agentId !== actor.agent) {
      requireAccess(policy, "agents", "agents");
      const agents = args.agentId ? await provision("list_managed_agents", {}) : [];
      if (args.agentId && !agents.some(entry => entry.id === args.agentId)) {
        throw new ConnectionError("The target agent does not exist.");
      }
      owner = args.agentId ?? null;
    }
    return result(registry.add(args.label, args.endpoint, owner));
  }
  if (agentTools.has(call.name)) {
    requireAccess(await access.snapshot(actor), "agents", "agents");
    return result(await provision(call.name, args, actor.user));
  }
  return serialized(args.id, async () => {
    const row = registry.get(args.id, args.revision);
    let selectedTools;
    if (gitTools.has(call.name)) {
      await requireGit(actor, args.id, args.revision, args.repository, call.name === "authorize_git_push" ? "write" : "read");
    } else {
      selectedTools = requireConnectionCall(await access.snapshot(actor), actor, row, call.name, args.name);
    }
    switch (call.name) {
      case "diagnose_connection":
        {
          const installation = githubInstallation(row);
          if (!installation) return result(await remote.diagnose(row, args.verify));
          if (args.verify) await installationTools(row, installation);
          return result({ status: "connected", authentication: "github_app_installation",
            ...(installation.account ? { account: installation.account } : { repository: installation.repository }),
            git: githubGitEnabled, verified: Boolean(args.verify) });
        }
      case "authorize_git_read":
        return result(gitAccess.open(row, actor, args.repository));
      case "authorize_git_push":
        return result(gitAccess.open(row, actor, args.repository, {
          ref: args.ref, oldCommit: args.oldCommit, newCommit: args.newCommit,
        }));
      case "edit_connection": {
        const edited = registry.edit(args.id, args.revision, args);
        if (edited.revision !== row.revision) remote.prune(row);
        return result(edited);
      }
      case "delete_connection":
        registry.delete(args.id, args.revision);
        remote.prune(row);
        return result({ deleted: args.id });
      case "begin_sign_in":
        return result(remote.begin(row, actor.user, actor));
      case "begin_github_installation": {
        if (row.endpoint !== githubMcpEndpoint || row.owner_agent !== adminAgent || row.legacy || row.credential) {
          throw new ConnectionError("Use a disconnected official GitHub MCP connection owned by Integration Admin.");
        }
        const { account, access: mode, organization } = args;
        return result(remote.begin(row, actor.user, actor, { method: "github_installation", account,
          organization: organization ? account : undefined, access: mode }));
      }
      case "begin_oauth_client_setup":
        return result(await remote.beginClientSetup(row, actor.user, actor, args));
      case "confirm_sign_in":
        remote.confirm(row, actor.user, args.code, actor);
        return result({ browser_verified: true });
      case "list_connection_access":
        return result(registry.grants(row.id).map(grant => grant.agent));
      case "grant_connection_access": {
        const agents = await provision("list_managed_agents", {});
        if (!agents.some(agent => agent.id === args.agentId)) throw new ConnectionError("The target agent does not exist.");
        if (!row.legacy && !row.credential) throw new ConnectionError("Connect this account before sharing it.");
        registry.grant(row.id, args.agentId);
        return result({ connection: row.id, agent: args.agentId, access: "use" });
      }
      case "revoke_connection_access":
        registry.revoke(row.id, args.agentId);
        return result({ connection: row.id, agent: args.agentId, access: "revoked" });
      case "list_connection_tools":
      case "call_connection_tool":
        const invoke = call.name === "call_connection_tool" ? { name: args.name, arguments: args.arguments } : undefined;
        const output = await mcpConnection(row, invoke);
        if (invoke) return output;
        return result(selectedTools ? { ...output, tools: output.tools.filter(tool => selectedTools.has(tool.name)) } : output);
    }
  });
}

async function withLegacy(route, call) {
  const transport = new StdioClientTransport({
    command: "/usr/bin/socat", args: ["-", `UNIX-CONNECT:${join(legacySocketDirectory, `sable-mcp-${route}.sock`)}`], stderr: "ignore",
  });
  const client = new Client(identity);
  const options = { timeout: 30_000 };
  try {
    await client.connect(transport, options);
    return call ? await client.callTool(call, undefined, options) : await client.listTools({}, options);
  } finally {
    await client.close().catch(() => {});
  }
}

async function legacyTools(route, call) {
  return serialized(route, async () => {
    let row;
    try { row = registry.get(route); } catch (error) {
      if (!(error instanceof ConnectionError)) throw error;
    }
    if (!row?.legacy) {
      if (!call) return { tools: [] };
      throw new ConnectionError("The original integration is disconnected. List connections for the current destination.");
    }
    if (!call) return withLegacy(route, undefined);
    const { [actorField]: actor, ...args } = call.arguments ?? {};
    requireMcpAccess(await access.snapshot(actor), actor, row, call.name);
    return withLegacy(route, { ...call, arguments: args });
  });
}

async function reviewTarget(payload) {
  const { service, name, args, fields, actor } = payload;
  const policy = await access.snapshot(actor);
  if (Object.hasOwn(legacy, service)) {
    const row = registry.get(service);
    requireMcpAccess(policy, actor, row, name);
    if (!row.legacy) throw new ConnectionError("This connection's original destination is disconnected.");
    return { connection: registry.describe(row) };
  }
  const definition = byName.get(name);
  if (service !== "integrations" || !definition) throw new ConnectionError("Unknown integration route.");
  validateFields(definition.inputSchema, fields, args);
  const operation = { description: definition.description };
  if (agentTools.has(name)) {
    requireAccess(policy, "agents", "agents");
    return { operation };
  }
  if (name === "add_connection" && args?.agentId !== undefined && args.agentId !== actor.agent) {
    requireAccess(policy, "agents", "agents");
  }
  if (name === "list_connections" || name === "add_connection") return { operation };
  if (scopedTools.has(name)) {
    if (["pair_approval_browser", "list_scoped_integration_access", "revoke_scoped_integration_access"].includes(name) ||
        name === "request_integration_access" && (args?.audience === "all-downstream" || args?.agentId && args.agentId !== actor.agent)) {
      requireAccess(policy, accessManagement, "share");
    }
    if (name === "discord_read_messages" || name === "discord_post_message") {
      const mode = name === "discord_post_message" ? "write" : "read";
      await discordScope(actor, args, mode);
    }
    return { operation };
  }
  const { id, revision } = args ?? {};
  if (typeof id !== "string" || !Number.isSafeInteger(revision)) throw new ConnectionError("Invalid connection reference.");
  const row = registry.get(id, revision);
  if (gitTools.has(name)) {
    await requireGit(actor, id, revision, args.repository, name === "authorize_git_push" ? "write" : "read");
  } else {
    requireConnectionCall(policy, actor, row, name, args.name);
  }
  return { operation, connection: registry.describe(row) };
}

function attachLocalRequest(socket, prefix, handler, maxBytes, visibleError = ToolInputError) {
  let data = prefix;
  function consume() {
    const end = data.indexOf(10);
    if (data.length > maxBytes) return socket.destroy();
    if (end < 0) return;
    socket.pause();
    Promise.resolve().then(() => handler(JSON.parse(data.subarray(0, end).toString())))
      .then(value => socket.end(JSON.stringify({ ok: true, value }) + "\n"))
      .catch(error => socket.end(JSON.stringify({
        ok: false,
        ...(error instanceof visibleError && { inputError: error.message }),
      }) + "\n"));
  }
  socket.on("data", chunk => { data = Buffer.concat([data, chunk]); consume(); });
  if (prefix.length) consume();
  if (data.indexOf(10) < 0) socket.resume();
}

function attach(socket, route, prefix) {
  const input = new PassThrough();
  socket.pipe(input);
  const server = new Server(identity, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, () =>
    route === "integrations" ? { tools: management } : legacyTools(route));
  server.setRequestHandler(CallToolRequestSchema, async ({ params }) => {
    try {
      return await (route === "integrations" ? manage(params) : legacyTools(route, params));
    } catch (error) {
      const message = error instanceof ConnectionError ? error.message : "The broker could not complete the request.";
      return { isError: true, content: [{ type: "text", text: message }] };
    }
  });
  socket.on("close", () => { server.close().catch(() => {}); input.destroy(); });
  server.connect(new StdioServerTransport(input, socket, { maxBufferSize: 256 * 1024 }))
    .then(() => { if (prefix.length) input.write(prefix); socket.resume(); })
    .catch(() => socket.destroy());
}

const listener = net.createServer(socket => {
  socket.on("error", () => socket.destroy());
  socket.setTimeout(5_000, () => socket.destroy());
  let head = Buffer.alloc(0);
  function onData(chunk) {
    head = Buffer.concat([head, chunk]);
    const newline = head.indexOf(10);
    if (newline < 0 && head.length < 64) return;
    const route = newline >= 0 && newline < 64 ? head.subarray(0, newline).toString("ascii") : "";
    if (!["integrations", "review-target", "schedule"].includes(route) && !Object.hasOwn(legacy, route)) return socket.destroy();
    socket.pause();
    socket.off("data", onData);
    socket.setTimeout(0);
    const prefix = head.subarray(newline + 1);
    if (route === "review-target") attachLocalRequest(socket, prefix, reviewTarget, 4096);
    else if (route === "schedule") attachLocalRequest(socket, prefix,
      payload => provision("manage_schedule", payload, payload.scope?.user), 65536, ConnectionError);
    else attach(socket, route, prefix);
  }
  socket.on("data", onData);
});

if (process.env.LISTEN_PID !== String(process.pid) || process.env.LISTEN_FDS !== "1") {
  throw new Error("The broker requires its systemd socket.");
}
listener.listen({ fd: 3 });

const markup = text => String(text).replace(/[&<>"']/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
function page(response, status, body, headers = {}) {
  response.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    ...headers,
  });
  response.end(`<!doctype html><meta charset="utf-8"><title>Agent Steward integrations</title>${body}`);
}

function pairedPage(pending) {
  if (pending.githubApp) {
    return { body: `<p><a href="${markup(pending.githubApp.installUrl)}" target="_blank" rel="noopener noreferrer">Install the app on GitHub</a>.
      Select all repositories of <strong>${markup(pending.setup.account)}</strong> and grant ${markup(pending.setup.access)} access for code, issues and pull requests.
      Then return to this paired tab.</p><form method="post"><button>Verify installation</button></form>` };
  }
  if (pending.setup?.method === "github_manifest" || pending.setup?.method === "github_installation") {
    const manifest = remote.manifest(pending);
    return {
      body: `<p>Register the private app on GitHub. Then install it on the repositories you choose and authorise this connection.</p>
        <form method="post" action="${markup(manifest.target)}">
          <input type="hidden" name="manifest" value="${markup(JSON.stringify(manifest.data))}">
          <button>Register GitHub App</button>
        </form>`,
      headers: {
        "Content-Security-Policy": "default-src 'none'; form-action https://github.com; frame-ancestors 'none'; base-uri 'none'",
      },
    };
  }
  if (pending.setup?.method === "secure_client_intake") {
    const issuer = markup(pending.setup.metadata.issuer);
    const tokenEndpoint = markup(pending.setup.metadata.token_endpoint);
    return {
      body: `<p>Register a client with <code>${issuer}</code>. Set its callback to <code>${markup(remote.origin)}/oauth/callback</code>.
        The broker will use these credentials only for the discovered token endpoint <code>${tokenEndpoint}</code>.</p>
        <form method="post" autocomplete="off">
          <p><label>Client ID <input name="client_id" maxlength="512" required></label></p>
          <p><label>Client secret <input type="password" name="client_secret" maxlength="4096" required></label></p>
          <p><label>Token endpoint authentication <select name="auth_method">
            <option value="client_secret_post">Client secret in request body</option>
            <option value="client_secret_basic">HTTP Basic authentication</option>
          </select></label></p>
          <button>Save directly to the broker</button>
        </form>`,
    };
  }
  const registration = remote.registeredClient(pending.row);
  const install = registration?.installUrl
    ? `<p><a href="${markup(registration.installUrl)}" target="_blank" rel="noopener noreferrer">Install the app on GitHub</a>
      and choose the repositories it can access. Then return to this tab.</p>`
    : "";
  return { body: `${install}<form method="post"><button>Continue to provider sign-in</button></form>` };
}

async function clientForm(request) {
  if (request.headers["content-type"]?.split(";")[0] !== "application/x-www-form-urlencoded") {
    throw new ConnectionError("Use the broker's credential form.");
  }
  let size = 0;
  const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 16_384) throw new ConnectionError("The credential form exceeds the size limit.");
    chunks.push(chunk);
  }
  const form = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
  if (form.size !== 3 || ["client_id", "client_secret", "auth_method"].some(key => form.getAll(key).length !== 1)) {
    throw new ConnectionError("The credential form is incomplete.");
  }
  return { clientId: form.get("client_id"), clientSecret: form.get("client_secret"), authMethod: form.get("auth_method") };
}

async function accessBrowser(request, response, id) {
  const cookies = (request.headers.cookie ?? "").split("; ").filter(item => item.startsWith(`${approvalCookie}=`));
  const cookie = cookies.length === 1 ? cookies[0].slice(approvalCookie.length + 1) : undefined;
  const browserId = isBrowserId(cookie) ? cookie : newBrowserId();
  if (request.method === "POST") {
    if (request.headers.origin !== remote.origin) return page(response, 403, "<p>Submit approval from its original tab.</p>");
    await scopedAccess.approve(id, browserId, checkScopedTarget);
    return page(response, 200, "<h1>Access approved</h1><p>Return to your agent. It can check the request and continue.</p>");
  }
  if (request.method !== "GET") return page(response, 405, "<p>Open the approval page in your browser.</p>");
  if (!await scopedAccess.browserAdmin(browserId)) {
    const code = scopedAccess.code(id, browserId);
    return page(response, 200, `<h1>Pair this approval browser</h1>
      <p>In your private Integration Admin DM, send this exact line:</p>
      <p><code>Pair integration approval ${markup(id)} with code ${markup(code)}</code></p>
      <p><a href="/connect/access/${markup(id)}">Check pairing</a></p>`,
      { "Set-Cookie": `${approvalCookie}=${browserId}; Max-Age=604800; Path=/; Secure; HttpOnly; SameSite=Lax` });
  }
  const { scope, approved } = scopedAccess.load(id);
  const recipient = scope.agent === "*" ? "All current and future downstream agents" : scope.agent;
  const permissions = scope.tools
    ? scope.tools.includes("*") ? "All current and future MCP tools" : scope.tools.join(", ")
    : scope.permission;
  const resource = scope.provider === "mcp" ? "MCP connector" : scope.resource;
  return page(response, 200, `<h1>Review integration access</h1>
    <dl><dt>Agent</dt><dd>${markup(recipient)}</dd><dt>Connection</dt><dd>${markup(scope.label)}</dd>
    <dt>Resource</dt><dd><code>${markup(resource)}</code></dd><dt>Permissions</dt><dd>${markup(permissions)}</dd></dl>
    ${scope.destination ? `<p>Destination <code>${markup(scope.destination)}</code></p>` : ""}
    ${scope.threadPermission ? `<p>Threads under this channel have ${markup(scope.threadPermission)} access.</p>` : ""}
    ${scope.provider === "github" ? "<p>This adds a native Git grant. Administrators can review or revoke broader existing connection access separately.</p>" : ""}
    <p>Integration calls go through Luna.</p>
    ${approved ? "<p>Already approved.</p>" : '<form method="post"><button>Approve requested access</button></form>'}`);
}

const browser = http.createServer(async (request, response) => {
  const host = request.headers.host;
  if (host !== signInHost || !request.url?.startsWith("/") ||
      request.url.startsWith("//") || request.url.length > 8192) {
    return page(response, 400, "<p>Invalid request.</p>");
  }
  let attempt;
  try {
    const url = new URL(request.url, remote.origin);
    const accessId = /^\/connect\/access\/([A-Za-z0-9_-]{43})$/.exec(url.pathname)?.[1];
    if (accessId) return await accessBrowser(request, response, accessId);
    const cookies = (request.headers.cookie ?? "").split("; ").filter(item => item.startsWith(`${pairingCookie}=`));
    const browserId = cookies.length === 1 ? cookies[0].slice(pairingCookie.length + 1) : undefined;
    const link = /^\/connect\/([\w-]{43})$/.exec(url.pathname)?.[1];
    if (link && request.method === "GET") {
      const pending = remote.pending(link);
      const { row, pairing } = pending;
      const id = isBrowserId(browserId) ? browserId : newBrowserId();
      const code = pairing.codeFor(id);
      const confirmed = pairing.canContinue(id);
      const paired = confirmed ? pairedPage(pending) : undefined;
      const next = paired ? paired.body
        : code
          ? `<p>Send this code to the agent in Discord.</p><p><strong>${code}</strong></p>
             <p>Return here after the agent confirms the code.</p><p><a href="/connect/${link}">Check confirmation</a></p>`
          : "<p>This link is paired with another browser. Ask the agent for a fresh link.</p>";
      return page(response, 200, `<h1>Connect ${markup(row.label)}</h1>
        <p>Integration endpoint <code>${markup(row.endpoint)}</code></p>${next}`,
        {
          "Set-Cookie": `${pairingCookie}=${id}; Max-Age=600; Path=/; Secure; HttpOnly; SameSite=Lax`,
          ...(paired && { "Referrer-Policy": "same-origin", ...paired.headers }),
        });
    }
    if (link && request.method === "POST") {
      if (request.headers.origin !== remote.origin) {
        return page(response, 403, "<p>Submit this form from the original sign-in tab.</p>");
      }
      const pending = remote.pending(link);
      const authorization = await serialized(pending.row.id, async () => {
        const current = remote.pending(link);
        requireAccess(await access.snapshot(current.actor), current.row.id, "manage");
        if (!current.pairing.canContinue(browserId)) throw new ConnectionError("Confirm this browser in Discord first.");
        attempt = current.row;
        if (current.setup?.method === "github_installation") {
          requireAccess(await access.snapshot(current.actor), current.row.id, "share");
          await remote.finishGitHubInstallation(current);
          return false;
        }
        if (current.setup) {
          if (current.setup.method !== "secure_client_intake") throw new ConnectionError("Register the app on GitHub first.");
          remote.saveRegistration(current, await clientForm(request));
          return undefined;
        }
        return remote.authorize(current);
      });
      if (authorization === false) {
        return page(response, 200, "<h1>GitHub connected</h1><p>You can return to Discord.</p>");
      }
      if (!authorization) {
        return page(response, 200, `<p>OAuth client saved. <a href="/connect/${link}">Continue to sign-in</a>.</p>`);
      }
      // Keep the form submission same-origin. Some browsers apply form-action to HTTP redirects.
      const destination = markup(authorization.href);
      return page(response, 200, `<meta http-equiv="refresh" content="0;url=${destination}">
        <p>Opening the provider sign-in. <a href="${destination}">Continue if it does not open automatically</a>.</p>`);
    }
    if (url.pathname === "/oauth/callback" && request.method === "GET") {
      const params = url.searchParams;
      const state = params.get("state");
      const code = params.get("code");
      const registration = remote.registrationStates.get(state);
      const pending = registration ?? remote.states.get(state);
      if (!pending?.pairing.canContinue(browserId) || params.getAll("state").length !== 1 ||
          params.getAll("code").length > 1 || params.getAll("iss").length > 1) {
        throw new ConnectionError("Invalid or expired sign-in. Request a new link.");
      }
      attempt = pending.row;
      if (!code || params.has("error")) throw new ConnectionError("The provider declined or cancelled sign-in.");
      await serialized(pending.row.id, async () => {
        requireAccess(await access.snapshot(pending.actor), pending.row.id, "manage");
        if (registration) {
          if (pending.setup?.method === "github_installation") {
            requireAccess(await access.snapshot(pending.actor), pending.row.id, "share");
          }
          return remote.finishManifest(pending, state, code);
        }
        return remote.finish(pending, state, params.get("iss"), code);
      });
      if (registration) {
        return page(response, 200, `<p>GitHub App registered. <a href="/connect/${pending.link}">Continue to installation and sign-in</a>.</p>`);
      }
      return page(response, 200, "<h1>Connected</h1><p>You can return to Discord.</p>");
    }
    page(response, 404, "<p>Page unavailable.</p>");
  } catch (error) {
    const message = error instanceof ConnectionError ? error.message : "The provider could not finish sign-in.";
    if (attempt) remote.record(attempt, "sign_in_error", message);
    if (!(error instanceof ConnectionError)) {
      const code = [error?.code, error?.cause?.code].find(value => typeof value === "string" && /^[A-Z][A-Z0-9_]{1,63}$/.test(value));
      const location = /(?:lifecycle\/)([a-z-]+\.mjs:\d+:\d+)/.exec(error?.stack ?? "")?.[1];
      console.warn("Integration browser request failed", { method: request.method, code, location });
    }
    page(response, 400, `<p>${markup(message)}</p>`);
  }
});
browser.listen(Number(process.env.SABLE_BROWSER_PORT ?? 17896), "127.0.0.1");
if (githubGitEnabled) gitAccess.server().listen(Number(process.env.SABLE_GIT_PORT ?? 17897), "127.0.0.1");
