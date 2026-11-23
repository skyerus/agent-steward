import { randomBytes } from "node:crypto";
import { auth, discoverOAuthServerInfo } from "@modelcontextprotocol/sdk/client/auth.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ConnectionError, httpsEndpoint } from "./registry.mjs";
import { publicFetch, resolvePublic, scopedFetch } from "./public-fetch.mjs";
import { BrowserPairing } from "./browser-pairing.mjs";
import { discoverAccountInstallation } from "./github-native.mjs";
import { exchangeGitHubManifest, githubDocumentation, githubManifest, githubMcpEndpoint } from "./github-registration.mjs";

const newState = () => randomBytes(32).toString("base64url");
const canonical = value => httpsEndpoint(value).href;
const identity = { name: "sable-integration-broker", version: "1.0.0" };
const options = { timeout: 30_000 };
const clientMethods = ["client_secret_basic", "client_secret_post"];
const missingClient = "This provider requires a registered OAuth client. Use the broker's OAuth client setup.";

class OAuthSession {
  constructor(row, callbackURL, data = {}, resolve = resolvePublic, registration) {
    this.endpoint = row.endpoint;
    this.redirectUrl = callbackURL;
    this.data = data;
    this.resolve = resolve;
    this.oauthState = newState();
    this.registration = registration;
    this.clientMetadata = {
      client_name: "Agent Steward integration broker",
      redirect_uris: [callbackURL],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: registration?.client.token_endpoint_auth_method ?? "none",
    };
  }

  state() { return this.oauthState; }
  clientInformation() { return this.registration?.client ?? this.data.client; }
  saveClientInformation(client) { if (!this.registration) this.data.client = client; }
  tokens() { return this.data.tokens; }
  saveTokens(tokens) { this.data.tokens = tokens; }
  discoveryState() { return this.data.discovery; }
  saveCodeVerifier(verifier) { this.verifier = verifier; }
  codeVerifier() { return this.verifier; }

  async validateResourceURL(_, resource) {
    if (resource && canonical(resource) !== this.endpoint) {
      throw new ConnectionError("The provider's OAuth resource differs from the integration endpoint.");
    }
    return new URL(this.endpoint);
  }

  async saveDiscoveryState(discovery) {
    const metadata = discovery.authorizationServerMetadata;
    if (!metadata?.code_challenge_methods_supported?.includes("S256")) {
      throw new ConnectionError("The provider must advertise OAuth with S256 PKCE.");
    }
    for (const key of ["issuer", "authorization_endpoint", "token_endpoint", "registration_endpoint"]) {
      if (key === "registration_endpoint" && !metadata[key]) continue;
      metadata[key] = canonical(metadata[key]);
      const previous = this.data.discovery?.authorizationServerMetadata[key];
      if (previous && metadata[key] !== previous) {
        throw new ConnectionError("The OAuth provider changed. Start a fresh sign-in.");
      }
      await this.resolve(metadata[key]);
    }
    this.verifyRegistration(discovery);
    if (canonical(discovery.authorizationServerUrl) !== metadata.issuer) {
      throw new ConnectionError("OAuth discovery and the advertised issuer do not match.");
    }
    this.data.discovery = discovery;
  }

  verifyRegistration(discovery) {
    if (!this.registration) return;
    const { issuer, authorization_endpoint, token_endpoint } = discovery.authorizationServerMetadata;
    const registration = this.registration;
    if (canonical(discovery.authorizationServerUrl) !== registration.client.issuer ||
        issuer !== registration.client.issuer ||
        authorization_endpoint !== registration.authorizationEndpoint ||
        token_endpoint !== registration.tokenEndpoint) {
      throw new ConnectionError("The OAuth provider does not match the registered client.");
    }
  }

  redirectToAuthorization(url) {
    const target = new URL(url);
    const metadata = this.data.discovery?.authorizationServerMetadata;
    const pinned = new URL(metadata.authorization_endpoint);
    httpsEndpoint(target);
    if (target.origin !== pinned.origin || target.pathname !== pinned.pathname) {
      throw new ConnectionError("OAuth returned an unexpected sign-in destination.");
    }
    this.authorization = target;
  }

  invalidateCredentials(scope) {
    if (scope === "tokens" || scope === "all") delete this.data.tokens;
    if (scope === "client" || scope === "all") delete this.data.client;
    if (scope === "verifier" || scope === "all") delete this.verifier;
    // Keep the verified OAuth endpoints pinned. New discovery requires an explicit sign-in.
  }
}

export class RemoteConnectors {
  constructor(registry, { origin, fetch = publicFetch, resolve = resolvePublic, clients = [] } = {}) {
    this.registry = registry;
    this.origin = httpsEndpoint(origin).origin;
    this.fetch = fetch;
    this.resolve = resolve;
    this.clients = new Map();
    for (const { endpoint, issuer, authorizationEndpoint, tokenEndpoint, clientId, clientSecret,
                 authMethod = "client_secret_post" } of clients) {
      const resource = canonical(endpoint);
      if (this.clients.has(resource) || typeof clientId !== "string" || !clientId ||
          typeof clientSecret !== "string" || !clientSecret ||
          !clientMethods.includes(authMethod)) {
        throw new Error("The broker OAuth client registrations are invalid.");
      }
      this.clients.set(resource, {
        authorizationEndpoint: canonical(authorizationEndpoint), tokenEndpoint: canonical(tokenEndpoint),
        client: { client_id: clientId, client_secret: clientSecret, issuer: canonical(issuer), token_endpoint_auth_method: authMethod },
      });
    }
    this.links = new Map();
    this.states = new Map();
    this.registrationStates = new Map();
    this.events = new Map();
  }

  record(row, stage, detail) {
    const key = `${row.id}:${row.revision}`;
    this.events.delete(key);
    if (this.events.size >= 128) this.events.delete(this.events.keys().next().value);
    this.events.set(key, { stage, ...(detail && { detail }), at: new Date().toISOString() });
  }

  prune(row) {
    for (const pending of this.links.values()) {
      if (pending.until <= Date.now() || pending.row.id === row.id) {
        this.links.delete(pending.link);
        this.states.delete(pending.session?.oauthState);
        this.registrationStates.delete(pending.registrationState);
      }
    }
  }

  begin(row, requester, actor, setup) {
    if (row.legacy || row.credential) throw new ConnectionError("This connection is already signed in.");
    this.prune(row);
    if (this.links.size >= 100) throw new ConnectionError("Too many pending sign-ins. Try again later.");
    const link = newState();
    const pending = { link, row, actor, setup, pairing: new BrowserPairing(requester), until: Date.now() + 10 * 60_000 };
    if (setup?.method === "github_manifest" || setup?.method === "github_installation") {
      pending.registrationState = newState();
      this.registrationStates.set(pending.registrationState, pending);
    }
    this.links.set(link, pending);
    this.record(row, "waiting_for_browser_pairing");
    return { sign_in_url: `${this.origin}/connect/${link}`, expires_in_seconds: 600, endpoint: row.endpoint };
  }

  confirm(row, requester, code, actor) {
    const pending = [...this.links.values()].find(entry => entry.row.id === row.id);
    if (!pending) throw new ConnectionError("No sign-in is pending. Ask to start sign-in again.");
    if (pending.actor?.agent !== actor.agent) throw new ConnectionError("Confirm sign-in with the agent that started it.");
    this.pending(pending.link).pairing.confirm(requester, code);
    this.record(row, "browser_paired");
  }

  pending(link) {
    const pending = this.links.get(link);
    if (!pending || pending.until <= Date.now()) throw new ConnectionError("This sign-in expired. Request a new link.");
    this.registry.get(pending.row.id, pending.row.revision);
    return pending;
  }

  registeredClient(row) { return this.registry.oauthClient(row) ?? this.clients.get(row.endpoint); }

  async discover(row) {
    const registration = this.registeredClient(row);
    const data = registration ? { registeredClientId: registration.client.client_id } : {};
    const session = new OAuthSession(row, `${this.origin}/oauth/callback`, data, this.resolve, registration);
    const fetch = scopedFetch(row.endpoint, () => session.discoveryState(), this.fetch);
    const metadataResponse = await this.fetch(row.endpoint, { headers: { Accept: "application/json" } });
    const challenge = metadataResponse.headers.get("www-authenticate") ?? "";
    await metadataResponse.body?.cancel();
    const location = /(?:^|[\s,])resource_metadata="([^"]+)"/i.exec(challenge)?.[1];
    const resourceMetadataUrl = location ? httpsEndpoint(location) : undefined;
    const { authorizationServerUrl, authorizationServerMetadata, resourceMetadata } =
      await discoverOAuthServerInfo(row.endpoint, { resourceMetadataUrl, fetchFn: fetch });
    await session.saveDiscoveryState({ authorizationServerUrl, authorizationServerMetadata, resourceMetadata,
      resourceMetadataUrl: resourceMetadataUrl?.href });
    await session.validateResourceURL(row.endpoint, resourceMetadata?.resource);
    return { session, fetch, metadata: session.discoveryState().authorizationServerMetadata };
  }

  async diagnose(row, verify = false) {
    const current = this.events.get(`${row.id}:${row.revision}`);
    const base = { status: row.credential || row.legacy ? "connected" : "sign_in_required", ...(current && { current }) };
    if (row.legacy || (row.credential && !verify)) return base;
    if (row.credential) {
      try {
        const { tools } = await this.tools(row);
        return { ...base, verified: true, toolCount: tools.length };
      } catch (error) {
        return { ...base, verified: false, detail: error instanceof ConnectionError ? error.message : "MCP verification failed." };
      }
    }
    try {
      const { session, metadata } = await this.discover(row);
      const registered = Boolean(session.clientInformation());
      const method = registered || metadata.registration_endpoint ? "browser_oauth" :
        row.endpoint === githubMcpEndpoint ? "github_manifest" : "secure_client_intake";
      return { ...base, method, issuer: metadata.issuer, registered,
        ...(method === "github_manifest" && { documentation: githubDocumentation }) };
    } catch (error) {
      return { ...base, method: "investigate_provider",
        detail: error instanceof ConnectionError ? error.message : "The broker could not verify the provider's public OAuth metadata." };
    }
  }

  async beginClientSetup(row, requester, actor, { organization, access }) {
    if (row.credential || row.legacy || this.registeredClient(row)) {
      throw new ConnectionError("This connection already has an OAuth client. Continue with regular sign-in.");
    }
    const { metadata } = await this.discover(row);
    if (metadata.registration_endpoint) throw new ConnectionError("This provider supports regular browser sign-in.");
    const method = row.endpoint === githubMcpEndpoint ? "github_manifest" : "secure_client_intake";
    const result = this.begin(row, requester, actor, { method, metadata, organization, access: access ?? "read" });
    return { ...result, method, issuer: metadata.issuer };
  }

  manifest(pending) {
    if (this.registrationStates.get(pending.registrationState) !== pending) {
      throw new ConnectionError("App registration is no longer current. Ask the agent to start a new link.");
    }
    return githubManifest(this.origin, pending.registrationState, pending.setup);
  }

  saveRegistration(pending, values) {
    const { row, setup } = pending;
    const { clientId, clientSecret, installUrl, authMethod = "client_secret_post" } = values;
    if (typeof clientId !== "string" || !/^[\x21-\x7e]{1,512}$/.test(clientId) ||
        typeof clientSecret !== "string" || !/^[\x21-\x7e]{1,4096}$/.test(clientSecret) ||
        !clientMethods.includes(authMethod) ||
        (setup.metadata.token_endpoint_auth_methods_supported && !setup.metadata.token_endpoint_auth_methods_supported.includes(authMethod))) {
      throw new ConnectionError("Enter valid OAuth client credentials and the authentication method supported by the provider.");
    }
    const { issuer, authorization_endpoint, token_endpoint } = setup.metadata;
    this.pending(pending.link);
    this.registry.registerOAuthClient(row, {
      authorizationEndpoint: authorization_endpoint, tokenEndpoint: token_endpoint,
      client: { client_id: clientId, client_secret: clientSecret, issuer, token_endpoint_auth_method: authMethod },
      ...(installUrl && { installUrl }),
    });
    pending.setup = undefined;
    this.record(row, "oauth_client_registered");
  }

  async finishManifest(pending, state, code) {
    const installation = pending.setup?.method === "github_installation";
    if (this.registrationStates.get(state) !== pending || !installation && pending.setup?.method !== "github_manifest") {
      throw new ConnectionError("Invalid or expired app registration.");
    }
    this.pending(pending.link);
    this.registrationStates.delete(state);
    const credentials = await exchangeGitHubManifest(code, this.fetch, { installation });
    if (installation) {
      pending.githubApp = credentials;
      this.record(pending.row, "waiting_for_github_installation");
    } else {
      this.saveRegistration(pending, credentials);
    }
  }

  async finishGitHubInstallation(pending) {
    if (pending.setup?.method !== "github_installation" || !pending.githubApp) {
      throw new ConnectionError("Register the app on GitHub before verifying installation.");
    }
    const current = this.registry.get(pending.row.id, pending.row.revision);
    if (current.credential) throw new ConnectionError("This connection is already signed in.");
    const credential = await discoverAccountInstallation(pending.setup, pending.githubApp, this.fetch);
    this.pending(pending.link);
    this.registry.credentials(current, credential);
    this.prune(current);
    this.record(current, "connected");
  }

  async authorize(pending) {
    const { row } = pending;
    const { session, fetch, metadata } = await this.discover(row);
    if (!session.clientInformation() && !metadata.registration_endpoint) throw new ConnectionError(missingClient);
    await auth(session, { serverUrl: row.endpoint, fetchFn: fetch });
    if (!session.authorization || !session.verifier) {
      throw new ConnectionError("The provider did not offer a browser OAuth sign-in.");
    }
    this.pending(pending.link);
    if (pending.session) this.states.delete(pending.session.oauthState);
    pending.session = session;
    this.states.set(session.oauthState, pending);
    this.record(row, "waiting_for_provider_consent");
    return session.authorization;
  }

  async finish(pending, state, issuer, code) {
    const session = pending.session;
    if (this.states.get(state) !== pending || state !== session?.oauthState) {
      throw new ConnectionError("The sign-in is no longer current.");
    }
    this.pending(pending.link);
    this.links.delete(pending.link);
    this.states.delete(state);
    const expected = session.discoveryState().authorizationServerMetadata.issuer;
    const requiresIssuer = session.discoveryState().authorizationServerMetadata.authorization_response_iss_parameter_supported;
    if ((issuer || requiresIssuer) && (!issuer || canonical(issuer) !== expected)) {
      throw new ConnectionError("The OAuth response came from a different issuer.");
    }
    const fetch = scopedFetch(pending.row.endpoint, () => session.discoveryState(), this.fetch);
    const result = await auth(session, { serverUrl: pending.row.endpoint, authorizationCode: code, fetchFn: fetch });
    if (result !== "AUTHORIZED" || !session.tokens()?.access_token) {
      throw new ConnectionError("The provider did not authorize this connection.");
    }
    this.registry.credentials(pending.row, session.data);
    this.record(pending.row, "connected");
  }

  async tools(row, call) {
    if (!row.credential) throw new ConnectionError("This destination requires a fresh sign-in.");
    const data = JSON.parse(row.credential);
    const registration = this.registeredClient(row);
    if (data.registeredClientId !== registration?.client.client_id) {
      throw new ConnectionError("The broker's registered OAuth client changed. Re-create this connection before signing in.");
    }
    const session = new OAuthSession(row, `${this.origin}/oauth/callback`, data, this.resolve, registration);
    session.verifyRegistration(data.discovery);
    const before = JSON.stringify(session.data);
    const fetch = scopedFetch(row.endpoint, () => session.discoveryState(), this.fetch);
    const transport = new StreamableHTTPClientTransport(new URL(row.endpoint), {
      authProvider: session, fetch, requestInit: { redirect: "error" },
      reconnectionOptions: { maxRetries: 0 },
    });
    const client = new Client(identity);
    try {
      await client.connect(transport, options);
      const response = call ? await client.callTool(call, undefined, options) : await client.listTools({}, options);
      const previous = JSON.parse(before);
      const secrets = [
        previous.tokens?.access_token, previous.tokens?.refresh_token, previous.client?.client_secret,
        session.tokens()?.access_token, session.tokens()?.refresh_token, session.clientInformation()?.client_secret,
      ].filter(Boolean);
      const text = JSON.stringify(response);
      if (secrets.some(secret => text.includes(JSON.stringify(secret).slice(1, -1)))) {
        throw new Error("The connector included a credential in its response.");
      }
      return response;
    } catch {
      if (session.authorization || !session.tokens()?.access_token) {
        throw new ConnectionError("The provider requires a fresh sign-in.");
      }
      throw new ConnectionError("The provider could not complete the MCP request.");
    } finally {
      await client.close().catch(() => {});
      if (session.authorization) this.registry.credentials(row, null);
      else if (JSON.stringify(session.data) !== before) {
        this.registry.credentials(row, session.tokens()?.access_token ? session.data : null);
      }
    }
  }
}
