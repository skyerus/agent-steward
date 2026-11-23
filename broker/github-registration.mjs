import { ConnectionError } from "./registry.mjs";

export const githubMcpEndpoint = "https://api.githubcopilot.com/mcp/";
export const githubDocumentation = "https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest";
const github = "https://github.com";

export function githubManifest(origin, state, { organization, access, method, account }) {
  const route = organization ? `/organizations/${organization}/settings/apps/new` : "/settings/apps/new";
  const callback = `${origin}/oauth/callback`;
  return {
    target: `${github}${route}?state=${state}`,
    data: {
      name: method === "github_installation" ? `Agent Git ${account}` : "Agent Steward Agents",
      url: origin,
      redirect_url: callback,
      callback_urls: [callback],
      hook_attributes: { url: origin, active: false },
      public: false,
      default_permissions: { contents: access, issues: access, pull_requests: access },
    },
  };
}

export async function exchangeGitHubManifest(code, fetch, { installation = false } = {}) {
  if (!/^[a-zA-Z0-9_-]{1,256}$/.test(code)) throw new ConnectionError("GitHub returned an invalid registration code.");
  const response = await fetch(`https://api.github.com/app-manifests/${code}/conversions`, {
    method: "POST",
    headers: { Accept: "application/vnd.github+json", "User-Agent": "Agent-Steward-Integration-Broker" },
  });
  if (response.status !== 201) {
    await response.body?.cancel();
    throw new ConnectionError("GitHub could not complete app registration. Ask the agent for diagnostics.");
  }
  const value = await response.json();
  if (typeof value.slug !== "string" || !/^[a-z0-9-]{1,100}$/.test(value.slug)) {
    throw new ConnectionError("GitHub returned an invalid app name.");
  }
  const installUrl = `${github}/apps/${value.slug}/installations/new`;
  if (installation) {
    if (!Number.isSafeInteger(value.id) || value.id <= 0 || typeof value.pem !== "string" || value.pem.length > 16384) {
      throw new ConnectionError("GitHub returned an incomplete app registration.");
    }
    return { appId: String(value.id), privateKey: value.pem, installUrl };
  }
  if (typeof value.client_id !== "string" || typeof value.client_secret !== "string") {
    throw new ConnectionError("GitHub returned an incomplete OAuth registration.");
  }
  return {
    clientId: value.client_id,
    clientSecret: value.client_secret,
    installUrl,
  };
}
