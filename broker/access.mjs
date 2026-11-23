import { newEnforcer, newModelFromString } from "casbin";
import { ConnectionError } from "./registry.mjs";

export const adminAgent = "integration-admin";
export const actorField = "__sableActor";
export const agentIdPattern = /^[a-z][a-z0-9_-]{0,62}$/;
export const discordIdPattern = /^[0-9]{16,22}$/;

const model = `
[request_definition]
r = agent, user, obj, act
[policy_definition]
p = agent, user, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = (p.agent == "*" || p.agent == r.agent) && (p.user == "*" || p.user == r.user) && (p.obj == "*" || p.obj == r.obj) && p.act == r.act
`;

export function validActor(actor) {
  return typeof actor?.agent === "string" && agentIdPattern.test(actor.agent) &&
    typeof actor?.user === "string" && discordIdPattern.test(actor.user);
}

export class Access {
  constructor(registry, isAdmin) {
    this.registry = registry;
    this.isAdmin = isAdmin;
  }

  async snapshot(actor) {
    if (!validActor(actor)) throw new ConnectionError("An authenticated Discord agent and requester are required.");
    const policies = [["*", "*", "registry", "create"]];
    if (actor.agent === adminAgent && await this.isAdmin(actor.user)) {
      for (const action of ["manage", "share", "agents"]) policies.push([adminAgent, actor.user, "*", action]);
    }
    for (const row of this.registry.accessRows()) {
      if (row.owner_active && !row.shared) policies.push([row.owner_agent, "*", row.id, "manage"]);
    }
    for (const grant of this.registry.grants()) {
      policies.push([grant.agent, "*", grant.connection, "use"]);
    }
    const enforcer = await newEnforcer(newModelFromString(model));
    await enforcer.addPolicies(policies);
    return {
      can: (resource, action) => enforcer.enforceSync(actor.agent, actor.user, resource, action),
    };
  }
}

export function requireAccess(policy, resource, action) {
  if (!policy.can(resource, action)) throw new ConnectionError("This agent lacks permission for that action.");
}
