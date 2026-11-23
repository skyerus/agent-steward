const toolName = "manage_schedule";
const actions = ["list", "get", "create", "update", "remove"];
const text = (description) => ({ type: "string", description });

export function registerScheduleTool(api, resolveTurn, conversationFor, rpc, nativeWorkerFor = () => undefined) {
  api.registerTool({ contextVersion: 2, create: (ctx) => ({
    name: toolName,
    label: "Scheduled work",
    description: "Create and manage this Discord conversation's OpenClaw schedules. A job wakes this agent in the same sandbox. For one-time work provide at. For recurring work provide cron and timezone. Integration actions in a run still require Luna review against the saved Discord request.",
    catalogMode: "direct-only",
    parameters: {
      type: "object", additionalProperties: false, required: ["action"],
      properties: {
        action: { type: "string", enum: actions },
        id: text("Job ID from list."),
        name: text("Short display name."),
        task: text("What this agent should do when the job runs."),
        at: text("One-time ISO 8601 timestamp with timezone."),
        cron: text("Five-field cron expression for recurring work."),
        timezone: text("IANA timezone for cron schedules."),
        enabled: { type: "boolean", description: "Set false to pause a job." },
        keepAfterRun: { type: "boolean", description: "Create only. Retain a one-time job after it completes." },
        review_context_messages: { type: "integer", minimum: 1, description: "For create and task edits, include the original request and any clarifications in this many recent verified messages." },
      },
    },
    async execute(_id, argumentsValue, signal) {
      ctx.assertInvocationCurrent();
      const turn = resolveTurn(ctx.runId);
      const nativeWorker = ctx.sandboxed ? undefined : nativeWorkerFor(ctx.agentId);
      if ((ctx.sandboxed !== true && !nativeWorker) || !turn || turn.agentId !== ctx.agentId || turn.sessionKey !== ctx.sessionKey ||
          (nativeWorker && turn.nativeWorker !== nativeWorker)) {
        throw new Error("Manage schedules from an authorised Discord conversation with an active sandbox.");
      }
      const { action, review_context_messages: window, ...args } = argumentsValue;
      if (!actions.includes(action)) throw new Error("Choose an advertised schedule action.");
      const workSignal = AbortSignal.any([AbortSignal.timeout(36000), ...(signal ? [signal] : [])]);
      let conversation;
      if (action === "create" || (action === "update" && Object.hasOwn(args, "task"))) {
        if (!Number.isSafeInteger(window) || window < 1) throw new Error("Choose the verified message window for this task.");
        conversation = await conversationFor(turn, window, workSignal);
      }
      ctx.assertInvocationCurrent();
      if (resolveTurn(ctx.runId) !== turn || (nativeWorker && nativeWorkerFor(ctx.agentId) !== nativeWorker)) {
        throw new Error("The Discord turn or its execution boundary changed before the schedule request.");
      }
      const scope = { agent: turn.agentId, user: turn.senderId, account: turn.accountId,
        channel: turn.channel, session: turn.sessionKey, surface: turn.surface };
      const payload = await rpc({ action: "schedule", actor: { agent: scope.agent, user: scope.user },
        request: { action, args, scope, ...(conversation && { conversation }),
          ...(nativeWorker && { inheritLocalTools: true }) } }, workSignal, 34000, 65536);
      const reply = JSON.parse(payload);
      if (!reply.ok) throw new Error(reply.inputError ?? "The schedule broker did not confirm that request.");
      return { content: [{ type: "text", text: JSON.stringify(reply.value) }], details: reply.value };
    },
  }) }, { name: toolName, optional: true, workspaceAccess: false });
}

export function nativeScheduleRun(ctx, nativeWorker) {
  const proof = ctx.inputProvenance;
  if (proof?.kind !== "internal_system" || proof.sourceTool !== "cron_execution" || (ctx.sandboxed !== true && !nativeWorker) ||
      !ctx.agentId || !ctx.sessionKey || proof.sourceSessionKey !== ctx.sessionKey || typeof proof.runId !== "string" ||
      !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(proof.jobId ?? "")) return;
  const split = proof.runId.split(":");
  if (split.length !== 3 || split[0] !== "cron" || split[1] !== proof.jobId || !/^\d{13}$/.test(split[2])) return;
  return { scope: { agent: ctx.agentId, session: ctx.sessionKey }, args: { id: proof.jobId, startedAt: Number(split[2]) } };
}
