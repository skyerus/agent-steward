import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { registerHooks } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

test("Luna denials explain the failure without minting an integration permit", async t => {
  const dir = mkdtempSync(join(tmpdir(), "sable-review-denial-"));
  const plugin = new URL("./review-plugin.mjs", import.meta.url);
  const dataModule = source => `data:text/javascript,${encodeURIComponent(source)}`;
  const loader = registerHooks({
    resolve(specifier, context, next) {
      if (context.parentURL === plugin.href && specifier === "node:net") {
        return { shortCircuit: true, url: dataModule("export const createConnection = path => globalThis.sableTestReviewSocket(path);") };
      }
      if (specifier === "openclaw/plugin-sdk/session-transcript-runtime") {
        return { shortCircuit: true, url: dataModule("export function readSessionTranscriptVisibleMessageDelta() { return globalThis.sableFixtureTranscript(); }") };
      }
      return next(specifier, context);
    },
  });
  const config = join(dir, "gateway.json");
  process.env.SABLE_REVIEW_GATEWAY_CONFIG = config;
  t.after(() => {
    delete globalThis.sableTestReviewSocket;
    delete globalThis.sableFixtureTranscript;
    delete process.env.SABLE_REVIEW_GATEWAY_CONFIG;
    loader.deregister();
    rmSync(dir, { recursive: true, force: true });
  });

  const permit = "a".repeat(64);
  let issued = 0;
  const savedGrant = { scope: { user: "123456789012345678" }, revision: "verified",
    task: "Schedule a connection listing", conversation: [{ role: "user", text: "List my connections on schedule" }] };
  let scheduleChecks = 0;
  globalThis.sableTestReviewSocket = path => {
    assert.equal(path, "/run/sable-review/permits.sock");
    const socket = new EventEmitter();
    socket.setEncoding = socket.setTimeout = () => {};
    socket.end = body => {
      const action = JSON.parse(body).action;
      if (action === "schedule_run") {
        scheduleChecks++;
        socket.emit("data", JSON.stringify({ ok: true, value: savedGrant }));
      } else {
        if (!action) issued++;
        socket.emit("data", action === "target" ? '{"ok":true}' : permit);
      }
      socket.emit("close");
    };
    queueMicrotask(() => socket.emit("connect"));
    return socket;
  };

  writeFileSync(config, JSON.stringify({
    gateways: { integrations: { bindAddress: "127.0.0.1", port: 17895 } },
    routes: [{
      gateways: ["integrations"],
      backends: [{ mcp: { targets: [{ name: "integrations" }] } }],
      policies: { mcpGuardrails: { processors: [{
        kind: "remote", host: "127.0.0.1:17887", failureMode: "failClosed",
        methods: { "tools/call": "request", "tools/list": "response" },
      }] } },
    }],
  }));
  const { default: register } = await import(plugin);
  const hooks = new Map();
  const logs = [];
  const user = "123456789012345678";
  let reply;
  let reviewInput;
  register({
    config: { mcp: { servers: { integrations: { url: "http://127.0.0.1:17895/mcp" } } } },
    on: (name, hook) => hooks.set(name, hook),
    registerTool() {},
    logger: { info: line => logs.push(line) },
    runtime: {
      config: { current: () => ({ plugins: { entries: { "sable-integration-review": {
        config: { speakers: [user] },
      } } } }) },
      subagent: { complete: async ({ extraSystemPrompt, message }) => {
        assert.match(extraSystemPrompt, /one short sentence explaining the specific mismatch/);
        assert.match(extraSystemPrompt, /review window apply only to review evidence/);
        reviewInput = JSON.parse(message);
        return { text: JSON.stringify(reply) };
      } },
    },
  });

  const ctx = { agentId: "main", senderId: user, runId: "fixture", channelId: "room", messageProvider: "discord" };
  hooks.get("before_prompt_build")({ currentUserMessage: "Look up the account." }, ctx);
  const params = { id: "fixture", revision: 1, agentId: "accounting", review_context_messages: 1 };
  const review = () => hooks.get("before_tool_call")({ toolName: "mcp__integrations__grant_connection_access", params }, ctx);
  reply = {
    allow: false, reason: "missing_authorization",
    explanation: "The requester authorized a lookup but gave no permission to share. 12345678 https://example.test/secret",
  };
  const denied = await review();
  assert.equal(denied.block, true);
  assert.match(denied.blockReason, /gave no permission to share/);
  assert.match(denied.blockReason, /Check the authenticated conversation/);
  assert.doesNotMatch(denied.blockReason, /12345678|example\.test/);
  assert.match(logs.at(-1), /reason=missing_authorization/);
  assert.doesNotMatch(logs.at(-1), /authorized a lookup/);
  assert.equal(issued, 0);

  reply = { allow: false };
  assert.match((await review()).blockReason, /did not provide a specific explanation/);
  reply = { allow: true, explanation: "Unexpected approval field" };
  assert.equal((await review()).block, true);
  assert.equal(issued, 0);

  reply = { allow: true };
  assert.deepEqual((await review()).params, { ...params, __sableReviewPermit: permit });
  assert.equal(issued, 1);

  const jobId = "2e899033-4aef-4b72-96b6-a6cdd3eafaff";
  const sessionKey = "agent:main:discord:channel:123456789012345678";
  const scheduled = { agentId: "main", sandboxed: true, runId: "scheduled-run", sessionKey, trigger: "cron",
    modelProviderId: "anthropic", modelId: "claude-fixture",
    inputProvenance: { kind: "internal_system", sourceTool: "cron_execution", jobId,
      sourceSessionKey: sessionKey, runId: `cron:${jobId}:1795359300000` } };
  hooks.get("before_prompt_build")({}, scheduled);
  const readParams = { review_context_messages: 1 };
  const scheduledRead = await hooks.get("before_tool_call")({
    toolName: "mcp__openclaw__integrations__list_connections", params: readParams,
  }, scheduled);
  assert.equal(scheduledRead.params.__sableReviewPermit, permit);
  assert.equal(scheduleChecks, 2);
  assert.match(logs.at(-1), /Review \[scheduled\] integrations\/list_connections approved/);
  reply = { allow: false, reason: "missing_authorization", explanation: "The job did not authorise sharing." };
  const scheduledWrite = await hooks.get("before_tool_call")({
    toolName: "integrations__grant_connection_access", params,
  }, scheduled);
  assert.equal(scheduledWrite.block, true);
  assert.equal(issued, 2);

  const replyContext = {
    channelId: "discord", senderId: user, accountId: "default", sessionKey,
    messageId: "323456789012345678", replyToId: "223456789012345678",
    replyToBody: "The approved test plan is to check the connected integrations inventory.\nKeep this read-only.",
  };
  const replyTurn = { ...ctx, runId: "native-reply", sessionKey, sessionId: "fixture-session" };
  const transport = { channel: "discord", messageId: replyContext.messageId, replyToId: replyContext.replyToId };
  const transcriptLine = { role: "user", content: "Go ahead with that", __openclaw: {
    runId: replyTurn.runId,
    requesterOrigin: { sessionKey, messageProvider: "discord", senderId: user, accountId: "default" },
    transport,
  } };
  globalThis.sableFixtureTranscript = () => ({ kind: "page", hasMore: false, entries: [
    { message: { ...transcriptLine, content: "A newer but unrelated topic", __openclaw: {
      ...transcriptLine.__openclaw, runId: "prior", transport: { channel: "discord", messageId: "423456789012345678" },
    } } },
    { message: transcriptLine },
  ] });
  hooks.get("before_dispatch")({}, replyContext);
  hooks.get("before_prompt_build")({ currentUserMessage: transcriptLine.content }, replyTurn);
  const reviewReply = () => hooks.get("before_tool_call")({
    toolName: "integrations__list_connections", params: { review_context_messages: 1 },
  }, replyTurn);
  reply = { allow: true };
  await reviewReply();
  assert.deepEqual(reviewInput.conversation.map(({ role, text }) => ({ role, text })), [
    { role: "assistant", text: replyContext.replyToBody },
    { role: "user", text: transcriptLine.content },
  ]);
  assert.match(logs.at(-1), /exact reply targets=1/);

  // A neighbouring reply or caller-provided quotation cannot stand in for an exact transport match.
  for (const mismatch of [
    { ...transport, messageId: "523456789012345678" },
    { ...transport, replyToId: "623456789012345678" },
  ]) {
    transcriptLine.__openclaw.transport = mismatch;
    await reviewReply();
    assert.deepEqual(reviewInput.conversation.map(({ text }) => text), [transcriptLine.content]);
    assert.match(logs.at(-1), /exact reply targets=0/);
  }
});
