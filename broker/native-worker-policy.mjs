import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, join, normalize } from "node:path";

function trustedOwner(stat) {
  return stat.uid === 0n && (stat.mode & 0o022n) === 0n;
}

function trustedReceipt(path) {
  if (!isAbsolute(path) || normalize(path) !== path) return;
  for (let parent = dirname(path); parent !== "/"; parent = dirname(parent)) {
    const entry = lstatSync(parent, { bigint: true });
    if (!entry.isDirectory() || !trustedOwner(entry)) return;
  }
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd, { bigint: true });
    if (!stat.isFile() || !trustedOwner(stat) || stat.size > 4096n) return;
    return JSON.parse(readFileSync(fd, "utf8"));
  } finally {
    closeSync(fd);
  }
}

/** The root supervisor records the socket only after verifying the worker's OS isolation. */
export function approvedNativeWorker(config, agentId, endpoint) {
  const path = process.env.SABLE_NATIVE_WORKER_RECEIPT;
  if (!path || !agentId || typeof process.getuid !== "function") return;
  try {
    const worker = trustedReceipt(path);
    const entry = config.agents?.entries?.[agentId];
    const server = config.plugins?.entries?.codex?.config?.appServer;
    if (!entry || !worker || !/^[a-z][a-z0-9_-]{0,62}$/.test(agentId)) return;
    const workspace = worker.version === 2 && isAbsolute(worker.workspaceRoot) &&
      normalize(worker.workspaceRoot) === worker.workspaceRoot
      ? join(worker.workspaceRoot, agentId)
      : worker.version === 1 && worker.agentId === agentId ? worker.workspace : undefined;
    const unix = server?.transport === "unix" && server.url === `unix://${worker.socket}`;
    const proxy = worker.version === 2 && server?.transport === "stdio" &&
      worker.socket === "/run/sable-native-policy/app.sock" &&
      server.command === "/opt/sable/node/bin/node" &&
      server.args?.length === 1 && server.args[0] === "/usr/local/libexec/sable-native/app-server-stdio.mjs" &&
      trustedOwner(lstatSync(server.args[0], { bigint: true }));
    if (!workspace || entry.workspace !== workspace || !isAbsolute(workspace) ||
        normalize(workspace) !== workspace || !isAbsolute(worker.socket) ||
        normalize(worker.socket) !== worker.socket || (!unix && !proxy) ||
        config.tools?.exec?.host !== "sandbox" || config.tools?.elevated?.enabled !== false ||
        (entry.tools?.exec?.host && entry.tools.exec.host !== "sandbox") ||
        !Number.isSafeInteger(worker.uid) || worker.uid <= 0 || worker.uid === process.getuid()) return;
    if (endpoint && (!worker.mcpEndpoints || !Object.hasOwn(worker.mcpEndpoints, endpoint.service) ||
        worker.mcpEndpoints[endpoint.service] !== endpoint.url)) return;
    if (worker.version === 2) {
      const root = lstatSync(worker.workspaceRoot, { bigint: true });
      const directory = lstatSync(workspace, { bigint: true });
      if (!root.isDirectory() || !trustedOwner(root) ||
          !directory.isDirectory() || directory.uid !== BigInt(worker.uid) ||
          (directory.mode & 0o002n) !== 0n) return;
    }
    const socketPath = worker.version === 2 ? worker.socketTarget : worker.socket;
    if (!isAbsolute(socketPath) || normalize(socketPath) !== socketPath ||
        (worker.version === 2 && realpathSync(worker.socket) !== socketPath)) return;
    const socket = lstatSync(socketPath, { bigint: true });
    if (!socket.isSocket() || socket.uid !== BigInt(worker.uid) || (socket.mode & 0o007n) !== 0n ||
        String(socket.dev) !== worker.device || String(socket.ino) !== worker.inode ||
        String(socket.ctimeNs) !== worker.changedAt) return;
    return `${worker.socket}:${worker.device}:${worker.inode}:${worker.uid}`;
  } catch {
    return undefined;
  }
}
