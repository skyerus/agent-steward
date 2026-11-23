import { createConnection } from "node:net";

export function unixRequest(path, payload, timeout) {
  return new Promise((resolve, reject) => {
    const socket = createConnection(path);
    socket.setEncoding("utf8");
    socket.setTimeout(timeout, () => socket.destroy(new Error("Local service timed out.")));
    let response = "";
    socket.on("connect", () => socket.write(JSON.stringify(payload) + "\n"));
    socket.on("error", reject);
    socket.on("data", chunk => {
      response += chunk;
      if (response.length > 128_000) socket.destroy(new Error("Local service response exceeded the limit."));
      const end = response.indexOf("\n");
      if (end < 0) return;
      socket.destroy();
      try { resolve(JSON.parse(response.slice(0, end))); } catch (error) { reject(error); }
    });
    socket.on("close", () => reject(new Error("Local service closed before responding.")));
  });
}
