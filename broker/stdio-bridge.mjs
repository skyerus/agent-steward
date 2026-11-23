import { createConnection } from "node:net";
import process from "node:process";

const socket = createConnection("/run/sable-connection-broker.sock");
socket.on("connect", () => {
  socket.write(`${process.argv[2]}\n`);
  process.stdin.pipe(socket);
  socket.pipe(process.stdout);
});
socket.on("close", hadError => {
  process.stdin.pause();
  process.exitCode = hadError ? 1 : 0;
});
socket.on("error", () => { process.exitCode = 1; });
