import http from "node:http";

import { WebSocketServer } from "ws";

import { getRelay } from "../src/server/relay.js";

const server = http.createServer((req, res) => getRelay().handle(req, res));
const wss = new WebSocketServer({ noServer: true });

server.on("upgrade", (req, socket, head) => {
  try {
    getRelay().handleUpgrade(req, socket, head, wss);
  } catch {
    socket.destroy();
  }
});

export default server;
