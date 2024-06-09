import express from "express";
import morgan from "morgan";
import cors from "cors";
import { createServer } from "http";
import { Server } from "socket.io";
import { json } from "body-parser";

import { DEVNET_ENDPOINTS, getSlot, waitForPort } from "./devnet";
import { EventType } from "./types";
import { logger } from "./logger";

const SERVER_PORT = 3001;
const EVENTS_SET = new Set<string>();
let LATEST_SLOT = 0;

const app = express();
const server = createServer(app);
export const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
});

app.use(json());
app.use(morgan("dev"));
app.use(cors({ origin: "*" }));

// HTTP endpoint for receiving events via POST requests from BOLT components
app.post("/events", (req, res) => {
  logger.info(`Received event: ${JSON.stringify(req.body)}`);
  const { message } = req.body;

  if (!message) {
    console.error("No message provided");
    res.status(400).send("No message provided");
  } else {
    // // Remove time measurements from the message
    // const messageWithoutMeasurements = message.replace(/ in .+$/g, "");
    // // Deduplicate events
    // if (EVENTS_SET.has(messageWithoutMeasurements)) {
    //   console.warn(
    //     "Duplicate event received, discarding:",
    //     messageWithoutMeasurements
    //   );
    //   res.status(200).send("OK");
    //   return;
    // }
    // EVENTS_SET.add(messageWithoutMeasurements);

    // Broadcast the message to all connected WebSocket clients
    io.emit("new-event", { message, timestamp: new Date().toISOString() });

    res.setHeader("Content-Type", "text/plain");
    res.send("OK");
  }
});

// Helper endpoint for re-sending port events to the frontend when necessary
app.get("/retry-port-events", (req, res) => {
  sendDevnetEvents();
  res.send("OK");
});

app.get("/latest-slot", (req, res) => {
  if (!DEVNET_ENDPOINTS[EventType.BEACON_CLIENT_URL_FOUND]) {
    res.status(500).send({ message: "No beacon client URL found" });
    return;
  }

  getSlot(DEVNET_ENDPOINTS[EventType.BEACON_CLIENT_URL_FOUND]).then((slot) => {
    if (slot !== undefined) {
      res.send({ slot });
    } else {
      res.status(500).send("Could not fetch the latest slot");
    }
  });
});

// Endpoint to send a signed preconfirmation transaction to the BOLT MEV sidecar
app.post("/preconfirmation", async (req, res) => {
  const beaconClientUrl = DEVNET_ENDPOINTS[EventType.BEACON_CLIENT_URL_FOUND];
  const mevSidecarUrl = DEVNET_ENDPOINTS[EventType.MEV_SIDECAR_URL_FOUND];
  const providerUrl = DEVNET_ENDPOINTS[EventType.JSONRPC_PROVIDER_URL_FOUND];
  if (!mevSidecarUrl || !providerUrl || !beaconClientUrl) {
    res
      .status(500)
      .send("No MEV sidecar or beacon client or provider URL found");
    return;
  }

  const { slot, tx, signature } = req.body;
  if (!tx || !signature) {
    res.status(400).send("No tx or signature provided");
    return;
  }

  const preconfirmationResponse = await fetch(`http://${mevSidecarUrl}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      id: "1",
      jsonrpc: "2.0",
      method: "bolt_inclusionPreconfirmation",
      params: [{ slot, tx, signature }],
    }),
  }).then((response) => response.json());

  res.setHeader("Content-Type", "application/json");
  res.send({ result: preconfirmationResponse, slot });
});

server.listen(SERVER_PORT, () => {
  logger.info(`Server is running on http://localhost:${SERVER_PORT}`);
});

async function sendDevnetEvents() {
  waitForPort(
    ["cl-1-lighthouse-geth", "http"],
    EventType.BEACON_CLIENT_URL_FOUND
  );

  waitForPort(
    ["el-1-geth-lighthouse", "rpc"],
    EventType.JSONRPC_PROVIDER_URL_FOUND
  );

  waitForPort(["mev-sidecar-api", "api"], EventType.MEV_SIDECAR_URL_FOUND);

  waitForPort(["dora", "http"], EventType.EXPLORER_URL_FOUND);
}

// Send devnet events after a delay to ensure that the frontend is ready to receive them
// if we start the backend after the frontend.
(async () => {
  await new Promise((resolve) => setTimeout(resolve, 2000));
  sendDevnetEvents();
})();

// Poll for the latest slot number
(async () => {
  let beaconClientUrl = DEVNET_ENDPOINTS?.[EventType.BEACON_CLIENT_URL_FOUND];

  while (!beaconClientUrl) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    beaconClientUrl = DEVNET_ENDPOINTS?.[EventType.BEACON_CLIENT_URL_FOUND];
  }

  while (true) {
    LATEST_SLOT = await getSlot(beaconClientUrl);
    io.emit("new-event", {
      type: EventType.NEW_SLOT,
      message: LATEST_SLOT,
      timestamp: new Date().toISOString(),
    });

    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
})();
