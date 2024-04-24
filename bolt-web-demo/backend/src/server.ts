import express from "express";
import { Server } from "socket.io";
import { createServer } from "http";
import { json } from "body-parser";
import { spawn } from "node:child_process";

const SERVER_PORT = 3001;
const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"],
  },
});

// Middleware to parse JSON bodies
app.use(json());

// HTTP endpoint for receiving events via POST requests
app.post("/events", (req, res) => {
  console.log("Received event:", req.body);
  const { message } = req.body;

  if (!message) {
    res.status(400).send("No message provided");
  } else {
    // Broadcast the message to all connected WebSocket clients
    io.emit("new-event", { message, timestamp: new Date().toISOString() });

    res.setHeader("Content-Type", "text/plain");
    res.send("OK");
  }
});

// WebSocket connection handling
io.on("connection", (socket) => {
  console.log("A user connected");

  socket.on("disconnect", () => {
    console.log("User disconnected");
  });
});

// Listen on the specified port
server.listen(SERVER_PORT, () => {
  console.log(`Server is running on http://localhost:${SERVER_PORT}`);
});

async function waitForBeaconClientPort() {
  const waitTimeMs = 2000;
  let attemptsDone = 0;
  const maxAttempts = 20;
  let shouldTryAgain = true;

  while (shouldTryAgain && attemptsDone < maxAttempts) {
    console.log({ attemptsDone, maxAttempts });
    try {
      const kurtosisPort = spawn("kurtosis", [
        "port",
        "print",
        "bolt-devnet",
        "el-1-geth-lighthouse",
        "rpc",
      ]);

      kurtosisPort.stdout.on("data", (data) => {
        console.log(`stdout: ${data}`);
        io.emit("new-event", {
          message: data.toString(),
          timestamp: new Date().toISOString(),
        });
        shouldTryAgain = false;
      });

      kurtosisPort.stderr.on("data", (data) => {
        console.error(`stderr: ${data}`);
      });

      kurtosisPort.on("close", (code) => {
        console.log(`child process exited with code ${code}`);
      });
    } catch (e) {
      console.error(`Error while trying to get the port: ${e}`);
    }

    attemptsDone++;
    await new Promise((resolve) => setTimeout(resolve, waitTimeMs));
  }
}

waitForBeaconClientPort();
