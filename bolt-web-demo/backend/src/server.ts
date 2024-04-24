import express from "express";
import { Server } from "socket.io";
import { createServer } from "http";
import { json } from "body-parser";

const PORT = 3001;
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
    io.emit("new-event", message);

    res.setHeader("Content-Type", "text/plain");
    res.send("OK, Event sent to all clients");
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
server.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
