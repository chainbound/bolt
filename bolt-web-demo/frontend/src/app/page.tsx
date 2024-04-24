"use client";

import { Button } from "@/components/ui/button";
import { useState, useEffect } from "react";
import io from "socket.io-client";

export default function Home() {
  const [messages, setMessages] = useState<Array<any>>([]);

  useEffect(() => {
    const newSocket = io("http://localhost:3001", { autoConnect: true });

    newSocket.on("new-event", (message) => {
      console.log("Message from server:", message);
      setMessages((prev) => [...prev, message]);
    });

    return () => {
      newSocket.close();
    };
  }, []);

  return (
    <main className="flex min-h-screen flex-col items-center p-24">
      <div className="w-full max-w-5xl items-center justify-between lg:flex">
        <h1 className="font-mono text-2xl font-bold">BOLT</h1>

        <p>Your friendly preconfirmation companion.</p>
      </div>

      <div className="w-full max-w-5xl pt-8">
        <div className="grid gap-3 border p-4 border-gray-800">
          <p className="text-lg">Step 1: send a transaction</p>
          <small className="text-sm max-w-2xl">
            By clicking this button you will create a transaction and send it as
            a preconfirmation request to the BOLT sidecar of the next proposer
            in line:
          </small>
          <Button className="max-w-sm">Send</Button>

          <div>
            <h1>Messages from WebSocket</h1>
            <ul>
              {messages.map((message, index) => (
                <li key={index}>{message}</li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </main>
  );
}
