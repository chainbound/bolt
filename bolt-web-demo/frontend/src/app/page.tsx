"use client";

import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useState, useEffect } from "react";
import io from "socket.io-client";

export default function Home() {
  const [messages, setMessages] = useState<Array<any>>([]);
  const [timerActive, setTimerActive] = useState<boolean>(false);
  const [time, setTime] = useState(0);

  useEffect(() => {
    const newSocket = io("http://localhost:3001", { autoConnect: true });

    newSocket.on("new-event", (message) => {
      console.log("Message from server:", message);
      setMessages((prev) => [message, ...prev]);
    });

    return () => {
      newSocket.close();
    };
  }, []);

  useEffect(() => {
    let interval: any = null;

    if (timerActive) {
      interval = setInterval(() => {
        setTime((prev) => prev + 10);
      }, 10);
    } else {
      clearInterval(interval);
    }

    return () => clearInterval(interval);
  }, [timerActive]);

  return (
    <main className="flex min-h-screen flex-col items-center p-24">
      <div className="w-full max-w-5xl items-center justify-between lg:flex">
        <h1 className="font-mono text-2xl font-bold">BOLT</h1>

        <p>Your friendly preconfirmation companion.</p>
      </div>

      <div className="w-full max-w-5xl pt-4">
        <div className="grid gap-3 border p-4 border-gray-800">
          <p className="text-lg">Step 1: send a transaction</p>
          <small className="text-sm max-w-3xl">
            By clicking this button you will create a transaction and send it as
            a preconfirmation request to the BOLT sidecar of the next proposer
            in line. This transaction is crafted from a pre-funded account in
            the devnet for demo purposes.
          </small>

          <div className="flex flex-col items-center">
            <Button
              className="max-w-sm"
              onClick={async () => {
                // 0. fetch slot number

                // 1. POST preconfirmation
                try {
                  const res = await fetch("http://localhost:9061", {
                    method: "POST",
                    headers: {
                      "Content-Type": "application/json",
                    },
                    body: JSON.stringify({
                      id: "1",
                      jsonrpc: "2.0",
                      method: "eth_requestPreconfirmation",
                      params: [
                        {
                          slot: 1,
                          txHash: "0x1234",
                          rawTx: "0x1234",
                        },
                      ],
                    }),
                  }).then((res) => res.json());

                  console.log("res", res);
                } catch (e) {
                  console.error(e);
                }

                // 2. start timer to wait for confirmation from BOLT
                setTimerActive(true);
                setTime(0);
              }}
            >
              Send Preconfirmation
            </Button>
          </div>
        </div>

        <div className="grid gap-3 border p-4 border-gray-800 mt-4">
          <p className="text-lg">
            Step 2: wait for a cryptoeconomic preconfirmation
          </p>
          <small className="text-sm max-w-3xl">
            The transaction will be processed by BOLT and you will receive a
            preconfirmation for inclusion in the next block.
          </small>

          {timerActive && (
            <div>
              <p>
                Waiting for preconfirmation. Time elapsed: <b>{time}</b>ms
              </p>
            </div>
          )}
        </div>

        <div className="grid gap-3 border p-4 border-gray-800 mt-4">
          <p className="text-lg">Event logs</p>
          <small className="text-sm max-w-3xl">
            This is the list of events received from the server.
          </small>

          <ScrollArea className="max-h-80">
            <ul className="font-mono">
              {messages.map((message, index) => (
                <li key={index}>
                  <span>{parseDateToMs(message.timestamp)}</span>
                  {" | "}
                  {JSON.stringify(message.message)}
                </li>
              ))}
            </ul>
          </ScrollArea>
        </div>
      </div>
    </main>
  );
}

function parseDateToMs(date: any) {
  return new Date(date).toISOString().split("T")[1].split("Z")[0];
}
