"use client";

import io from "socket.io-client";
import { useState, useEffect } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { createAndSignTransaction } from "@/lib/wallet";
import { EventType } from "@/lib/types";

type Event = { message: string; type?: EventType; timestamp: string };

export default function Home() {
  const [events, setEvents] = useState<Array<Event>>([]);

  const [preconfSent, setPreconfSent] = useState<boolean>(false);
  const [timerActive, setTimerActive] = useState<boolean>(false);
  const [time, setTime] = useState(0);

  const [beaconClientUrl, setBeaconClientUrl] = useState<string>("");
  const [providerUrl, setProviderUrl] = useState<string>("");
  const [explorerUrl, setExplorerUrl] = useState<string>("");

  const SERVER_URL = "http://localhost:3001";

  useEffect(() => {
    const newSocket = io(SERVER_URL, { autoConnect: true });

    newSocket.on("new-event", (event: Event) => {
      console.log("Event from server:", event);

      // If the event has a special type, handle it differently
      // and return early
      switch (event.type) {
        case EventType.BEACON_CLIENT_URL_FOUND:
          setBeaconClientUrl(event.message);
          return;
        case EventType.JSONRPC_PROVIDER_URL_FOUND:
          setProviderUrl(event.message);
          return;
        case EventType.EXPLORER_URL_FOUND:
          setExplorerUrl(event.message);
        case EventType.MEV_SIDECAR_URL_FOUND:
          return;
        default:
          break;
      }

      if (
        event.message.includes("preconfirmation proof verified for tx hash")
      ) {
        const txHash = event.message.match(/0x[a-fA-F0-9]{64}/g);
        new Promise((_) =>
          setTimeout(() => {
            const event: Event = {
              message: `Preconfirmation ${txHash} available here: ${explorerUrl}/tx/${txHash}`,
              timestamp: new Date().toISOString(),
            };
            setEvents((prev) => [event, ...prev]);
          }, 1000)
        );
      }

      setEvents((prev) => [event, ...prev]);
    });

    return () => {
      newSocket.close();
    };
  }, [explorerUrl]);

  useEffect(() => {
    let interval: any = null;

    if (timerActive) {
      interval = setInterval(() => {
        setTime((prev) => prev + 2);
      }, 2);
    } else {
      clearInterval(interval);
    }

    return () => clearInterval(interval);
  }, [timerActive]);

  async function sendPreconfirmation() {
    setEvents([]);
    setPreconfSent(true);
    try {
      const { signedTx, txHash } = await createAndSignTransaction(providerUrl);
      console.log("signedTx", signedTx);

      // 1. POST preconfirmation.
      // The preconfirmation is considered valid as soon as the server responds with a 200 status code.
      setTime(0);
      setTimerActive(true);
      const res = await fetch("http://localhost:3001/preconfirmation", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ signedTx, txHash }),
      });
      if (res.status === 200) {
        console.log("Preconfirmation successful");
        setTimerActive(false);
      }

      const json = await res.json();
      const { result, slot } = json;

      console.log("preconf result", result);
      console.log("slot", slot);
    } catch (e) {
      console.error(e);
    }
  }

  return (
    <main className="flex min-h-screen flex-col items-center p-24">
      <div className="w-full max-w-5xl items-center justify-between lg:flex">
        <h1 className="font-mono text-2xl font-bold">BOLT</h1>

        <p>Your friendly preconfirmation companion.</p>
      </div>

      {beaconClientUrl && providerUrl ? (
        <div className="w-full max-w-5xl pt-4">
          <div className="grid gap-3 border p-4 border-gray-800">
            <p className="text-lg">Step 1: send a transaction</p>
            <small className="text-sm max-w-3xl">
              By clicking this button you will create a transaction and send it
              as a preconfirmation request to the BOLT sidecar of the next
              proposer in line. This transaction is crafted from a pre-funded
              account in the devnet for demo purposes.
            </small>

            <div className="flex flex-col items-center">
              <Button
                className="max-w-sm"
                onClick={() => sendPreconfirmation()}
              >
                Send Preconfirmation
              </Button>
            </div>
          </div>

          {preconfSent && (
            <div className="grid gap-3 border p-4 border-gray-800 mt-4">
              <p className="text-lg">
                Step 2: wait for a cryptoeconomic preconfirmation
              </p>
              <small className="text-sm max-w-3xl">
                The transaction will be processed by BOLT and you will receive a
                preconfirmation for inclusion in the next block.
              </small>

              <div>
                <p>
                  Waiting for preconfirmation. Time elapsed: <b>{time}</b>ms
                </p>
              </div>
            </div>
          )}

          <div className="grid gap-3 border p-4 border-gray-800 mt-4">
            <p className="text-lg">Event logs</p>
            <small className="text-sm max-w-3xl">
              This is the list of events received from the server.
            </small>

            <ScrollArea className="max-h-80">
              <ul className="font-mono">
                {events.map((message, index) => (
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
      ) : (
        <div className="w-full max-w-5xl pt-4">
          <div className="grid gap-3 border p-4 border-gray-800">
            <p className="text-lg">
              Waiting for the devnet servers to start...
            </p>
            <small className="text-sm max-w-3xl">
              This page will automatically update when the servers are ready.
            </small>

            <div className="flex w-full justify-center">
              <Button
                className="max-w-sm"
                onClick={() => {
                  fetch("http://localhost:3001/retry-port-events");
                }}
              >
                Refresh manually
              </Button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}

function parseDateToMs(date: any) {
  return new Date(date).toISOString().split("T")[1].split("Z")[0];
}
