"use client";

import io from "socket.io-client";
import Image from "next/image";
import { useState, useEffect, useCallback } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { createAndSignTransaction } from "@/lib/wallet";
import { EventType } from "@/lib/types";
import { Progress } from "@/components/ui/progress";

type Event = { message: string; type?: EventType; timestamp: string };

export default function Home() {
  const [events, setEvents] = useState<Array<Event>>([]);

  const [preconfSent, setPreconfSent] = useState<boolean>(false);
  const [timerActive, setTimerActive] = useState<boolean>(false);
  const [time, setTime] = useState(0);

  const [newSlotNumber, setNewSlotNumber] = useState<number>(-1);
  const [beaconClientUrl, setBeaconClientUrl] = useState<string>("");
  const [providerUrl, setProviderUrl] = useState<string>("");
  const [explorerUrl, setExplorerUrl] = useState<string>("");

  const SERVER_URL = "http://localhost:3001";

  useEffect(() => {
    fetch(`${SERVER_URL}/retry-port-events`);
    fetch(`${SERVER_URL}/latest-slot`)
      .then((res) => res.json())
      .then((data) => setNewSlotNumber(data.slot));
  }, []);

  useEffect(() => {
    const newSocket = io(SERVER_URL, { autoConnect: true });

    newSocket.on("new-event", (event: Event) => {
      console.log("Event from server:", event);

      // If the event has a special type, handle it differently
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
        case EventType.NEW_SLOT:
          setNewSlotNumber(Number(event.message));
          return;
        default:
          break;
      }

      if (
        event.message
          .toLowerCase()
          .includes("preconfirmation proof verified for tx hash")
      ) {
        const txHash = event.message.match(/0x[a-fA-F0-9]{64}/g);
        const slot = event.message
          .match(/slot \d+/g)
          ?.toString()
          .match(/\d+/g)
          ?.toString();

        new Promise((_) =>
          setTimeout(() => {
            const event: Event = {
              message: `Preconfirmation ${txHash} available here: ${explorerUrl}/slot/${slot}`,
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

  const sendPreconfirmation = useCallback(
    async function () {
      setEvents([]);
      setPreconfSent(true);
      try {
        const { signedTx, txHash } = await createAndSignTransaction(
          providerUrl
        );

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
      } catch (e) {
        console.error(e);
      }
    },
    [providerUrl]
  );

  return (
    <main className="flex min-h-screen flex-col items-center p-24">
      <div className="w-full max-w-5xl items-center justify-between lg:flex">
        <Image src="/bolt-logo.png" alt="BOLT" width={100} height={100} />

        <p>Your friendly preconfirmation companion.</p>
      </div>

      {newSlotNumber < 128 ? (
        <>
          {newSlotNumber === -1 ? (
            <div className="w-full max-w-5xl pt-4">
              <p className="text-center pt-10">Loading...</p>
            </div>
          ) : (
            <div className="w-full max-w-5xl pt-4">
              <div className="grid gap-3 border p-4 border-gray-800">
                <p className="text-lg">
                  MEV Boost is not active yet, please wait
                </p>
                <small className="text-sm max-w-3xl">
                  MEV-Boost takes 4 epochs to activate on the Kurtosis devnet.
                  Please wait a few minutes for it to activate.
                </small>

                <Progress value={(newSlotNumber / 128) * 100} />
              </div>
            </div>
          )}
        </>
      ) : (
        <div className="w-full max-w-5xl pt-4">
          {beaconClientUrl && providerUrl ? (
            <div className="w-full">
              <div className="grid gap-3 border p-4 border-gray-800">
                <p className="text-lg">Step 1: send a transaction</p>
                <small className="text-sm max-w-3xl">
                  By clicking this button you will create a transaction and send
                  it as a preconfirmation request to the BOLT sidecar of the
                  next proposer in line. This transaction is crafted from a
                  pre-funded account in the devnet for demo purposes.
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
                    The transaction will be processed by BOLT and you will
                    receive a preconfirmation for inclusion in the next block.
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
                  <ul className="font-mono text-sm">
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
                  This page will automatically update when the servers are
                  ready.
                </small>

                <div className="flex w-full justify-center">
                  <Button
                    className="max-w-sm"
                    onClick={() => fetch(`${SERVER_URL}/retry-port-events`)}
                  >
                    Refresh manually
                  </Button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </main>
  );
}

function parseDateToMs(date: any) {
  return new Date(date).toISOString().split("T")[1].split("Z")[0];
}
