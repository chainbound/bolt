"use client";

import io from "socket.io-client";
import Image from "next/image";
import { useState, useEffect } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { createPreconfPayload } from "@/lib/wallet";
import { EventType } from "@/lib/types";
import { Progress } from "@/components/ui/progress";

type Event = {
  message: string;
  type?: EventType;
  timestamp: string;
  link?: string;
};

export const SERVER_URL = "http://localhost:3001";

export default function Home() {
  const [events, setEvents] = useState<Array<Event>>([]);

  const [preconfSent, setPreconfSent] = useState<boolean>(false);
  const [preconfSlot, setPreconfSlot] = useState<number>(-1);
  const [preconfIncluded, setPreconfIncluded] = useState<boolean>(false);

  const [timerActive, setTimerActive] = useState<boolean>(false);
  const [time, setTime] = useState(0);

  const [newSlotNumber, setNewSlotNumber] = useState<number>(-1);
  const [beaconClientUrl, setBeaconClientUrl] = useState<string>("");
  const [providerUrl, setProviderUrl] = useState<string>("");
  const [explorerUrl, setExplorerUrl] = useState<string>("");

  useEffect(() => {
    fetch(`${SERVER_URL}/retry-port-events`);
    fetch(`${SERVER_URL}/latest-slot`)
      .then((res) => res.json())
      .then((data) => setNewSlotNumber(data.slot));
  }, []);

  useEffect(() => {
    const newSocket = io(SERVER_URL, { autoConnect: true });

    newSocket.on("new-event", (event: Event) => {
      console.debug("Event from server:", event);

      // If the event has a special type, handle it differently
      switch (event.type) {
        case EventType.BEACON_CLIENT_URL_FOUND:
          console.info("Beacon client URL found:", event.message);
          setBeaconClientUrl(event.message);
          return;
        case EventType.JSONRPC_PROVIDER_URL_FOUND:
          console.info("Provider URL found:", event.message);
          setProviderUrl(event.message);
          return;
        case EventType.EXPLORER_URL_FOUND:
          console.info("Explorer URL found:", event.message);
          setExplorerUrl(event.message);
        case EventType.MEV_SIDECAR_URL_FOUND:
          console.info("MEV sidecar URL found:", event.message);
          return;
        case EventType.NEW_SLOT:
          setNewSlotNumber(Number(event.message));
          return;
        default:
          break;
      }

      setEvents((prev) => [event, ...prev]);

      // If the event is a preconfirmation, extract the tx hash and slot number
      // and display a message with the explorer URL
      if (
        event.message.toLowerCase().includes("verified merkle proof for tx")
      ) {
        setPreconfIncluded(true);
        dispatchEvent({
          message: `Preconfirmed transaction included at slot ${preconfSlot}`,
          link: `${explorerUrl}/slot/${preconfSlot}`,
          timestamp: new Date().toISOString(),
        });
      }
    });

    return () => {
      newSocket.close();
    };
  }, [explorerUrl, preconfSlot]);

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
    // Reset state
    setEvents([]);
    setPreconfSent(true);
    setPreconfIncluded(false);

    try {
      const { payload, txHash } = await createPreconfPayload(providerUrl);
      setPreconfSlot(payload.slot);
      dispatchEvent({
        message: `Preconfirmation request sent for tx: ${txHash} at slot ${payload.slot}`,
        timestamp: new Date().toISOString(),
      });

      // 1. POST preconfirmation.
      // The preconfirmation is considered valid as soon as the server responds with a 200 status code.
      setTime(0);
      setTimerActive(true);
      const res = await fetch(`${SERVER_URL}/preconfirmation`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.status === 200) {
        console.log("Preconfirmation successful");
        setTimerActive(false);
      }
    } catch (e) {
      console.error(e);
    }
  }

  function dispatchEvent(event: Event) {
    setEvents((prev) => [event, ...prev]);
  }

  return (
    <main className="flex min-h-screen flex-col items-center p-24">
      <div className="w-full max-w-6xl items-center justify-between lg:flex">
        <Image src="/bolt-logo.png" alt="BOLT" width={100} height={100} />

        <div className="flex items-center gap-2.5 mt-2">
          <p>
            Powered by{" "}
            <a
              href="https://www.chainbound.io"
              target="_blank"
              rel="noreferrer"
              className="underline underline-offset-1 decoration-dotted decoration-slate-700 cursor-pointer"
            >
              Chainbound
            </a>
          </p>
          <Image
            src="/chainbound-logo.svg"
            alt="chainbound"
            width={20}
            height={20}
          />
          <p>– v0.1.0</p>
        </div>
      </div>

      {newSlotNumber < 128 ? (
        <>
          {newSlotNumber === -1 ? (
            <div className="w-full max-w-6xl pt-4">
              <p className="text-center pt-10">Loading...</p>
            </div>
          ) : (
            <div className="w-full max-w-6xl pt-4">
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
        <div className="w-full max-w-6xl pt-4">
          {beaconClientUrl && providerUrl ? (
            <div className="w-full">
              <div className="grid gap-3 border p-4 border-gray-800">
                <p className="text-lg">Step 1: send a transaction</p>
                <small className="text-sm">
                  By clicking this button you will create a transaction and send
                  it as a preconfirmation request to the BOLT sidecar of the
                  next proposer in line. <br />
                  This transaction is crafted from a pre-funded account in the
                  devnet for demo purposes.
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
                        {message.message.toString()}
                        {message.link && (
                          <a
                            href={message.link}
                            target="_blank"
                            rel="noreferrer"
                            className="text-blue-500"
                          >
                            {" "}
                            [link]
                          </a>
                        )}
                      </li>
                    ))}
                  </ul>
                </ScrollArea>
              </div>
            </div>
          ) : (
            <div className="w-full max-w-6xl pt-4">
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

      <div className="w-full max-w-6xl pt-4">
        <div className="grid gap-3 p-4 border border-gray-800">
          <p className="text-lg">Disclaimer</p>
          <small className="text-sm">
            This demo application showcases the BOLT protocol happy-case.
            <br />
            Real-world deployments should consider the following missing
            components and features (which are under development):
            <ul className="list-disc list-inside ml-3 mt-1">
              <li>Automatic safety & liveness fault detection</li>
              <li>On-chain dispute logic to verifiably attribute faults</li>
              <li>BOLT RPC server proxy integration</li>
              <li>
                High network participation (at least 1 proposer opted-in in the
                lookahead window)
              </li>
            </ul>
          </small>
        </div>
      </div>
    </main>
  );
}

function parseDateToMs(date: any) {
  return new Date(date).toISOString().split("T")[1].split("Z")[0];
}
