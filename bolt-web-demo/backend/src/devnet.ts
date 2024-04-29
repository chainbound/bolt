import { logger } from "./logger";
import { io } from "./server";
import { EventType } from "./types";
import { spawn } from "child_process";

// In-memory cache for devnet endpoints. Each time the devnet is restarted,
// endpoints will change according to kurtosis random port assignments.
export let DEVNET_ENDPOINTS: { [key: string]: string } = {};

export async function waitForPort(
  kurtosisArgs: string[],
  eventType: EventType
) {
  const waitTimeMs = 2000;
  let attemptsDone = 0;
  const maxAttempts = 20;
  let shouldTryAgain = true;

  while (shouldTryAgain && attemptsDone < maxAttempts) {
    logger.debug(
      `Attempts done for ${eventType}: ${attemptsDone}; maxAttempts: ${maxAttempts}`
    );
    try {
      const kurtosisPort = spawn("kurtosis", [
        "port",
        "print",
        "bolt-devnet",
        ...kurtosisArgs,
      ]);

      kurtosisPort.stdout.on("data", (data) => {
        logger.info(`Event ${eventType} occurred: ${data}`);
        if (data.toString().includes("WARN")) {
          logger.debug("skipping warn message from kurtosis");
          return;
        }

        DEVNET_ENDPOINTS[eventType] = data.toString().replace(/\n/g, "");

        io.emit("new-event", {
          type: eventType,
          message: data.toString().replace(/\n/g, ""),
          timestamp: new Date().toISOString(),
        });
        shouldTryAgain = false;
      });

      kurtosisPort.stderr.on("data", (data) => {
        if (attemptsDone === maxAttempts - 1) {
          logger.error(`stderr: ${data}`);
        }
      });

      kurtosisPort.on("close", (code) => {
        logger.debug(`child process exited with code ${code}`);
      });
    } catch (e) {
      logger.error(`Error while trying to get the port: ${e}`);
    }

    attemptsDone++;
    await new Promise((resolve) => setTimeout(resolve, waitTimeMs));
  }
}

export async function getSlot(beaconClientUrl: string): Promise<number> {
  const slotResponse = await fetch(
    `${beaconClientUrl}/eth/v1/beacon/headers/head`,
    { mode: "no-cors" }
  ).then((response) => response.json());

  return Number(slotResponse.data.header.message.slot);
}
