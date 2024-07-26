import { SERVER_URL } from "./constants";

export async function getLatestSlot(): Promise<number> {
  const slotResponse = await fetch(`${SERVER_URL}/latest-slot`).then(
    (response) => response.json(),
  );
  return Number(slotResponse.slot);
}
