import { TransactionRequest, keccak256 } from "ethers";
import { ethers } from "ethers";
import { KURTOSIS_CHAIN_ID, SERVER_URL } from "./constants";

type InclusionRequestPayload = {
  slot: number;
  tx: string;
  signature: string;
};

export async function createPreconfPayload(
  wallet: ethers.Wallet,
  nonce: number,
): Promise<{ payload: InclusionRequestPayload; txHash: string }> {
  // Define the transaction
  const tx: TransactionRequest = {
    chainId: KURTOSIS_CHAIN_ID,
    nonce: nonce,
    from: await wallet.getAddress(),
    to: "0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD",
    value: ethers.parseEther("0.0069420"),
    maxFeePerGas: ethers.parseUnits("200", "gwei"),
    maxPriorityFeePerGas: ethers.parseUnits("30", "gwei"),
    data: "0xdeadbeef",
  };

  const estimatedGas = await wallet.estimateGas(tx);
  tx.gasLimit = estimatedGas;

  const populated = await wallet.populateCall(tx);
  const signedTx = await wallet.signTransaction(populated);
  const txHash = keccak256(signedTx);
  const slot = (await getLatestSlot()) + 2;

  // Create a signature over the request fields "slot" and "tx" using the same signer
  // to authenticate the preconfirmation request through bolt.
  const slotBytes = numberToLittleEndianBytes(slot);
  const txHashBytes = hexToBytes(txHash);
  const message = new Uint8Array(slotBytes.length + txHashBytes.length);
  message.set(slotBytes);
  message.set(txHashBytes, slotBytes.length);

  const messageDigest = keccak256(message);
  const signature = wallet.signingKey.sign(messageDigest).serialized;

  return { payload: { slot, tx: signedTx, signature }, txHash };
}

export async function getLatestSlot(): Promise<number> {
  const slotResponse = await fetch(`${SERVER_URL}/latest-slot`).then(
    (response) => response.json(),
  );
  return Number(slotResponse.slot);
}

// Function to convert a number to a little-endian byte array
function numberToLittleEndianBytes(num: number): Uint8Array {
  const buffer = new ArrayBuffer(8); // Assuming slot_number is a 64-bit integer
  const view = new DataView(buffer);
  view.setUint32(0, num, true); // true for little-endian
  return new Uint8Array(buffer);
}

// Function to decode a hex string to a byte array
function hexToBytes(hex: string): Uint8Array {
  hex = hex.replace(/^0x/, ""); // Remove "0x" prefix if present
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}
