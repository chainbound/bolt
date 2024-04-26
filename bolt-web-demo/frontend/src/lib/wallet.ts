import { TransactionRequest, keccak256 } from "ethers";
import { ethers } from "ethers";

// Test private key, for which address[0] holds 1000 ETH in the Kurtosis devnet
const PRIVATE_KEY =
  "bcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31";

export async function createAndSignTransaction(
  providerUrl: string,
  toAddress?: string,
  amount?: string
): Promise<{
  signedTx: string;
  txHash: string;
}> {
  // Create a Wallet instance from a private key
  const provider = new ethers.JsonRpcProvider(providerUrl);
  const wallet = new ethers.Wallet(PRIVATE_KEY, provider);

  // Define the transaction
  const tx: TransactionRequest = {
    to: toAddress || wallet.address,
    value: ethers.parseEther(amount || "1"),
    gasLimit: 21000,
  };

  const signedTx = await wallet.signTransaction(tx);
  const txHash = keccak256(signedTx);

  return { signedTx, txHash };
}
