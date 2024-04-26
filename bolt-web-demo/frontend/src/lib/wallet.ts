import { TransactionRequest, keccak256 } from "ethers";
import { ethers } from "ethers";

// Test private key, for which address[0] holds 1000 ETH in the Kurtosis devnet
const PRIVATE_KEY =
  "bcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31";

export async function createAndSignTransaction(providerUrl: string): Promise<{
  signedTx: string;
  txHash: string;
}> {
  // Create a Wallet instance from a private key
  const provider = new ethers.JsonRpcProvider(providerUrl);
  const wallet = new ethers.Wallet(PRIVATE_KEY, provider);

  // Define the transaction
  const tx: TransactionRequest = {
    chainId: (await provider.getNetwork()).chainId,
    nonce: await wallet.getNonce(),
    from: await wallet.getAddress(),
    to: "0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD",
    value: ethers.parseEther("0.0069420"),
    maxFeePerGas: ethers.parseUnits("20", "gwei"),
    maxPriorityFeePerGas: ethers.parseUnits("3", "gwei"),
    data: "0x",
  };

  const estimatedGas = await wallet.estimateGas(tx);
  tx.gasLimit = estimatedGas;

  const populated = await wallet.populateCall(tx);
  const signedTx = await wallet.signTransaction(populated);
  const txHash = keccak256(signedTx);

  console.log({ signedTx, txHash });

  return { signedTx, txHash };
}
