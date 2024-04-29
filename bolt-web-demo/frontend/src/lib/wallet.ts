import { TransactionRequest, keccak256 } from "ethers";
import { ethers } from "ethers";

// Test private key, for which address[0] holds 1000 ETH in the Kurtosis devnet
const PRIVATE_KEY =
  "39725efee3fb28614de3bacaffe4cc4bd8c436257e2c8bb887c4b5c4be45e76d";

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
