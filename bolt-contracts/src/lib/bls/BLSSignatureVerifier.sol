// ======================================================
// Code below is copied from:
// https://github.com/NethermindEth/Taiko-Preconf-AVS/blob/caf9fbbde0dd84947af5a7b26610ffd38525d932/SmartContracts/src/libraries/BLS12381.sol
//
// If/when a license will be added to the original code, it will be added here as well.
// ======================================================

// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.25;

import {BLS12381} from "./BLS12381.sol";

contract BLSSignatureVerifier {
    using BLS12381 for *;

    /// @dev The domain separation tag for the BLS signature
    function dst() internal pure returns (bytes memory) {
        // Todo: This must be set based on the recommendations of RFC9380
        return hex"";
    }

    /**
     * @notice Returns `true` if the BLS signature on the message matches against the public key
     * @param message The message bytes
     * @param sig The BLS signature
     * @param pubkey The BLS public key of the expected signer
     */
    function _verifySignature(
        bytes memory message,
        BLS12381.G2Point memory sig,
        BLS12381.G1Point memory pubkey
    ) internal view returns (bool) {
        // Hash the message bytes into a G2 point
        BLS12381.G2Point memory msgG2 = message.hashToCurveG2(dst());

        // Return the pairing check result
        return BLS12381.pairing(BLS12381.generatorG1().negate(), sig, pubkey, msgG2);
    }

    /**
     * @notice Aggregate a list of BLS public keys into a single BLS public key
     * @param pubkeys The list of BLS public keys to aggregate
     * @return The aggregated BLS public key
     */
    function _aggregatePubkeys(BLS12381.G1Point[] calldata pubkeys) internal pure returns (BLS12381.G1Point memory) {
        // TODO: implement + test.

        // Simply adding pubkeys will result in a rogue key vulnerability.
        //
        // https://xn--2-umb.com/22/bls-signatures/#rogue-key-attack
        // https://github.com/chronicleprotocol/scribe/blob/main/docs/Schnorr.md#key-aggregation-for-multisignatures

        uint256[2] memory aggPubkeyZero = [uint256(0), uint256(0)];
        BLS12381.G1Point memory aggPubkey = BLS12381.G1Point(aggPubkeyZero, aggPubkeyZero);

        // unimplemented!()
        // silence compiler warnings
        pubkeys;

        return aggPubkey;
    }
}
