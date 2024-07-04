// // SPDX-License-Identifier: MIT
// pragma solidity ^0.8.13;

// import {Test, console} from "forge-std/Test.sol";
// import {BoltRegistry} from "../src/contracts/BoltRegistry.sol";
// import {BoltChallenger} from "../src/contracts/BoltChallenger.sol";
// import {IBoltChallenger} from "../src/interfaces/IBoltChallenger.sol";
// import {BeaconChainUtils} from "../src/lib/BeaconChainUtils.sol";

// contract BoltChallengerTest is Test {
//     BoltRegistry public registry;
//     BoltChallenger public challenger;

//     // Relic protocol contracts
//     address relicReliquary = 0x5E4DE6Bb8c6824f29c44Bd3473d44da120387d08;
//     address relicBlockHeaderProver = 0x9f9A1eb0CF9340538297c853915DCc06Eb6D72c4;
//     address relicAccountInfoProver = 0xf74105AE736Ca0C4B171a2EC4F1D4B0b6EBB99ae;
//     address beaconRootsContract = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;

//     address public alice;
//     address public bob;

//     uint256 public alicePk;
//     uint256 public bobPk;

//     function setUp() public {
//         // Set up mainnet forking
//         vm.createSelectFork("https://cloudflare-eth.com", 19932764);
//         assertEq(block.number, 19932764);

//         (alice, alicePk) = makeAddrAndKey("alice");
//         (bob, bobPk) = makeAddrAndKey("bob");

//         registry = new BoltRegistry();
//         challenger =
//             new BoltChallenger(address(registry), relicReliquary, relicBlockHeaderProver, relicAccountInfoProver);

//         vm.deal(alice, 10 ether);
//         vm.deal(bob, 10 ether);
//     }

//     function testOpenChallengeConditions() public {
//         uint256 latestSlot = BeaconChainUtils._getSlotFromTimestamp(block.timestamp);

//         BoltChallenger.SignedCommitment memory sc = BoltChallenger.SignedCommitment({
//             slot: 1,
//             nonce: 1,
//             gasUsed: 21000,
//             transactionHash: bytes32("0x123"),
//             signedRawTransaction: "0x456",
//             signature: "0x789"
//         });

//         // TEST: bond is less than 1 ether
//         vm.expectRevert(IBoltChallenger.InsufficientBond.selector);
//         vm.prank(alice);
//         challenger.challengeProposer{value: 0.5 ether}(bob, sc);

//         // TEST: challenge opened too late
//         vm.expectRevert(IBoltChallenger.TargetSlotTooFarInThePast.selector);
//         vm.prank(alice);
//         challenger.challengeProposer{value: 1 ether}(bob, sc);

//         sc.slot = latestSlot;

//         // TEST: proposer address is authorized in the registry
//         vm.expectRevert(IBoltChallenger.InvalidProposerAddress.selector);
//         vm.prank(alice);
//         challenger.challengeProposer{value: 1 ether}(bob, sc);

//         vm.prank(bob);
//         registry.optIn();

//         // TEST: mocked commitment signature
//         vm.expectRevert(IBoltChallenger.InvalidCommitmentSignature.selector);
//         vm.prank(alice);
//         challenger.challengeProposer{value: 1 ether}(bob, sc);
//     }

//     function testOpenChallengeSignature() public {
//         uint256 latestSlot = BeaconChainUtils._getSlotFromTimestamp(block.timestamp);

//         vm.prank(bob);
//         registry.optIn();

//         bytes32 txHash = 0xbe162ae10f376ad2bcf0934233493c7b353836fc1d27c5cb6785ce68d45914ea;
//         bytes memory signedRawTx =
//             hex"02f87101830f45b3808504acefa159825208944675c7e5baafbffbca748158becba61ef3b0a26387cb62154da95e6480c080a0101d7785433fd38e12fccd911bf9e61a941c88543f372877f07901dacf066b0aa016a75077103f7e175b61b5509e20ef5e8364d322f2ecaade5922717efeb892cd";

//         bytes32 commitmentDigest = keccak256(abi.encodePacked(latestSlot, txHash, signedRawTx));
//         (uint8 v, bytes32 r, bytes32 s) = vm.sign(bobPk, commitmentDigest);
//         bytes memory commitmentSignature = abi.encodePacked(r, s, v);

//         BoltChallenger.SignedCommitment memory sc = BoltChallenger.SignedCommitment({
//             slot: latestSlot,
//             nonce: vm.getNonce(0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5),
//             gasUsed: 21000,
//             transactionHash: txHash,
//             signedRawTransaction: signedRawTx,
//             signature: commitmentSignature
//         });

//         // mock the beacon root for the target slot (todo: fix this)
//         bytes32 timestampIdx = bytes32(uint256(block.timestamp % 8191));
//         vm.store(beaconRootsContract, timestampIdx, bytes32(block.timestamp));
//         vm.store(beaconRootsContract, bytes32(uint256(timestampIdx) + 8191), bytes32(uint256(123)));

//         // TEST: challenge opened successfully
//         // Ignore beacon root verification for now as EIP-4788 is out of scope for this test
//         vm.expectRevert(BeaconChainUtils.BeaconRootNotFound.selector);
//         vm.prank(alice);
//         challenger.challengeProposer{value: 1 ether}(bob, sc);
//     }
// }
