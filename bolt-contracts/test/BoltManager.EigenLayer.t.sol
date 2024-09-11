// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";

import {BoltValidators} from "../src/contracts/BoltValidators.sol";
import {BoltManager} from "../src/contracts/BoltManager.sol";

import {AVSDirectoryStorage} from "@eigenlayer/src/contracts/core/AVSDirectoryStorage.sol";
import {DelegationManagerStorage} from "@eigenlayer/src/contracts/core/DelegationManagerStorage.sol";
import {IDelegationManager} from "@eigenlayer/src/contracts/interfaces/IDelegationManager.sol";
import {ISignatureUtils} from "@eigenlayer/src/contracts/interfaces/ISignatureUtils.sol";
import {IAVSDirectory} from "@eigenlayer/src/contracts/interfaces/IAVSDirectory.sol";
import {IStrategy} from "@eigenlayer/src/contracts/interfaces/IStrategy.sol";
import {EigenLayerDeployer} from "../test/fixtures/EigenLayerDeployer.f.sol";

contract BoltManagerEigenLayerTest is Test {
    BoltValidators public validators;
    BoltManager public manager;
    EigenLayerDeployer public eigenLayerDeployer;

    address staker = makeAddr("staker");
    address operator;
    uint256 operatorSk;

    address admin = makeAddr("admin");

    function setUp() public {
        // Set-up accounts
        (operator, operatorSk) = makeAddrAndKey("operator");

        // Deploy EigenLayer contracts.
        // This also deploy a `weth` token and `wethStrat` strategy base available as properties of the contract.
        eigenLayerDeployer = new EigenLayerDeployer(staker);
        eigenLayerDeployer.setUp();

        // Deploy Bolt contracts
        validators = new BoltValidators(admin);
        manager = new BoltManager(
            admin,
            address(validators),
            address(0),
            address(0),
            address(0),
            address(0),
            address(eigenLayerDeployer.avsDirectory()),
            address(eigenLayerDeployer.delegationManager()),
            address(eigenLayerDeployer.strategyManager())
        );
    }

    function _eigenLayerOptInRoutine() internal {
        // 1. As a staker, I deposit some LSTs into a Stategy via the StrategyManager.depositIntoStrategy function.
        // After this, I get back some shares that I can use at a later time for withdrawal

        vm.startPrank(staker);
        eigenLayerDeployer.weth().approve(
            address(eigenLayerDeployer.strategyManager()),
            1 ether
        );
        uint256 shares = eigenLayerDeployer
            .strategyManager()
            .depositIntoStrategy(
                eigenLayerDeployer.wethStrat(),
                eigenLayerDeployer.weth(),
                1 ether
            );
        vm.stopPrank();
        assertEq(
            eigenLayerDeployer.wethStrat().sharesToUnderlyingView(shares),
            1 ether
        );

        // 2. As a Operator, I register myself into EigenLayer using DelegationManager.registerAsOperator.
        // Note that this function doesn’t require specifying anything related to the service I’m going to provide.
        // However, a parameter describes who can delegate to me whether it can be anyone or a subset of stakers.

        IDelegationManager.OperatorDetails
            memory operatorDetails = IDelegationManager.OperatorDetails(
                address(0),
                address(0),
                0
            );
        vm.startPrank(operator);
        eigenLayerDeployer.delegationManager().registerAsOperator(
            operatorDetails,
            "https://boltprotocol.xyz"
        );
        vm.stopPrank();

        // 3. As a staker, I can start delegating funds to these operators using
        // the DelegationManager.delegateTo function and specifying to who I wish
        // to delegate my funds

        // NOTE: this signature is not used since the operator allows funds delegated from anyone
        ISignatureUtils.SignatureWithExpiry memory signature = ISignatureUtils
            .SignatureWithExpiry(bytes(""), 0);
        console.logAddress(
            eigenLayerDeployer.delegationManager().delegatedTo(staker)
        );
        vm.startPrank(staker);
        eigenLayerDeployer.delegationManager().delegateTo(
            operator,
            signature,
            bytes32(0)
        );
        vm.stopPrank();
        assertEq(
            eigenLayerDeployer.delegationManager().delegatedTo(staker),
            operator
        );

        // 4. As an AVS developer I create an entrypoint contract.
        // Upon deploying the contract it is required to make a call to EL’s
        // AVSDirectory.updateAVSMetadataURI which takes just a string which is a URI.
        // Note that his is not stored anywhere, just an log is emitted.
        // Note that msg.sender which is the ServiceManager contract is used to identify the AVS itself

        vm.prank(admin);
        manager.updateEigenLayerAVSMetadataURI("https://boltprotocol.xyz");

        // 5. As a operator, I can now opt-in into an AVS by interacting with the ServiceManager.
        // Two steps happen:
        // i. I call the AVS’ ServiceManager.registerOperatorToAVS. The payload is a signature whose digest consists of:
        //     a. my operator address
        //     b. the AVS’ ServiceManager contract address
        //     c. a salt
        //     d. an expiry
        // ii. The contract forwards the call to the AVSDirectory.registerOperatorToAVS to
        // that msg.sender is the AVS contract. Upon successful verification of the signature,
        // the operator is considered REGISTERED in a mapping avsOperatorStatus[msg.sender][operator].

        // Calculate the digest hash
        bytes32 operatorRegistrationDigestHash = eigenLayerDeployer
            .avsDirectory()
            .calculateOperatorAVSRegistrationDigestHash({
                operator: operator,
                avs: address(manager),
                salt: bytes32(0),
                expiry: UINT256_MAX
            });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            operatorSk,
            operatorRegistrationDigestHash
        );
        bytes memory operatorRawSignature = abi.encodePacked(r, s, v);
        ISignatureUtils.SignatureWithSaltAndExpiry
            memory operatorSignature = ISignatureUtils
                .SignatureWithSaltAndExpiry(
                    operatorRawSignature,
                    bytes32(0),
                    UINT256_MAX
                );
        vm.expectEmit(true, true, true, true);
        emit IAVSDirectory.OperatorAVSRegistrationStatusUpdated(
            operator,
            address(manager),
            IAVSDirectory.OperatorAVSRegistrationStatus.REGISTERED
        );
        manager.registerEigenLayerOperatorToAVS(operator, operatorSignature);
        assertEq(
            manager.checkIfEigenLayerOperatorRegisteredToAVS(operator),
            true
        );
    }

    function test_deregisterEigenLayerOperatorFromAVS() public {
        _eigenLayerOptInRoutine();
        vm.prank(operator);
        manager.deregisterEigenLayerOperatorFromAVS();
        assertEq(
            manager.checkIfEigenLayerOperatorRegisteredToAVS(operator),
            false
        );
    }

    // function test_getEigenLayerOperatorStake() public {
    //     _eigenLayerOptInRoutine();
    //
    //     IStrategy[] memory strategies = new IStrategy[](1);
    //     strategies[0] = eigenLayerDeployer.wethStrat();
    //
    //     uint256[] memory tokensAmounts = manager.getEigenLayerOperatorStake(
    //         operator,
    //         strategies
    //     );
    //     assertEq(tokensAmounts.length, 1);
    //     assertEq(tokensAmounts[0], 1 ether);
    // }
}
