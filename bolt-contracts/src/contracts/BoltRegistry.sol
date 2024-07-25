// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IBoltRegistry} from "../interfaces/IBoltRegistry.sol";

contract BoltRegistry is IBoltRegistry {
    // Cooldown period after which a based proposer can complete the exit process
    uint256 public constant EXIT_COOLDOWN = 1 days;

    // Minimum collateral per operator
    uint256 public immutable MINIMUM_COLLATERAL;

    // Mapping to hold the registrants
    mapping(address => Registrant) public registrants;

    // Array to hold operator addresses
    address[] public operators;

    // Mapping that holds the relationship between validator index and operator address
    mapping(uint64 => address) public delegations;

    /// @notice Constructor which can set the minimum collateral required to register
    constructor(uint256 _minimumCollateral) {
        MINIMUM_COLLATERAL = _minimumCollateral;
    }

    /// @notice Allows a based proposer to opt-in to the protocol
    function register(
        uint64[] calldata validatorIndexes,
        string calldata rpc,
        bytes calldata extra
    ) external payable {
        if (msg.value < MINIMUM_COLLATERAL) {
            revert InsufficientCollateral();
        }

        if (registrants[msg.sender].operator != address(0)) {
            revert AlreadyOptedIn();
        }

        MetaData memory metadata = MetaData(rpc, extra);

        registrants[msg.sender] = Registrant(
            msg.sender,
            validatorIndexes,
            block.timestamp,
            0,
            msg.value,
            Status.ACTIVE,
            metadata
        );

        operators.push(msg.sender);

        // Set the delegations
        for (uint256 i = 0; i < validatorIndexes.length; i++) {
            delegations[validatorIndexes[i]] = msg.sender;
        }

        emit Registered(msg.sender, validatorIndexes, metadata);
    }

    /// @notice Allows a based proposer to exit out of the protocol.
    /// @dev Requires a second transaction after the cooldown period to complete the exit process.
    function startExit() external {
        Registrant storage registrant = registrants[msg.sender];

        if (registrant.operator != msg.sender) {
            revert BasedProposerDoesNotExist();
        }

        if (registrant.status == Status.EXITING) {
            revert InvalidStatusChange();
        }

        registrant.exitInitiatedAt = block.timestamp;

        emit StatusChange(msg.sender, Status.EXITING);
    }

    /// @notice Completes the exit process for a based proposer
    /// and sends the funds back to the `recipient` address.
    function confirmExit(address payable recipient) external {
        Registrant storage registrant = registrants[msg.sender];

        if (registrant.operator != msg.sender) {
            revert BasedProposerDoesNotExist();
        }
        if (registrant.exitInitiatedAt == 0) {
            revert InvalidStatusChange();
        }
        if (registrant.status == Status.INACTIVE) {
            revert InvalidStatusChange();
        }

        if (block.timestamp < registrant.exitInitiatedAt + EXIT_COOLDOWN) {
            revert CooldownNotElapsed();
        }

        // Remove operator from the operators array
        for (uint256 i = 0; i < operators.length; i++) {
            if (operators[i] == msg.sender) {
                operators[i] = operators[operators.length - 1];
                operators.pop();
                break;
            }
        }
        
        delete registrants[msg.sender];

        for (uint256 i = 0; i < registrant.validatorIndexes.length; i++) {
            delete delegations[registrant.validatorIndexes[i]];
        }

        recipient.transfer(registrant.balance);

        emit StatusChange(msg.sender, Status.INACTIVE);
    }

    /// @notice Check if an address is a based proposer opted into the protocol
    /// @param _operator The address to check
    /// @return True if the address is an active based proposer, false otherwise
    function isActiveOperator(address _operator) public view returns (bool) {
        return registrants[_operator].status == Status.ACTIVE;
    }

    /// @notice Get the status of a based proposer
    /// @param _operator The address of the operator
    /// @return The status of the based proposer
    function getOperatorStatus(
        address _operator
    ) external view returns (Status) {
        // Will return INACTIVE if the operator is not registered
        return registrants[_operator].status;
    }

    function getOperatorForValidator(
        uint64 _validatorIndex
    ) external view returns (Registrant memory) {
        if (delegations[_validatorIndex] != address(0)) {
            return registrants[delegations[_validatorIndex]];
        }

        revert NotFound();
    }

    function getAllRegistrants() external view returns (Registrant[] memory) {
        uint256 activeCount = 0;
        for (uint256 i = 0; i < operators.length; i++) {
            if (isActiveOperator(operators[i])) {
                activeCount++;
            }
        }

        Registrant[] memory _registrants = new Registrant[](activeCount);
        uint256 index = 0;
        for (uint256 i = 0; i < operators.length; i++) {
            if (isActiveOperator(operators[i])) {
                _registrants[index] = registrants[operators[i]];
                index++;
            }
        }

        return _registrants;
    }
}
