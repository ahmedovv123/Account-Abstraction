//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

contract MinimalAccount is IAccount, Ownable {
    ///////////////////////////////////////////////
    //             ERRORS
    ///////////////////////////////////////////////
    error MinimalAccount__NotFromEntryPoint();
    error MinimalAccount__NotFromEntryPointOrOwner();
    error MinimalAccount__CallFailed(bytes result);

    ///////////////////////////////////////////////
    //             STATE VARIABLES
    ///////////////////////////////////////////////

    address private immutable i_entryPoint;

    ///////////////////////////////////////////////
    //             MODIFIERS
    ///////////////////////////////////////////////

    modifier requireFromEntryPoint() {
        if (msg.sender != address(i_entryPoint)) {
            revert MinimalAccount__NotFromEntryPoint();
        }
        _;
    }

    modifier requireFromEntryPointOrOwner() {
        if (msg.sender != address(i_entryPoint) && msg.sender != owner()) {
            revert MinimalAccount__NotFromEntryPointOrOwner();
        }
        _;
    }

    ///////////////////////////////////////////////
    //             CONSTRUCTOR
    ///////////////////////////////////////////////
    constructor(address entryPoint) Ownable(msg.sender) {
        i_entryPoint = entryPoint;
    }

    receive() external payable {}

    ///////////////////////////////////////////////
    //             EXTERNAL FUNCTIONS
    ///////////////////////////////////////////////
    function execute(address dest, uint256 value, bytes calldata funcData) external requireFromEntryPointOrOwner {
        (bool success, bytes memory result) = dest.call{value: value, gas: type(uint256).max}(funcData);
        
        if(!success) {
            revert MinimalAccount__CallFailed(result);
        }
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        requireFromEntryPoint
        returns (uint256 validationData)
    {
        validationData = _validateSignature(userOp, userOpHash);
        // ideally we should also check the nonce, but for simplicity we skip it here
        _payPrefund(missingAccountFunds);
    }

    ///////////////////////////////////////////////
    //             INTERNAL FUNCTIONS
    ///////////////////////////////////////////////

    // Many ways to implement the signature validation. I go with the simplest one. A signature is valid if its the minimal account owner.
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        returns (uint256 validationData)
    {
        // Correct userOpHash to correct format
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        address signer = ECDSA.recover(ethSignedMessageHash, userOp.signature);

        if (signer != owner()) {
            return SIG_VALIDATION_FAILED;
        }

        return SIG_VALIDATION_SUCCESS;
    }

    function _payPrefund(uint256 missingAccountFunds) internal {
        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds, gas: type(uint256).max}("");
            (success); // silence the warning
        }
    }

    ///////////////////////////////////////////////
    //                  GETTERS
    ///////////////////////////////////////////////

    function getEntryPoint() external view returns (address) {
        return address(i_entryPoint);
    }
}
