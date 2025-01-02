// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccount, ACCOUNT_VALIDATION_SUCCESS_MAGIC} from "foundry-era-contracts/interfaces/IAccount.sol";
import {Transaction, MemoryTransactionHelper} from "foundry-era-contracts/libraries/MemoryTransactionHelper.sol";
import {SystemContractsCaller} from "foundry-era-contracts/libraries/SystemContractsCaller.sol";
import {
    NONCE_HOLDER_SYSTEM_CONTRACT,
    BOOTLOADER_FORMAL_ADDRESS,
    DEPLOYER_SYSTEM_CONTRACT
} from "foundry-era-contracts/Constants.sol";
import {INonceHolder} from "foundry-era-contracts/interfaces/INonceHolder.sol";
import {Utils} from "foundry-era-contracts/libraries/Utils.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * Lifecyle of a type 113 (0x71) transaction
 * msg.sender is the bootloader system contract
 *
 * Phase 1 - Validation
 * 1. The user sends the transaction to the "zkSync API client" (sort of a "light node")
 * 2. The zkSync API client checks to see the nonce is unique by querying the NonceHolder system contract
 * 3. The zkSync API client calls validateTransaction, which MUST update the nonce
 * 4. The zkSync API client checks the nonce is updated
 * 5. The zkSync API client calls payForTransaction, or prepareForPaymaster & validateAndPayForPaymasterTransaction
 * 6. The zkSync API client verifies that the bootloader gets paid
 *
 * Phase 2 - Execution
 * 1. The zkSync API client passes the validated transaction to the main node / sequencer (as of today, they are the same)
 * 2. The main node / sequencer calls executeTransaction
 * 3. If a paymaster was used, the postTransaction is called
 */
contract ZkMinimalAccount is IAccount, Ownable {
    using MemoryTransactionHelper for Transaction;

    error ZkMinimalAccount__NotEnoughBalance();
    error ZkMinimalAccount__NotFromBootloader();
    error ZkMinimalAccount__NotFromBootloaderOrOwner();
    error ZkMinimalAccount__ExecutionFailed();
    error ZkMinimalAccount__FailedToPay();
    error ZkMinimalAccount__ValidationFailed();

    ///////////////////////////////////////////////
    //                 MODIFIERS
    ///////////////////////////////////////////////
    modifier requireFromBootloader() {
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS) {
            revert ZkMinimalAccount__NotFromBootloader();
        }
        _;
    }

    modifier requireFromBootloaderOrOwner() {
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS && msg.sender != owner()) {
            revert ZkMinimalAccount__NotFromBootloaderOrOwner();
        }
        _;
    }

    constructor() Ownable(msg.sender) {}

    receive() external payable {}

    ///////////////////////////////////////////////
    //             EXTERNAL FUNCTIONS
    ///////////////////////////////////////////////
    /**
     * @notice  must increase the nonce
     * @notice  must validate the transaction (check the owner signed the transaction)
     * @notice  also check to see if we have enough money to pay for the transaction
     * @dev     .
     * @param   _transaction the transaction to validate
     * @return  magic  .
     */
    function validateTransaction(
        bytes32, /*_txHash*/
        bytes32, /*_suggestedSignedHash*/
        Transaction calldata _transaction
    ) external payable requireFromBootloader returns (bytes4 magic) {
        return _validateTransaction(_transaction);
    }

    function executeTransaction(
        bytes32, /*_txHash*/
        bytes32, /*_suggestedSignedHash*/
        Transaction calldata _transaction
    ) external payable requireFromBootloaderOrOwner {
        _executeTransaction(_transaction);
    }

    // There is no point in providing possible signed hash in the `executeTransactionFromOutside` method,
    // since it typically should not be trusted.
    function executeTransactionFromOutside(Transaction calldata _transaction) external payable {
        bytes4 magic = _validateTransaction(_transaction);

        if (magic != ACCOUNT_VALIDATION_SUCCESS_MAGIC) {
            revert ZkMinimalAccount__ValidationFailed();
        }
        _executeTransaction(_transaction);
    }

    function payForTransaction(bytes32, /*_txHash*/ bytes32, /*_suggestedSignedHash*/ Transaction calldata _transaction)
        external
        payable
    {
        bool success = _transaction.payToTheBootloader();
        if (!success) {
            revert ZkMinimalAccount__FailedToPay();
        }
    }

    function prepareForPaymaster(bytes32 _txHash, bytes32 _possibleSignedHash, Transaction calldata _transaction)
        external
        payable
    {}

    ///////////////////////////////////////////////
    //             INTERNAL FUNCTIONS
    ///////////////////////////////////////////////
    function _validateTransaction(Transaction memory _transaction) internal returns (bytes4 magic) {
        // Calling system contract is not simply as dropping the address and calling its function like in ethereum, check foundry.toml
        // Call nonceholder and increment nonce
        // When the is-system is true, when there is a call, it will be replaced with the system contract call for example:
        // call(x, y, z) -> system contract call
        // call(address(25), 7, string(helloSecretThing)) => systemcontract.updateNonceHolder(1)
        // We use utility functions to make the call, SystemContractsCaller is a library that has the utility functions

        SystemContractsCaller.systemCallWithPropagatedRevert(
            uint32(gasleft()),
            address(NONCE_HOLDER_SYSTEM_CONTRACT),
            0,
            abi.encodeCall(INonceHolder.incrementMinNonceIfEquals, (_transaction.nonce))
        );

        // Check for fee to pay
        uint256 totalRequiredBalance = _transaction.totalRequiredBalance();
        if (totalRequiredBalance > address(this).balance) {
            revert ZkMinimalAccount__NotEnoughBalance();
        }

        // Check the signature
        bytes32 txHash = _transaction.encodeHash();
        address signer = ECDSA.recover(txHash, _transaction.signature);
        bool isValidSIgner = signer == owner();
        if (isValidSIgner) {
            magic = ACCOUNT_VALIDATION_SUCCESS_MAGIC;
        } else {
            magic = bytes4(0);
        }

        // Return the magic number
        return magic;
    }

    function _executeTransaction(Transaction memory _transaction) internal {
        address to = address(uint160(_transaction.to));
        uint128 value = Utils.safeCastToU128(_transaction.value);
        bytes memory data = _transaction.data;

        if (to == address(DEPLOYER_SYSTEM_CONTRACT)) {
            uint32 gas = Utils.safeCastToU32(gasleft());
            SystemContractsCaller.systemCallWithPropagatedRevert(gas, to, value, data);
        } else {
            bool success;

            assembly {
                success := call(gas(), to, value, add(data, 0x20), mload(data), 0, 0)
            }

            if (!success) {
                revert ZkMinimalAccount__ExecutionFailed();
            }
        }
    }
}
