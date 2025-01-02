// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccount} from "foundry-era-contracts/interfaces/IAccount.sol";
import {Transaction} from "foundry-era-contracts/libraries/MemoryTransactionHelper.sol";

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

contract ZkMinimalAccount is IAccount {
    function validateTransaction(bytes32 _txHash, bytes32 _suggestedSignedHash, Transaction calldata _transaction)
        external
        payable
        returns (bytes4 magic)
    {}

    function executeTransaction(bytes32 _txHash, bytes32 _suggestedSignedHash, Transaction calldata _transaction)
        external
        payable
    {}

    // There is no point in providing possible signed hash in the `executeTransactionFromOutside` method,
    // since it typically should not be trusted.
    function executeTransactionFromOutside(Transaction calldata _transaction) external payable {}

    function payForTransaction(bytes32 _txHash, bytes32 _suggestedSignedHash, Transaction calldata _transaction)
        external
        payable
    {}

    function prepareForPaymaster(bytes32 _txHash, bytes32 _possibleSignedHash, Transaction calldata _transaction)
        external
        payable
    {}
}
