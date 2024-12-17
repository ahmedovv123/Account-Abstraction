//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {MinimalAccount} from "../src/ethereum/MinimalAccount.sol";
import {HelperConfig} from "./HelperConfig.s.sol";

contract DeployMinimal is Script {
    function run() public {}

    function deployMinimalAccount() public returns (HelperConfig, MinimalAccount) {
        HelperConfig config = new HelperConfig();
        HelperConfig.NetworkConfig memory networkConfig = config.getConfig();

        vm.startBroadcast(networkConfig.account);

        MinimalAccount minimalAccount = new MinimalAccount(networkConfig.entryPoint);
        minimalAccount.transferOwnership(msg.sender);

        vm.stopBroadcast();

        return (config, minimalAccount);


    }
}