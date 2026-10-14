// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {PermissionRegistry} from "../src/PermissionRegistry.sol";

/// @notice Deploy PermissionRegistry to local Anvil. Usage:
///         anvil (chain-id 31337) then: forge script script/Deploy.s.sol --rpc-url 127.0.0.1:8545 --broadcast
contract Deploy is Script {
    function run() external returns (PermissionRegistry registry) {
        vm.startBroadcast();
        registry = new PermissionRegistry();
        vm.stopBroadcast();
    }
}
