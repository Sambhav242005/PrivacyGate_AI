// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PermissionRegistry} from "../src/PermissionRegistry.sol";

contract PermissionRegistryTest is Test {
    PermissionRegistry private registry;
    address private owner = address(0xA11CE);
    address private reader = address(0xB0B);
    bytes32 private resourceId = keccak256("resource-1");
    bytes32 private digest = keccak256("policy-1");

    event ResourceRegistered(bytes32 indexed resourceId, address indexed owner);
    event Granted(
        bytes32 indexed resourceId, address indexed reader, bytes32 policyDigest, uint64 expiresAt, uint32 version
    );
    event Revoked(bytes32 indexed resourceId, address indexed reader, uint32 version);

    function setUp() public {
        registry = new PermissionRegistry();
        vm.prank(owner);
        registry.registerResource(resourceId);
    }

    function _expiry() internal view returns (uint64) {
        return uint64(block.timestamp + 30 days);
    }

    function test_registerResource_setsOwner() public view {
        assertEq(registry.ownerOf(resourceId), owner);
    }

    function test_registerResource_rejectsZeroId() public {
        vm.expectRevert(PermissionRegistry.ZeroResourceId.selector);
        registry.registerResource(bytes32(0));
    }

    function test_registerResource_rejectsDoubleRegister() public {
        vm.expectRevert(PermissionRegistry.AlreadyRegistered.selector);
        registry.registerResource(resourceId);
    }

    function test_grant_setsGrantVersionOne() public {
        vm.prank(owner);
        vm.expectEmit(true, true, false, true);
        emit Granted(resourceId, reader, digest, _expiry(), 1);
        registry.grant(resourceId, reader, digest, _expiry());

        (bytes32 d, uint64 e, uint32 v, bool active, uint8 scope) = registry.getGrant(resourceId, reader);
        assertEq(d, digest);
        assertEq(e, _expiry());
        assertEq(v, 1);
        assertTrue(active);
        assertEq(scope, registry.SCOPE_READ_INSIGHT());
    }

    function test_grant_regrantIncrementsVersion() public {
        vm.startPrank(owner);
        registry.grant(resourceId, reader, digest, _expiry());
        registry.grant(resourceId, reader, keccak256("policy-2"), _expiry());
        vm.stopPrank();
        (,,, uint32 v, bool active, uint8 scope) = registry.getGrant(resourceId, reader);
        // version must be 2
        assertEq(v, 2);
        assertTrue(active);
        assertEq(scope, 1);
    }

    function test_grant_unauthorizedRejected() public {
        vm.prank(reader);
        vm.expectRevert(PermissionRegistry.NotResourceOwner.selector);
        registry.grant(resourceId, reader, digest, _expiry());
    }

    function test_grant_rejectsZeroReader() public {
        vm.prank(owner);
        vm.expectRevert(PermissionRegistry.ZeroReader.selector);
        registry.grant(resourceId, address(0), digest, _expiry());
    }

    function test_grant_rejectsZeroDigest() public {
        vm.prank(owner);
        vm.expectRevert(PermissionRegistry.ZeroPolicyDigest.selector);
        registry.grant(resourceId, reader, bytes32(0), _expiry());
    }

    function test_grant_rejectsPastExpiry() public {
        vm.prank(owner);
        vm.expectRevert(PermissionRegistry.ExpiryNotInFuture.selector);
        registry.grant(resourceId, reader, digest, uint64(block.timestamp));
    }

    function test_grant_rejectsUnregisteredResource() public {
        bytes32 unknown = keccak256("nope");
        vm.prank(owner);
        vm.expectRevert(PermissionRegistry.UnregisteredResource.selector);
        registry.grant(unknown, reader, digest, _expiry());
    }

    function test_revoke_blocksDelivery() public {
        vm.startPrank(owner);
        registry.grant(resourceId, reader, digest, _expiry());
        vm.expectEmit(true, true, false, true);
        emit Revoked(resourceId, reader, 2);
        registry.revoke(resourceId, reader);
        vm.stopPrank();

        (,, uint32 v, bool active,) = registry.getGrant(resourceId, reader);
        assertEq(v, 2);
        assertFalse(active);
    }

    function test_revoke_unauthorizedRejected() public {
        vm.prank(owner);
        registry.grant(resourceId, reader, digest, _expiry());
        vm.prank(reader);
        vm.expectRevert(PermissionRegistry.NotResourceOwner.selector);
        registry.revoke(resourceId, reader);
    }

    function test_revoke_rejectsMissingGrant() public {
        vm.prank(owner);
        vm.expectRevert(PermissionRegistry.NoGrantExists.selector);
        registry.revoke(resourceId, address(0xDEAD));
    }

    function test_expiry_deactivatesGrant() public {
        vm.prank(owner);
        registry.grant(resourceId, reader, digest, uint64(block.timestamp + 1 days));
        (,,, bool activeBefore,) = registry.getGrant(resourceId, reader);
        assertTrue(activeBefore);
        vm.warp(block.timestamp + 2 days);
        (,,, bool activeAfter,) = registry.getGrant(resourceId, reader);
        assertFalse(activeAfter);
    }

    /// forge-config: default.fuzz.runs = 256
    function testFuzz_grantRoundTrip(address fuzzReader, bytes32 fuzzDigest, uint64 ttl) public {
        vm.assume(fuzzReader != address(0));
        vm.assume(fuzzDigest != bytes32(0));
        ttl = uint64(bound(ttl, 1, 365 days));
        vm.prank(owner);
        registry.grant(resourceId, fuzzReader, fuzzDigest, uint64(block.timestamp) + ttl);
        (bytes32 d, uint64 e, uint32 v, bool active, uint8 scope) =
            registry.getGrant(resourceId, fuzzReader);
        assertEq(d, fuzzDigest);
        assertEq(e, uint64(block.timestamp) + ttl);
        assertEq(v, 1);
        assertTrue(active);
        assertEq(scope, 1);
    }

    /// forge-config: default.fuzz.runs = 256
    function testFuzz_nonOwnerCannotGrant(address attacker) public {
        vm.assume(attacker != owner);
        vm.assume(attacker != address(0));
        vm.prank(attacker);
        vm.expectRevert(PermissionRegistry.NotResourceOwner.selector);
        registry.grant(resourceId, reader, digest, _expiry());
    }
}
