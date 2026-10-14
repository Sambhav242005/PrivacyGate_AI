// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title PermissionRegistry — owner-managed READ_INSIGHT grants (local Anvil demo).
/// @notice Stores ONLY resource ownership + grant metadata (digests, expiry, version).
///         NEVER store telemetry, coordinates, prompts, plaintext insights, keys, or personal data.
contract PermissionRegistry {
    /// @notice Fixed MVP scope: READ_INSIGHT. READ_DETAIL is never grantable on-chain.
    uint8 public constant SCOPE_READ_INSIGHT = 1;

    struct Grant {
        bytes32 policyDigest;
        uint64 expiresAt;
        uint32 version;
        bool active;
        uint8 scope;
    }

    mapping(bytes32 => address) private _owners;
    mapping(bytes32 => mapping(address => Grant)) private _grants;

    event ResourceRegistered(bytes32 indexed resourceId, address indexed owner);
    event Granted(
        bytes32 indexed resourceId, address indexed reader, bytes32 policyDigest, uint64 expiresAt, uint32 version
    );
    event Revoked(bytes32 indexed resourceId, address indexed reader, uint32 version);

    error ZeroResourceId();
    error AlreadyRegistered();
    error NotResourceOwner();
    error ZeroReader();
    error ZeroPolicyDigest();
    error ExpiryNotInFuture();
    error NoGrantExists();
    error UnregisteredResource();

    /// @notice Register a resource; caller becomes its owner exactly once. No reassignment in MVP.
    function registerResource(bytes32 resourceId) external {
        if (resourceId == bytes32(0)) revert ZeroResourceId();
        if (_owners[resourceId] != address(0)) revert AlreadyRegistered();
        _owners[resourceId] = msg.sender;
        emit ResourceRegistered(resourceId, msg.sender);
    }

    /// @notice Owner-only grant of READ_INSIGHT to `reader`. Increments version; re-grant overwrites.
    function grant(bytes32 resourceId, address reader, bytes32 policyDigest, uint64 expiresAt) external {
        address owner = _owners[resourceId];
        if (owner == address(0)) revert UnregisteredResource();
        if (msg.sender != owner) revert NotResourceOwner();
        if (reader == address(0)) revert ZeroReader();
        if (policyDigest == bytes32(0)) revert ZeroPolicyDigest();
        if (expiresAt <= block.timestamp) revert ExpiryNotInFuture();

        Grant storage g = _grants[resourceId][reader];
        g.policyDigest = policyDigest;
        g.expiresAt = expiresAt;
        g.version = g.version + 1;
        g.active = true;
        g.scope = SCOPE_READ_INSIGHT;

        emit Granted(resourceId, reader, policyDigest, expiresAt, g.version);
    }

    /// @notice Owner-only revoke. Increments version, marks inactive. Cannot erase already-decrypted data.
    function revoke(bytes32 resourceId, address reader) external {
        address owner = _owners[resourceId];
        if (owner == address(0)) revert UnregisteredResource();
        if (msg.sender != owner) revert NotResourceOwner();
        Grant storage g = _grants[resourceId][reader];
        if (g.version == 0) revert NoGrantExists();
        g.version = g.version + 1;
        g.active = false;

        emit Revoked(resourceId, reader, g.version);
    }

    /// @notice Owner of a resource, or address(0) if unregistered.
    function ownerOf(bytes32 resourceId) external view returns (address) {
        return _owners[resourceId];
    }

    /// @notice Grant view. `active` is false when revoked OR expired (fail-closed helper).
    function getGrant(bytes32 resourceId, address reader)
        external
        view
        returns (bytes32 policyDigest, uint64 expiresAt, uint32 version, bool active, uint8 scope)
    {
        Grant storage g = _grants[resourceId][reader];
        active = g.active && g.expiresAt > block.timestamp;
        return (g.policyDigest, g.expiresAt, g.version, active, g.scope);
    }
}
