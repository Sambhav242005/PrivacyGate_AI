# PrivacyGate AI

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users and purpose

An academic demonstration for device owners and authorized insight readers. Make the path from a signed industrial IoT sensor through a local gateway to two reader views easy to understand. Owners control permissions; readers receive only recipient-encrypted approved insights.

## Operating context

One simulated sensor, a local gateway, and a local Ethereum-compatible permission registry. The authoritative product/security documents remain in docs/. The current implementation has unassembled live service dependencies; a visual walkthrough must not imply measured connectivity or confirmed real transactions.

## Confirmed design direction

The user selected a light control room with a clear network map, activity feed, and simple panels. Their priority is seeing which components are connected, sending data, writing chain permissions, and reading chain state. All task pages now share the same light workspace and client-focused language: My devices, Shared insights, and Sign in. A persistent Back to network link returns from every nonhome page. Technical setup is secondary to client tasks.

## Constraints

Telemetry and insight content remain off-chain. Permission checks and enforcement belong to the backend. No private keys or raw telemetry in public overview assets. Simulated activity must be labeled. Existing owner and subscriber tasks remain available from the overview. Sign-in still uses the existing wallet-based authentication; the new presentation does not introduce a different identity system or demonstrate completed live backend integration.
