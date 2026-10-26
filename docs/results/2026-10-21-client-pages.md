# Client workspace redesign — 2026-10-21

Scope: PG-040 / PG-041 frontend presentation, navigation, and existing client action wiring. Full task completion remains blocked by the previously documented runtime/auth integration gaps.

The user requested client-oriented pages in place of the crypto-centric owner and reader forms, back navigation on every nonhome route, and a fix for the registry arrow shown in their screenshot.

## Changes

- Added a shared light workspace shell to `/dashboard`, `/insights`, `/login`, `/api-docs`, and other nonhome routes, with a persistent `Back to network` link, active navigation, and a keyboard skip link.
- `/dashboard` now leads with equipment, readings, and shared access. Installer identifiers, keys, service address, transaction reference, and history are progressively disclosed. Expiration uses a date picker with UTC semantics.
- `/insights` now presents an insight inbox and one-action private-viewing setup. Existing private-key import remains advanced and memory-only; its input masks the value. Insight reference data stays available under disclosure.
- `/login` now explains account sign-in in plain language and accurately discloses the existing browser-wallet identity mechanism. No email/password mechanism was invented or introduced.
- Existing policy approval now signs that policy's own resource, recipient, digest, and expiry, rather than values currently being edited in the new invitation form. Revocation retains its returned reference for confirmation checks.
- Main overview appearance is retained. Its navigation labels match the client pages, and its write arrow enters the registry from the right horizontally.
- The technical API reference inherits the new shell. Its API schemas and loading behavior are unchanged.

No backend permissions, public API, encryption protocol, key custody, schema, or chain target changed.

## Evidence

Windows, Node v24.14.1, Next.js 14.2.35. From apps/web:

```text
npm.cmd run build
node node_modules/@playwright/test/cli.js test --reporter=line
node --test tests/disclosure.test.mjs
```

Production build/type checking passed. Browser suite: **8 passed**. Disclosure tests: **6 passed**. New browser coverage checks visible back links on all four routes, actual back navigation, hidden installer fields that open correctly, and document-width containment at 390px. Existing render, mock authentication, and walkthrough cases pass.

Browser test screenshots under `docs/results/playwright/client-*-desktop.png` and `client-*-mobile.png` capture whole pages, with the API reference awaited until loaded. Owner, reader, login, home-arrow, and settled API reference images were visually inspected. The T3 preview still navigates, but its snapshot call failed; existing browser-suite screenshot artifacts supplied the visual evidence.

The design detector ran once. It reported advisory palette/type drift against the previous homepage-only design record and legacy global CSS; those are not proof of a functional failure. The design record is being extended for the new client shell.

Initial implementation had a JSX replacement syntax error; the build caught it, the replacement boundary was corrected, and subsequent builds passed. Initial API reference screenshot captured loading state; the browser check now waits for the endpoint navigation before capture. Independent review found revocation wording that overclaimed recall and poor selected-endpoint contrast; both were corrected. The review also confirmed the arrow direction and policy-specific action parameters.

Final verdict: **ship**. The independent reviewer confirmed both corrections in fresh screenshots and source. The final production build and all eight browser tests passed after the corrections. Product/design documentation and its JSON sidecar were updated and validated.

Modern Web Guidance's accessibility guide informed native disclosure controls, persistent input labels, and a focusable skip-link target ("Don't use placeholders as labels"). Next.js Context7 documentation informed the shared pathname-aware navigation shell.

## Limits

This is a frontend redesign. Live chain/MQTT delivery and real wallet authentication remain unproven. Tests use wallet/API stubs where stated. The existing npm test directory-entry issue and unconfigured ESLint were not changed. A module-type warning remains on direct disclosure tests. Telemetry pagination behavior is unchanged; the UI says `Load more readings` rather than implying older records. Previously received ciphertext or decrypted updates cannot be recalled by revocation.
