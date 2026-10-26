# Network overview visual slice — 2026-10-21

Scope: PG-040 / PG-041 visual navigation and explanation only. Neither task is marked complete; backend integration prerequisites remain outstanding. The user selected a light control room with a clear network map, activity feed, and simple panels.

## Delivered

- `/` now presents a responsive light workspace with a clickable sensor/gateway/owner/reader/permission-registry map.
- Color and text distinguish off-chain data, chain reads, and chain writes. Component details explain sends, receives, and blockchain relationship.
- A local illustrative walkthrough supports allowed access, confirmed/synced revocation, and chain outage, with manual step, run/pause, replay, reset, node state, and activity feed.
- Mobile uses explicit connection descriptions rather than a misleading linear diagram.
- Existing owner and subscriber routes are linked. Login's incorrect `/(owner)/dashboard` link was corrected to `/dashboard`.
- Product context is recorded in PRODUCT.md; visual decisions in apps/web/DESIGN.md. docs/DESIGN.md remains the authoritative architecture record.

## Executed verification

On Windows with Node v24.14.1 and Next.js 14.2.35, from apps/web:

```text
npm.cmd run tsc
npm.cmd run build
node node_modules/@playwright/test/cli.js test --reporter=line
node --test tests/disclosure.test.mjs
```

Type check passed; production build passed. Browser suite: **7 passed**, including all three walkthrough scenarios and mobile no-horizontal-overflow/connection labels. Disclosure tests: **6 passed**. The pre-existing module-type warning remains. The npm test entry point and missing ESLint configuration reported in the previous verification were not changed.

`git diff --check` passed (line-ending notices only). Impeccable detector returned `[]` on the initial built page/CSS; it was not rerun after the final mobile relationship adjustment.

Desktop map and initial mobile rendering were visually inspected. Final desktop capture: `.impeccable/review/desktop.png`. Mobile capture `.impeccable/review/mobile.png` is partial: the tool clipped the long viewport. Attempts to capture lower sections then failed with `Preview automation snapshot failed on client preview-6c22037f520ad87738476d303f5ce13b`, including after reopening/navigation. Lower mobile visuals therefore have automated-layout evidence and source review, not complete final screenshot evidence.

## Boundaries

This view makes no API calls or live chain transactions. All map activity is labeled illustrative/simulated, and it contains no raw telemetry values. It demonstrates expected behavior rather than measuring real connectivity. Existing forms, gateway CORS/runtime assembly, real wallet authorization, and chain/MQTT operation still need separate work. No ownership, encryption, API, schema, custody, or deployment-target changes were made.

Modern Web Guidance was searched for accessible network diagrams and interaction/reduced-motion patterns. The retrieved spotlight/reveal guide was not applied: this control-room map needs continuously visible information rather than pointer-revealed content. React's official useEffect guidance informed interval cleanup.

## Independent finish review

The reviewer requested scenario-specific step-3 explanations and disabling successful chain-read animation during outage. Both were corrected; the reviewer scored both resolved and returned **ship with capture limitation**. Compact navigation row sizing was also corrected in source, with no fresh visual confirmation. Production build and all seven browser tests passed again after these corrections. One intermediate build command was accidentally run from repository root and reported a missing build script; rerunning from apps/web succeeded.
