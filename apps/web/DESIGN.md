---
name: PrivacyGate AI client workspace
description: A light control room for an illustrative local privacy gateway.
colors:
  primary: "#2f684e"
  primary-hover: "#214e39"
  data: "#438777"
  chain-read: "#7662b0"
  chain-write: "#b7813b"
  blocked: "#9c443c"
  canvas: "#f7f9f6"
  surface: "#ffffff"
  text: "#253631"
  secondary-text: "#61716b"
  border: "#dde5df"
  focus: "#5269bb"
  client-border: "#dce5dd"
  client-primary-hover: "#25543f"
  client-error: "#a4473b"
  input-border: "#cdd9ce"
typography:
  client-headline:
    fontFamily: 'ui-sans-serif, system-ui, "Segoe UI", Roboto, Helvetica, Arial, sans-serif'
    fontSize: "30px"
    fontWeight: 650
    lineHeight: 1.25
    letterSpacing: "-0.035em"
  client-title:
    fontFamily: 'ui-sans-serif, system-ui, "Segoe UI", Roboto, Helvetica, Arial, sans-serif'
    fontSize: "17px"
    fontWeight: 650
    letterSpacing: "-0.02em"
  client-body:
    fontFamily: 'ui-sans-serif, system-ui, "Segoe UI", Roboto, Helvetica, Arial, sans-serif'
    fontSize: "14px"
    lineHeight: 1.55
  headline:
    fontFamily: 'ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif'
    fontSize: "29px"
    fontWeight: 650
    lineHeight: 1.25
    letterSpacing: "-0.035em"
  title:
    fontFamily: 'ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif'
    fontSize: "16px"
    fontWeight: 650
    letterSpacing: "-0.015em"
  body:
    fontFamily: 'ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif'
    fontSize: "14px"
    lineHeight: 1.5
rounded:
  button: "6px"
  node: "8px"
  panel: "10px"
spacing:
  compact: "8px"
  panel-gap: "20px"
  client-panel-padding: "24px"
  client-panel-gap: "22px"
  client-grid-gap: "24px"
  workspace: "32px"
components:
  client-button:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.surface}"
    rounded: "{rounded.button}"
    padding: "10px 14px"
  client-input:
    backgroundColor: "{colors.surface}"
    textColor: "#293e30"
    rounded: "{rounded.button}"
    padding: "10px 12px"
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.surface}"
    rounded: "{rounded.button}"
    padding: "8px 10px"
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "#526559"
    rounded: "{rounded.button}"
    padding: "8px 10px"
  panel:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.panel}"
---

# Design System: PrivacyGate AI client workspace

## Overview

**Creative North Star: "Light control room"**

A daylight operations workspace with white surfaces, a pale sage canvas, restrained green actions, purple chain reads, and amber chain writes. Familiar sans-serif text and explicit labels make the network understandable without specialist knowledge.

Scope includes the network overview and all nonhome pages: My devices (`/dashboard`), Shared insights (`/insights`), Sign in (`/login`), and the technical reference. A shared light shell puts client tasks first and supplies a persistent Back to network link. This is a visual-design record; `docs/DESIGN.md` remains the authoritative architecture and threat model. The overview describes simulated activity, not measured service health. Sign-in retains the existing wallet authentication; presentation changes do not demonstrate completed backend integration.

**Key Characteristics:**

- Light surfaces with subtle borders.
- Plain client task names and a persistent way back to the network.
- A selectable network map with a plain-language inspector.
- Explicit data, chain-read, and chain-write labels.
- A guided walkthrough with an activity feed and simple panels.

## Colors

Muted natural neutrals support three distinct connection roles. Exact primitives are in the frontmatter.

### Primary

- **Forest green:** primary walkthrough action and completion state.
- **Deep forest:** primary action hover.
- **River green:** off-chain data connections.

### Secondary

- **Muted violet:** chain permission reads.
- **Warm amber:** owner permission writes.
- **Brick red:** blocked delivery and uncertain permission status.

### Neutral

- **Sage paper:** workspace canvas.
- **White:** navigation, panels, and nodes.
- **Forest ink:** principal text.
- **Muted sage ink:** secondary descriptions.
- **Pale sage line:** panel borders and dividers.
- **Slate indigo:** keyboard focus outline.

**The Connection Label Rule.** Pair connection colors with written roles and directional arrows; color alone must not explain the network.

## Typography

Display and body use the system sans-serif stack in the frontmatter. The main heading is compact rather than promotional; section titles establish hierarchy while descriptions remain quiet.

- Main heading uses the headline token; compact screens reduce it to (25px).
- Section titles use the title token. The inspector title is (18px, weight 600).
- Workspace text inherits the body token. Descriptions typically use (11–12px).
- Map labels and status text use (8–10px); compact node names use (13px). These small labels describe this implemented overview rather than a recommended minimum for future forms.

## Layout

The desktop grid has a navigation column (224px) and flexible workspace. Content is capped at (1600px) with workspace padding from the frontmatter. The map sits beside an inspector (250px); the activity and access-summary panels form a lower two-column grid with the panel-gap token.

At (1250px), navigation and inspector narrow. At (1020px), navigation moves above the workspace. At (760px), the inspector follows the map and lower panels stack; content uses horizontal padding (18px). At (480px), nodes become a vertical list with explicit per-node connection descriptions. Connector graphics are hidden in that compact list, and no line implies a sequential pipeline. Progress steps become two columns.

Task pages share a navigation column (224px), white top bar, and content capped at (1400px), with desktop padding (35px 32px 20px). The task grid uses a right rail (310px), narrowing to (275px) at (1250px). At (1050px), navigation moves above the task content; at (760px), the rail and sign-in layout stack. Forms collapse from two columns to one at (480px). The Back to network link remains in the top bar on compact screens.

## Elevation & Depth

One-pixel borders and tonal layering carry depth. Main panels have no shadow. The selected scenario control uses a small structural shadow (`0 1px 3px #23342618`). Selected map nodes use a pale surrounding outline, not a floating effect.

## Shapes

Buttons, nodes, and panels use the gently curved radii in the frontmatter. Tiny circular status markers accompany text. Network paths use straight segments and restrained directional arrowheads; the background uses a subtle dotted grid.

## Components

### Buttons

Compact and explicit. The primary action uses forest green; secondary and icon controls use white with a thin border. Hover changes background over (150ms). Keyboard focus uses an outline (3px) with offset (4px) on the overview and (3px) on task pages. Task controls have minimum height (40px) and use the client-button token; task hover uses client-primary-hover. Disabled controls reduce opacity to (.45). Controls do not move on hover.

### Navigation

White navigation with muted default links, a pale green active item, and a green active label. Active navigation is marked with `aria-current`. Labels are Network overview, My devices, and Shared insights, with Sign in as the authentication entry. On narrower screens navigation becomes a horizontal row above the content. Each nonhome page has a persistent Back to network link.

### Panels

White bordered panels group the map, walkthrough, and activity. The access summary uses a pale green fill. Internal padding is typically (19–22px). The map inspector uses definition-list labels for sends, receives, and blockchain connection. Task cards use the client-panel-padding and client-panel-gap tokens, reducing padding to (20px) on narrower screens. Task cards have no shadows.

### Network nodes

Keyboard-operable buttons with `aria-pressed` selected state. A selected node uses green border and pale green fill. Status labels describe the walkthrough state. The compact list states each node's connection in text.

### Scenario controls and activity

Three scenario buttons switch local state among allowed access, confirmed revocation, and chain outage. The selected button uses a white surface on a pale green track. Four walkthrough stages feed an ordered activity list. Playback supports run, pause, next step, replay, and reset. Connector flow uses a repeating linear animation (1s); reduced-motion preference removes that animation and button transitions.

### Inputs and task states

Task inputs use white fill, the input-border token, button radius, and client-input sizing as a minimum height. Labels remain visible, hints sit below fields, and inputs receive the shared focus outline. Empty states explain the next action; setup details use disclosure controls. Errors use pale warm surfaces with red text; badges pair state words with color. These controls present existing wallet-based workflows, not a new authentication scheme.

### Demo status

An amber-tinted illustrative-demo badge and explicit notice identify the simulated map and activity. There are no inputs on this overview.

## Do's and Don'ts

### Do:

- **Do** keep simulation status visible beside the overview heading and activity.
- **Do** describe sends, receives, and blockchain connection in the inspector.
- **Do** preserve visible keyboard focus and selected state.
- **Do** retain client task labels and a visible Back to network link on nonhome pages.
- **Do** use explicit connection descriptions in the compact node list.

### Don't:

- **Don't** present simulated activity as measured connectivity or confirmed real transactions.
- **Don't** imply that the compact list is a linear data pipeline.
- **Don't** put raw telemetry, private keys, or plaintext insight content in overview examples.
