---
name: EasyRMM
description: Technician console for EasyRMM, built on EasyPatch's design system adopted as-is.
colors:
  # Dark theme (default, <html class="dark">)
  canvas: "#0b0f17"
  surface: "#121824"
  raised: "#171e2c"
  hover: "#1c2433"
  line: "#243044"
  line-strong: "#33415a"
  fg: "#e6ebf2"
  muted: "#9aa6b8"
  subtle: "#6b778b"
  accent: "#4f8cff"
  accent-hover: "#6a9dff"
  accent-fg: "#06101f"
  accent-soft: "#15233d"
  ok: "#4ade80"
  ok-soft: "#12291d"
  warn: "#fbbf24"
  warn-soft: "#2d2410"
  danger: "#f87171"
  danger-soft: "#2f1517"
  info: "#22d3ee"
  info-soft: "#0f2a31"
  neutral-soft: "#1e2635"
  focus: "#6a9dff"
  sidebar: "#080b12"
  sidebar-fg: "#a3aec0"
  sidebar-active: "#172033"
  # Light theme (:root without .dark)
  canvas-light: "#f4f6f9"
  surface-light: "#ffffff"
  raised-light: "#f8fafc"
  hover-light: "#eef2f7"
  line-light: "#dde3ea"
  line-strong-light: "#c5ced9"
  fg-light: "#0f172a"
  muted-light: "#5b6678"
  subtle-light: "#8a94a6"
  accent-light: "#2563eb"
  accent-hover-light: "#1d4ed8"
  accent-fg-light: "#ffffff"
  accent-soft-light: "#e7efff"
  ok-light: "#15803d"
  ok-soft-light: "#e3f6ea"
  warn-light: "#b45309"
  warn-soft-light: "#fdf1df"
  danger-light: "#c62828"
  danger-soft-light: "#fde8e8"
  info-light: "#0e7490"
  info-soft-light: "#e0f4f8"
  neutral-soft-light: "#edf0f4"
  focus-light: "#2563eb"
  sidebar-light: "#0f172a"
  sidebar-fg-light: "#cbd5e1"
  sidebar-active-light: "#1e293b"
typography:
  headline:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "1.25rem"
    fontWeight: 600
    lineHeight: 1.4
  stat:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "1.5rem"
    fontWeight: 600
    lineHeight: 1.333
    fontFeature: "tnum"
  title-auth:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 600
    lineHeight: 1.556
  title-dialog:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "1rem"
    fontWeight: 600
    lineHeight: 1.5
  title-card:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 600
    lineHeight: 1.429
  body:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.45
  label:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 500
    lineHeight: 1.333
  table-head:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 600
    lineHeight: 1.333
    letterSpacing: "0.025em"
  mono:
    fontFamily: "ui-monospace, SFMono-Regular, 'Cascadia Mono', 'Segoe UI Mono', Menlo, Consolas, monospace"
    fontSize: "0.75rem"
    fontWeight: 400
    lineHeight: 1.333
rounded:
  sm: "4px"
  md: "6px"
  lg: "8px"
  xl: "12px"
  full: "9999px"
spacing:
  xs: "4px"
  sm: "8px"
  form: "14px"
  md: "16px"
  lg: "20px"
  page-x-sm: "24px"
  page-x-lg: "32px"
  content-max: "1440px"
  sidebar: "240px"
  header: "56px"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.accent-fg}"
    rounded: "{rounded.md}"
    padding: "0 14px"
    height: "34px"
  button-primary-hover:
    backgroundColor: "{colors.accent-hover}"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.fg}"
    rounded: "{rounded.md}"
    padding: "0 14px"
    height: "34px"
  button-secondary-hover:
    backgroundColor: "{colors.hover}"
  button-ghost:
    textColor: "{colors.fg}"
    rounded: "{rounded.md}"
    padding: "0 14px"
    height: "34px"
  button-danger:
    backgroundColor: "{colors.danger}"
    rounded: "{rounded.md}"
    padding: "0 14px"
    height: "34px"
  button-danger-ghost:
    textColor: "{colors.danger}"
    rounded: "{rounded.md}"
  button-danger-ghost-hover:
    backgroundColor: "{colors.danger-soft}"
  button-sm:
    rounded: "{rounded.md}"
    padding: "0 10px"
    height: "28px"
  input:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.fg}"
    rounded: "{rounded.md}"
    padding: "6px 12px"
    height: "34px"
  card:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.lg}"
    padding: "16px"
  card-header:
    typography: "{typography.title-card}"
    padding: "10px 16px"
  stat-tile:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.lg}"
    padding: "12px 16px"
  table-head-cell:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.muted}"
    typography: "{typography.table-head}"
    padding: "8px 12px"
  table-row-hover:
    backgroundColor: "{colors.hover}"
  badge:
    typography: "{typography.label}"
    rounded: "{rounded.full}"
    padding: "2px 8px"
  badge-ok:
    backgroundColor: "{colors.ok-soft}"
    textColor: "{colors.ok}"
  badge-warn:
    backgroundColor: "{colors.warn-soft}"
    textColor: "{colors.warn}"
  badge-danger:
    backgroundColor: "{colors.danger-soft}"
    textColor: "{colors.danger}"
  badge-info:
    backgroundColor: "{colors.info-soft}"
    textColor: "{colors.info}"
  badge-neutral:
    backgroundColor: "{colors.neutral-soft}"
    textColor: "{colors.muted}"
  badge-accent:
    backgroundColor: "{colors.accent-soft}"
    textColor: "{colors.accent}"
  nav-item:
    textColor: "{colors.sidebar-fg}"
    rounded: "{rounded.md}"
    padding: "8px 12px"
  nav-item-active:
    backgroundColor: "{colors.sidebar-active}"
    textColor: "#ffffff"
  dialog:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.xl}"
  auth-panel:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.xl}"
    padding: "24px"
  kbd:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.muted}"
    rounded: "{rounded.sm}"
    padding: "0 4px"
---

# Design System: EasyRMM

## Overview

**Creative North Star: "The Sister Console"**

EasyRMM uses EasyPatch's design system, adopted as-is. This is the owner's binding instruction, recorded in ADR 0013 (`docs/architecture/adr/0013-easypatch-design-system.md`): a technician moving between the EasyPatch and EasyRMM consoles should not notice a change of product family. The upstream source of truth for every token is EasyPatch's `frontend/src/index.css`; `web/src/index.css` mirrors it value for value (verified by diff), and the primitives in `web/src/components/` follow EasyPatch's component vocabulary (same classes, variants, tones and states). Change a shared token in EasyPatch first, then mirror it here. Never fork a value locally.

The system is calm, dense and flat operator UI. Bordered surfaces on a dark canvas, one blue accent, four status tones with soft fills, a navy sidebar, the system UI font at a 14px base. Nothing decorative; every tile, badge and row is server data.

EasyRMM's additions on top of the shared system are each marked "(EasyRMM addition)" below. The first five serve keyboard travel and toolbar alignment: `kbd` styling, a uniform `.input` min-height so toolbar inputs and selects line up with buttons, a `focus-within` row tint for j/k travel, a `narrow` variant of KeyValueList, and `hideLegend` on AssignmentEditor. Everything else is EasyPatch's.

**Key Characteristics:**
- EasyPatch's tokens, components and both themes, unchanged; EasyPatch `frontend/src/index.css` is upstream.
- Dark theme by default, class-based (`<html class="dark">`), with a light theme toggle in the header.
- Flat bordered surfaces; shadows are hairline (`shadow-xs`) at rest and only lift for overlays.
- System UI stack, 14px base, tabular figures for counts.
- Keyboard-first operation: j/k row travel with prefetch, "/" to search, live filter readouts.

## Colors

One restrained blue accent over cool slate neutrals, with four semantic status tones each paired with a soft fill. Every color is a semantic CSS custom property defined twice (`:root` light, `.dark` dark) and exposed to Tailwind as `bg-surface`, `text-muted`, `border-line` and so on through `@theme inline`; components never use raw palette colors.

### Primary
- **Console Blue** (accent): primary buttons, active tab underline, links ("View all", "Forgot your password?"), focused input border, checkbox accent. Hover deepens in light (accent-hover) and brightens in dark.
- **Accent Soft** (accent-soft): accent badge fill and text selection.

### Status tones
- **OK Green / Warn Amber / Danger Red / Info Cyan** (ok, warn, danger, info): text and icon color for state. Each has a `-soft` fill used behind it in badges, alerts and the one-time notice. Danger also fills the destructive button.
- **Neutral Soft** (neutral-soft): neutral badge fill, inline monospace chips.

### Neutral
- **Canvas** (canvas): page background behind everything.
- **Surface** (surface): cards, tables, header bar, inputs, dialogs, toasts, auth panel.
- **Raised** (raised): table head row, code blocks, `kbd` keys.
- **Hover** (hover): row hover, row focus-within, ghost and secondary button hover.
- **Line / Line Strong** (line, line-strong): every border and divider.
- **Foreground / Muted / Subtle** (fg, muted, subtle): primary text; secondary text, labels and table heads; hints, placeholders, empty-state icons.
- **Navy Sidebar** (sidebar, sidebar-fg, sidebar-active): the sidebar is dark in both themes; active and hovered items sit on sidebar-active with white text.

### Named Rules
**The Semantic Token Rule.** Components reference semantic tokens only (`surface`, `line`, `muted`, `danger-soft`), so both themes stay consistent. The only literal colors in shipped components are white text on the navy sidebar and on the danger button (with `#1a0606` danger-button text in dark).

**The Upstream Rule.** A token value changes in EasyPatch's `frontend/src/index.css` first and is mirrored here; EasyRMM does not diverge.

## Typography

**Body Font:** system UI stack (ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, Arial, sans-serif)
**Mono Font:** ui-monospace, SFMono-Regular, Cascadia Mono, Segoe UI Mono, Menlo, Consolas, monospace

**Character:** The native UI face of the operator's own OS, set small and dense. No web fonts (the strict CSP forbids runtime font loading, and the sister console uses none).

### Hierarchy
- **Headline** (600, 20px): page title (`PageHeader` h1), truncated on one line, with a 14px muted subtitle and an optional 12px breadcrumb above.
- **Stat** (600, 24px, tabular figures): the value in a stat tile.
- **Auth title** (600, 18px): sign-in, setup and MFA panel heading.
- **Dialog title** (600, 16px).
- **Card title** (600, 14px): card header rows.
- **Body** (400, 14px, line-height 1.45): base text; table cells and most content are 14px.
- **Label** (500, 12px, muted): form labels, key-value terms, stat labels, badges. Hints and field errors are 12px at 400.
- **Table head** (600, 12px, uppercase, 0.025em tracking, muted, no wrap).
- **Mono** (12px): IDs, codes, secrets, the typed confirmation name; `kbd` keys at 11px.

### Named Rules
**The Tabular Count Rule.** Counts that sit in columns or tiles use tabular figures so they align.

## Layout

App shell: a 240px (`w-60`) navy sidebar fixed at the left from `lg` up; below `lg` it is hidden and opens as a 256px drawer over a 50% black scrim from a menu button in the header. The header is 56px tall (`h-14`), surface-colored with a bottom line, and holds the theme toggle on the right (and the logo on small screens); its status slot stays empty until a live readout exists. A "Skip to content" link precedes everything.

Main content scrolls independently with page padding of 16px horizontally on phones, 24px from `sm`, 32px from `lg`, and 20px vertically, inside a centered column capped at 1440px.

Page grammar: `PageHeader` (20px bottom margin), optional `Toolbar` (wrapping row of fields aligned to their bottom edge, 8px gaps, 12px bottom margin), then content. Card grids are single column, splitting at `xl` into 2 or 3 columns with 20px gaps and `items-start`, so each card keeps its own height. Stat tiles run 2 across, 4 from `md`, with 12px gaps.

Rhythm: 8px is the default gap between controls; forms stack fields at 14px; cards pad 16px with a 10px by 16px header row; dialogs pad 20px horizontally.

Phone behaviour: tables never reflow into cards. Secondary columns drop out with `hidden sm:table-cell`, `hidden md:table-cell` or `hidden lg:table-cell` so the primary column always survives, and `TableWrap` scrolls horizontally if needed. Key-value lists stack to one column below `sm`. Tabs scroll horizontally.

Auth pages: a centered column (384px, 448px when wide) with the large logo above a 12px-radius surface panel, and the theme toggle pinned top right.

### Named Rules
**The Own-Height Rule.** Cards in a grid align to the top (`items-start`) and never stretch to match a neighbour.

**The Column Shedding Rule.** On narrow screens a table hides secondary columns by breakpoint; it never turns into a stack of cards.

## Elevation & Depth

Flat, layered by border and tone rather than shadow. Surfaces at rest carry a hairline shadow at most; real elevation is reserved for things that float above the page.

### Shadow Vocabulary
- **Hairline** (`shadow-xs`: 0 1px 2px 0 rgb(0 0 0 / 0.05)): cards, stat tiles, inputs, primary/secondary/danger buttons.
- **Panel** (`shadow-sm`): the auth panel.
- **Toast** (`shadow-lg`): toasts and menus.
- **Drawer** (`shadow-xl`): the mobile sidebar drawer, and the device tree over the page below `lg`.
- **Modal** (`shadow-2xl`): dialogs, over a `rgb(2 6 23 / 0.6)` backdrop.

### Named Rules
**The Float-Only Lift Rule.** Only overlays (toast, menu, drawer, dialog) get more than a hairline shadow. The device tree docked beside the page is part of the layout and stays flat; over the page on narrow screens it is a drawer.

## Shapes

Gently rounded rectangles with 1px borders in `line`. Radius steps by size of the object: 4px for `kbd` and inline mono chips, 6px for buttons, inputs, nav items, alerts and code blocks, 8px for cards, stat tiles, table wraps and toasts, 12px for dialogs and the auth panel, full round for badges and status dots. `kbd` keys have a 2px bottom border to read as physical keys.

## Components

### Buttons
Compact and quiet; weight comes from fill, not size.
- **Shape:** 6px radius, medium weight, icon gap 6px. Medium is 34px tall with 14px sides at 14px text; small is 28px with 10px sides at 12px text.
- **Primary:** accent fill, accent-fg text; hover to accent-hover.
- **Secondary (default):** surface fill, line border, fg text; hover to hover tint.
- **Ghost:** transparent; hover to hover tint.
- **Danger:** danger fill, white text (near-black in dark); hover to 90% opacity. **Danger ghost:** danger text, danger-soft fill on hover.
- **Loading / disabled:** loading swaps the icon for a spinner and sets `aria-busy`; disabled is 55% opacity with a not-allowed cursor.
- **Icon button:** 32px square, muted icon, hover tint, label in `aria-label` and `title`.

### Badges and dots
Small pills (full radius, 2px by 8px, 12px medium) in six tones: ok, warn, danger, info, neutral, accent, each soft fill with the tone as text. Status dots are 8px circles in the solid tone. User state (Active, MFA pending, Invited, Locked, Disabled) and audit outcome (Success, Failed, Denied) map to fixed tones and carry an explanatory `title`.

### Cards / Containers
- **Corner Style:** 8px.
- **Background:** surface, line border, hairline shadow.
- **Header:** optional row with a 14px semibold title and actions, separated by a bottom line, 10px by 16px.
- **Internal Padding:** 16px, or none for flush tables and lists.
- **Stat tile:** label row (12px muted, optional subtle icon), 24px tabular value, optional hint or link.

### Inputs / Fields
- **Style:** surface fill, line border, 6px radius, 6px by 12px padding, 14px text, subtle placeholder, hairline shadow. Inputs, selects and textareas share the `.input` class; every input and select is at least 34px tall so toolbar fields line up with medium buttons (EasyRMM addition).
- **Focus:** border turns accent with a 2px accent ring at 30%.
- **Error:** `aria-invalid` turns border danger with a danger ring; the message replaces the hint below in 12px danger.
- **Disabled:** 60% opacity, not-allowed cursor.
- **Field:** 12px muted label above (danger asterisk when required), 4px gap, 12px subtle hint or error below.
- **Search:** a search field with a 14px subtle magnifier inside, `aria-keyshortcuts="/"`, and a live readout in the hint slot ("3 of 12 organizations").

### Tables
Full-width, collapsed borders, 14px. Head row on raised with uppercase 12px muted labels; cells 8px by 12px with a bottom line (none on the last row). Rows tint to hover on pointer hover and on `focus-within`, so the row whose link has keyboard focus reads as selected (EasyRMM addition). Wrapped in an 8px-radius bordered surface that scrolls horizontally.

### Key-value lists
Terms in 12px muted, values in 14px fg (an em dash when empty). One column on phones; from `sm` a two-column grid with terms at least 9rem. The `narrow` variant (EasyRMM addition) narrows the term column to 6.5rem with a 16px gap for side cards.

### Tabs
Bottom-bordered strip, 14px medium items; the selected tab has a 2px accent underline and fg text, others muted with fg on hover. Arrow keys move between tabs.

### Dialogs
Native `<dialog>` (browser focus trap, Escape, top layer) at 12px radius on surface, widths 448 / 576 / 768px, never taller than the viewport minus 32px. Header with a 16px title, optional muted description and close button; scrolling body; right-aligned footer. Focus returns to the opener on close.
- **Confirm dialog:** small width; destructive actions use the danger button and require typing the object's name (shown in mono) before the confirm button enables.
- **Non-dismissible:** while a one-time secret is shown (invitation or password link, authenticator setup), Escape, backdrop and the close button are disabled until the user acts.

### One-time notice and copy
A warn-soft banner with a shield icon, "Copy this now. You will not see it again.", above code blocks (raised, 6px radius, 12px mono) that carry a copy button which confirms with "Copied" or "Copy failed".

### Alerts and toasts
Alerts are 6px-radius bordered blocks in a tone's soft fill with a 40% tone border and a tone icon. Toasts stack bottom right (max 24rem, five at most), surface with a line border, slide up 8px over 160ms (none under reduced motion), and dismiss after 5s, or 9s for errors.

### Empty, loading and error states
Centered, quiet: a subtle 32px icon, a medium fg title and muted body, optional action. Error states distinguish "Not found" and "Not available to your role" from load failures, which offer Retry.

### Menus (EasyRMM addition)
`MenuButton` follows the WAI-ARIA menu button pattern: a button with a trailing chevron that turns over while open, and below it a surface panel (line border, 8px radius, 4px padding, `shadow-lg`, at least 12rem) of menu items with 16px icons. It aligns to the button's right edge and flips to its left when that would leave the viewport. The first item takes focus on open; arrow keys, Home and End move, Escape closes and returns focus, Tab and a click outside close. The device page uses it so each remote session opens **In this tab** or **In a new window**.

### Device tree dock (EasyRMM addition)
A **Tree** toggle (pressed state in accent-soft with a 40% accent border) in the devices pages' header opens a 20rem dock at the right of the page: surface, line border on its left, no shadow, entering over 180ms (12px slide, none under reduced motion). It holds a header (title, Collapse all, close), a filter with a live count, an **All devices** row, and the WAI-ARIA tree of organizations, sites and devices: 28px rows indented 16px a level, chevrons, building, pin and status-dot icons, online/total counts in muted tabular figures, the row for the page's organization, site or device in accent-soft and medium weight. From `lg` it sits beside the page and is remembered in the browser; below `lg` it opens over the page as a drawer with a scrim and closes after a choice.

### Code and script output (EasyRMM addition)
Scripts and their output are the content of the scripts and jobs pages, so they are shown as code, never restyled as prose.
- **Code view:** a script on raised with a line border and 6px radius, 12px mono at relaxed leading, line numbers in a subtle right-aligned gutter that selection skips, lines never wrapped (the block scrolls sideways, at most 36rem tall), and the copy button at top right.
- **Output view:** each stream (standard output, standard error) under a 12px muted heading with its own copy button; the text keeps its spacing and line breaks but wraps long lines, at most 32rem tall. An empty stream is a dashed-border line in muted text, not an empty box; a stream cut in the middle says so under it.
- **Run status:** Queued (neutral), Delivered and Running (info, Running with a dot), Succeeded (ok), Failed (danger), Timed out, Expired and No result (warn), Canceled (neutral); a running script with a stop requested reads Canceling (warn). A job's state sums its runs (Waiting, Running, Succeeded, Some failed, Failed, Partly canceled, Canceled), and its progress is the non-zero counts as dot, tabular count and muted status word.
- **Device picker:** in the run dialog, a bordered list (16rem tall) of checkbox rows (name over muted organization / site, online dot at the right) under a filter and an All toggle that goes indeterminate for a partial choice; the selected count sits at the left of the dialog's buttons.

### Navigation
The navy sidebar holds the wordmark (on-dark variant in both themes), primary items (14px, 16px icons, 8px by 12px, 6px radius; active on sidebar-active with white medium text), and at its foot the account link (name over platform role or email) and Sign out above a 10% white divider. Elsewhere the wordmark switches between `wordmark.svg` (dark) and `wordmark-light.svg` (light) next to `logo.svg`.

### Keyboard signatures
- **Row travel:** j/k (and arrow keys while a row link has focus) move between a table's row links; the focused row scrolls into view, takes the focus-within tint, and its detail is prefetched so it opens instantly.
- **"/"** focuses the page's search from anywhere outside a text field.
- **`kbd`** (EasyRMM addition): 11px mono keys on raised with a line border and 2px bottom edge, used to teach these shortcuts in place.

### Sign-in
The sign-in button stays enabled and names empty fields ("Enter your email address.", "Enter your password.") instead of disabling: password managers fill fields without notifying React, and a disabled button would swallow their first click.

### AssignmentEditor
Role assignment rows (role, organization, site) under a "Roles" legend; `hideLegend` (EasyRMM addition) keeps the legend for screen readers only when the surrounding dialog already titles it.

## Do's and Don'ts

### Do:
- **Do** take every token from EasyPatch's `frontend/src/index.css`; mirror changes there first.
- **Do** use semantic token classes (`bg-surface`, `text-muted`, `border-line`, tone `-soft` fills) so both themes hold.
- **Do** keep dark as the default theme and toggle with the `dark` class on `<html>`.
- **Do** keep cards in grids top-aligned with their own height (`items-start`).
- **Do** hide secondary table columns below `sm`/`md`/`lg` rather than reflowing tables.
- **Do** keep toolbar inputs, selects and medium buttons at the shared 34px height.
- **Do** give list tables j/k row travel with prefetch, "/" search, and a live match readout when filtering.
- **Do** show one-time secrets in a non-dismissible dialog with the one-time notice and a copy control.
- **Do** require typing the object's name before a destructive delete.
- **Do** use the product's nouns: organization, site, device group, device, technician.
- **Do** show real API data only, with empty, loading, error, forbidden and read-only states.

### Don't:
- **Don't** fork a token value or add a local palette color in EasyRMM.
- **Don't** load web fonts; the system UI stack is the face.
- **Don't** put more than a hairline shadow on anything that is not an overlay.
- **Don't** disable the sign-in button for empty fields; name the missing field instead.
- **Don't** show placeholders, sample rows or fake data, and don't show a feature before it exists.
