# Diagrams

The documentation's diagrams are drawn with the
[diagram-design](https://github.com/cathrynlavery/diagram-design) skill for
Claude Code, in an EasyRMM style: always dark, on the console's dark
surface, in [DESIGN.md](../../../DESIGN.md)'s colours and system fonts, so
they read the same in GitHub's light and dark themes.

| Diagram | Shown in |
|---|---|
| [architecture.svg](architecture.svg) | [README](../../../README.md), [architecture overview](../../architecture/overview.md) |
| [remote-session.svg](remote-session.svg) | [architecture overview](../../architecture/overview.md#5-meshcentral-integration) |
| [agent-enrollment.svg](agent-enrollment.svg) | [installing the agent](../../deployment/agents.md), [architecture overview](../../architecture/overview.md#6-endpoint-one-installation) |
| [patching-engine.svg](patching-engine.svg) | [patching engine](../../architecture/patching-engine.md) |
| [patch-job-lifecycle.svg](patch-job-lifecycle.svg) | [patching engine](../../architecture/patching-engine.md#jobs) |
| [patching-agent-install.svg](patching-agent-install.svg) | [the EasyPatch agent](../../deployment/patching-agent.md#installing-it-from-easyrmm) |

## Changing a diagram

Each `src/<name>.html` is the source, and `<name>.svg` is exported from it.

1. Install the diagram-design plugin and save a profile named `easyrmm`
   (`~/.diagram-design/profiles/easyrmm.md`) with the values below. The
   `.diagram-design` file at the repository root selects it.
2. Edit `src/<name>.html`. Keep the skill's rules: right-angle connectors
   with rounded corners, arrow labels of at most 14 characters in capitals,
   at most 9 boxes, one or two accent elements, a 4 px grid, and a `<title>`
   and `<desc>` that say what the diagram shows.
3. From the plugin's `skills/diagram-design/` directory, check it and export it:

   ```bash
   python3 scripts/self_check.py <repo>/docs/images/diagrams/src/<name>.html
   python3 scripts/verify_geometry.py <repo>/docs/images/diagrams/src/<name>.html
   python3 scripts/export_svg.py <repo>/docs/images/diagrams/src/<name>.html <repo>/docs/images/diagrams/<name>.svg --system-fonts
   ```

4. Look at the SVG as an image (as GitHub shows it) before committing.

## The EasyRMM profile

The profile is the skill's style guide with these values; light and dark
are the same.

| Role | Value | From DESIGN.md |
|---|---|---|
| `paper` | `#121824` | dark `surface` |
| `paper-2` | `#171e2c` | dark `raised` |
| `ink` | `#e6ebf2` | dark `fg` |
| `ink-strong` | `#06101f` | `accent-fg` |
| `muted` | `#9aa6b8` | dark `muted` |
| `soft` | `#8793a7` | between `muted` and `subtle` (4.5:1 or better) |
| `rule` | `rgba(230,235,242,0.12)` | `fg` at 12 % |
| `rule-solid` | `#33415a` | dark `line-strong` |
| `accent` | `#4f8cff` | `accent` |
| `accent-tint` | `rgba(79,140,255,0.12)` | `accent` at 12 % |
| `link` | `#22d3ee` | `info` |

Fonts: `Font source: system`, with DESIGN.md's stacks:
`ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif`
for names, and
`ui-monospace, SFMono-Regular, 'Cascadia Mono', 'Segoe UI Mono', Menlo, Consolas, monospace`
for sublabels, tags and arrow labels. Back-end boxes are filled with
`paper-2` and outlined in `ink` at 45 %.
