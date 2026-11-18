/**
 * How wide the sidebar is while it shows a section's tree (ADR-0021): wide enough for the longest organization, site
 * or device name in the whole tree, collapsed branches included, so it does not change size as branches open and close
 * or the filter narrows the list; within limits, past which names are cut short with an ellipsis and shown in full on
 * hover.
 */

/** A row of the tree, as far as its width goes. */
export interface RowSpec {
  text: string;
  level: 1 | 2 | 3;
  /** The count at the end of the row; a pill for alert counts. */
  badge?: { text: string; pill: boolean } | null;
  /** Whether the row has a quick-connect button. */
  quick?: boolean;
}

/** The width of text in a row's name, plain count or pill count font. */
export type Measure = (text: string, font: "row" | "badge" | "pill") => number;

// A row's geometry in CSS pixels, from the classes SectionTree gives it.
const AREA = 16; // the scrolling area's px-2, both sides
const INDENT = { 1: 4, 2: 16, 3: 28 } as const; // pl-1, pl-4, pl-7
const LEAD = 16 + 6 + 16 + 6; // the chevron, a gap, the icon (16 on the top rows, 14 in the tree), a gap
const GAP = 6; // gap-1.5
const END = 6; // pr-1.5
const QUICK = 24; // the quick-connect button
const PILL_PAD = 12; // px-1.5 on both sides
const PILL_MIN = 20; // min-w-5

export function rowWidth(r: RowSpec, measure: Measure): number {
  let w = AREA + INDENT[r.level] + LEAD + measure(r.text, "row") + END;
  if (r.badge) w += GAP + (r.badge.pill ? Math.max(PILL_MIN, measure(r.badge.text, "pill") + PILL_PAD) : measure(r.badge.text, "badge"));
  if (r.quick) w += GAP + QUICK;
  return w;
}

/** The width a tree asks for: its widest row and the platform's scroll bar, in whole pixels. */
export function treeWidth(rows: Iterable<RowSpec>, measure: Measure, scrollbar = 0): number {
  let widest = 0;
  for (const r of rows) widest = Math.max(widest, rowWidth(r, measure));
  return Math.ceil(widest + scrollbar);
}

/**
 * The sidebar's CSS width for a tree that asks for `wanted` pixels: at least the main menu's 15rem, at most 24rem and
 * a third of the window. The menu drawer on small screens may take up to 85% of the screen.
 */
export function sidebarWidth(wanted: number, drawer = false): string {
  return drawer ? `clamp(16rem, ${wanted}px, 85vw)` : `clamp(15rem, ${wanted}px, min(24rem, 33.3vw))`;
}

/**
 * Measures text in the sidebar's fonts with a canvas. Names are measured at the selected row's medium weight, so
 * selecting a row never cuts its name short. Without a canvas (tests) it estimates generously from the length.
 */
export function textMeasure(family: string): Measure {
  const ctx = typeof OffscreenCanvas === "undefined" ? null : new OffscreenCanvas(1, 1).getContext("2d");
  const fonts = { row: `500 14px ${family}`, badge: `400 12px ${family}`, pill: `600 12px ${family}` };
  const cache = new Map<string, number>();
  return (text, font) => {
    const key = `${font}\u0000${text}`;
    let w = cache.get(key);
    if (w === undefined) {
      if (ctx) {
        ctx.font = fonts[font];
        w = ctx.measureText(text).width;
      } else {
        w = text.length * (font === "row" ? 8 : 7);
      }
      cache.set(key, w);
    }
    return w;
  };
}

let scrollbar: number | undefined;

/** The width of the platform's scroll bar: 0 where scroll bars overlay the content. */
export function scrollbarWidth(): number {
  if (scrollbar === undefined) {
    const probe = document.createElement("div");
    probe.style.cssText = "position:absolute;top:-200px;visibility:hidden;width:100px;height:100px;overflow:scroll";
    document.body.appendChild(probe);
    scrollbar = probe.offsetWidth - probe.clientWidth;
    probe.remove();
  }
  return scrollbar;
}
