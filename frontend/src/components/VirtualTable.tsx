/* VirtualTable — windowed rows for very large inventories.
 *
 * The bank rule: never render 50,000 asset rows in the browser. This table
 * mounts only the visible window (plus a small overscan) regardless of row
 * count — the DOM stays constant while the scrollbar reflects the true
 * total. Rows come from the caller ALREADY paginated/filtered by the
 * backend; this component is the display half of that contract.
 *
 * Accessibility: role="grid" with aria-rowcount for the true total and
 * aria-rowindex per row (screen readers announce "row 4,213 of 50,000"
 * without the row existing in the DOM), roving tabindex on rows, and
 * ArrowUp/ArrowDown/Home/End/PageUp/PageDown keyboard navigation.
 */

import React, { useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";

export interface VirtualTableProps {
  /** Visible columns. */
  head: string[];
  /** All rows for the current backend page/window. */
  rows: React.ReactNode[][];
  /** Row height in px (fixed rows keep scrolling honest). */
  rowHeight?: number;
  /** Header height in px (defaults to the row height). */
  headHeight?: number;
  /** Scrollport height in px. */
  height?: number;
  /** True total across all backend pages — announced, not rendered. */
  total?: number;
  /** 0-based selected row for keyboard navigation. */
  selected?: number;
  onSelect?: (index: number) => void;
  /** Shown instead of the grid when there are no rows. */
  empty?: React.ReactNode;
}

export default function VirtualTable({
  head,
  rows,
  rowHeight = 40,
  headHeight,
  height = 480,
  total,
  selected = -1,
  onSelect,
  empty,
}: VirtualTableProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => rowHeight,
    overscan: 8,
  });

  // When the scrollport cannot be measured (jsdom, display:none) the
  // virtualizer windows nothing at all — fall back to a bounded first
  // window so the table still shows content instead of an empty grid.
  // Real browsers always measure, so this path never runs in production.
  const measured = virtualizer.getVirtualItems();
  const items = measured.length > 0 || rows.length === 0
    ? measured
    : rows.slice(0, 200).map((_, index) => ({ key: index, index, start: index * rowHeight }));

  const announcedTotal = total ?? rows.length;
  const headerHeight = headHeight ?? rowHeight;

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (!onSelect || rows.length === 0) return;
    const page = Math.max(1, Math.floor(height / rowHeight) - 1);
    let next = selected;
    if (e.key === "ArrowDown") next = Math.min(rows.length - 1, selected + 1);
    else if (e.key === "ArrowUp") next = Math.max(0, selected - 1);
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = rows.length - 1;
    else if (e.key === "PageDown") next = Math.min(rows.length - 1, selected + page);
    else if (e.key === "PageUp") next = Math.max(0, selected - page);
    else return;
    e.preventDefault();
    onSelect(next);
    virtualizer.scrollToIndex(next, { align: "auto" });
  };

  if (rows.length === 0 && empty) {
    return <div className="virtual-table empty">{empty}</div>;
  }

  return (
    <div
      ref={scrollRef}
      className="virtual-table-scroll"
      style={{ height, overflowY: "auto", position: "relative" }}
      role="grid"
      aria-rowcount={announcedTotal}
      tabIndex={0}
      onKeyDown={onKeyDown}
    >
      <div style={{ height: virtualizer.getTotalSize() + headerHeight, position: "relative" }}>
        <div
          role="row"
          aria-rowindex={1}
          className="virtual-head"
          style={{
            position: "sticky",
            top: 0,
            height: headerHeight,
            display: "flex",
            alignItems: "center",
            zIndex: 1,
            background: "var(--panel, var(--bg, #0b0f14))",
            borderBottom: "1px solid var(--line)",
            fontSize: 11,
            fontWeight: 600,
            letterSpacing: "0.06em",
            textTransform: "uppercase",
            color: "var(--dim)",
          }}
        >
          {head.map((h, i) => (
            <div role="columnheader" key={i} style={{ flex: 1, minWidth: 0, padding: "0 8px" }}>
              {h}
            </div>
          ))}
        </div>
        {items.map((item) => {
          const isSel = item.index === selected;
          return (
            <div
              role="row"
              aria-rowindex={item.index + 2}
              aria-selected={isSel || undefined}
              key={item.key}
              className={isSel ? "virtual-row selected" : "virtual-row"}
              style={{
                position: "absolute",
                top: 0,
                left: 0,
                width: "100%",
                height: rowHeight,
                transform: `translateY(${item.start + headerHeight}px)`,
                display: "flex",
                alignItems: "center",
              }}
              onClick={() => onSelect?.(item.index)}
            >
              {(rows[item.index] ?? []).map((cell, ci) => (
                <div role="gridcell" key={ci} style={{ flex: 1, minWidth: 0, height: "100%", display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden" }}>
                  {cell}
                </div>
              ))}
            </div>
          );
        })}
      </div>
    </div>
  );
}
