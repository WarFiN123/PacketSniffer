import {
  useRef,
  useEffect,
  useState,
  useCallback,
  useMemo,
  memo,
} from "react";
import { invoke } from "@tauri-apps/api/core";
import { useVirtualizer } from "@tanstack/react-virtual";
import { cn } from "@/lib/utils";
import { formatSize, formatTime, shortType } from "@/lib/utils";
import type { HttpSession } from "@/types";
import { Pin, RadioTower, FilterX } from "lucide-react";
import { Button } from "@/components/ui/button";
import Spinner from "./Spinner";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import {
  getFullUrl,
  exportToPostman,
  exportRequest,
  exportResponse,
} from "@/lib/exportUtils";

interface RequestTableProps {
  sessions: Map<number, HttpSession>;
  order: number[];
  /** Total captured requests before filtering — distinguishes "no traffic yet"
   *  from "traffic exists but the filters hide all of it". */
  totalCount: number;
  hasActiveFilters: boolean;
  onClearFilters: () => void;
  selectedId: number | null;
  onSelect: (id: number | null) => void;
  pinnedIds: Set<number>;
  onTogglePin: (id: number) => void;
}

const ROW_HEIGHT = 24;

// Column layout. `dot`/`pin` are fixed; the rest are user-resizable. A trailing
// filler column absorbs slack so the grid fills the pane without stretching the
// data columns. Total cells per row = COL_IDS.length + 1 (filler).
const COL_IDS = [
  "dot",
  "pin",
  "id",
  "url",
  "method",
  "status",
  "type",
  "size",
  "time",
] as const;
type ColId = (typeof COL_IDS)[number];

const DEFAULT_WIDTHS: Record<ColId, number> = {
  dot: 28,
  pin: 28,
  id: 56,
  url: 460,
  method: 72,
  status: 96,
  type: 72,
  size: 84,
  time: 84,
};
const MIN_WIDTHS: Partial<Record<ColId, number>> = {
  id: 40,
  url: 140,
  method: 52,
  status: 64,
  type: 52,
  size: 56,
  time: 56,
};
const RESIZABLE = new Set<ColId>([
  "id",
  "url",
  "method",
  "status",
  "type",
  "size",
  "time",
]);
const COL_SPAN = COL_IDS.length + 1; // + filler
const WIDTHS_KEY = "ps_col_widths";

type Widths = Record<ColId, number>;

function minWidth(id: ColId): number {
  return MIN_WIDTHS[id] ?? 40;
}

/**
 * Fit the stored column widths into `available` pixels.
 *
 * Stored widths are treated as a *ratio*, not as absolute sizes: when the pane
 * is narrower than their sum, resizable columns shrink proportionally rather
 * than pushing a horizontal scrollbar onto the user. Fixed columns (the status
 * dot and pin) never shrink, and no column goes below its minimum — once every
 * column has bottomed out, the scrollbar is genuinely the only option left.
 */
function fitColumns(base: Widths, available: number): Widths {
  const fitted = { ...base };
  const fixed = COL_IDS.filter((id) => !RESIZABLE.has(id)).reduce(
    (sum, id) => sum + base[id],
    0,
  );

  let pool = COL_IDS.filter((id) => RESIZABLE.has(id));
  let poolWidth = pool.reduce((sum, id) => sum + base[id], 0);
  let budget = available - fixed;

  if (budget <= 0 || poolWidth <= 0 || budget >= poolWidth) return fitted;

  // Shrink proportionally, park any column that would breach its minimum, and
  // redistribute that column's shortfall across the ones with slack left. Each
  // pass parks at least one column, so this terminates in at most `pool` passes.
  while (pool.length > 0) {
    const scale = budget / poolWidth;
    const parked = pool.filter((id) => base[id] * scale < minWidth(id));

    if (parked.length === 0) {
      for (const id of pool) fitted[id] = Math.floor(base[id] * scale);
      break;
    }

    for (const id of parked) {
      fitted[id] = minWidth(id);
      budget -= fitted[id];
      poolWidth -= base[id];
    }
    pool = pool.filter((id) => !parked.includes(id));
  }

  return fitted;
}

function ResizeHandle({
  onMouseDown,
}: {
  onMouseDown: (e: React.MouseEvent) => void;
}) {
  return (
    <div
      onMouseDown={onMouseDown}
      onClick={(e) => e.stopPropagation()}
      className="absolute top-0 -right-0.75 z-20 h-full w-1.5 cursor-col-resize select-none hover:bg-primary/50 active:bg-primary/70"
    />
  );
}

function dotClass(s: HttpSession): string {
  if (!s.complete) return "bg-orange-400";
  if (s.status === 0) return "bg-muted-foreground";
  if (s.status < 300) return "bg-[#00ca50]";
  if (s.status < 400) return "bg-[#fed000]";
  return "bg-destructive";
}

interface RowProps {
  id: number;
  session: HttpSession;
  isSelected: boolean;
  isPinned: boolean;
  onSelect: (id: number | null) => void;
  onTogglePin: (id: number) => void;
  onCopy: (text: string) => void;
  onExport: (s: HttpSession, fn: (full: HttpSession) => void) => void;
}

const RequestRow = memo(function RequestRow({
  id,
  session: s,
  isSelected,
  isPinned,
  onSelect,
  onTogglePin,
  onCopy,
  onExport,
}: RowProps) {
  const fullUrl = getFullUrl(s);

  return (
    <ContextMenu>
      <ContextMenuTrigger asChild>
        <tr
          onClick={() => onSelect(isSelected ? null : id)}
          className={cn(
            "group text-[12px] h-6 cursor-default",
            isSelected
              ? "selected bg-select text-select-fg"
              : "hover:bg-muted/50 text-foreground",
          )}
        >
          <td className="h-6 px-2 m-0 border-b border-b-border/40 text-center border-r border-r-border/20 border-l-2 border-l-transparent group-[.selected]:border-l-foreground">
            <span
              className={cn("inline-block w-2 h-2 rounded-full", dotClass(s))}
            />
          </td>

          <td className="h-6 px-2 m-0 border-b border-b-border/40 text-center border-r border-r-border/20">
            {isPinned && (
              <Pin className="size-3 mx-auto fill-current text-foreground" />
            )}
          </td>

          <td className="h-6 px-2 m-0 border-b border-b-border/40 border-r border-r-border/20 tabular-nums">
            {s.id}
          </td>

          <td className="h-6 px-2 m-0 border-b border-b-border/40 border-r border-r-border/20 truncate">
            <span
              className={cn(
                "font-medium",
                isSelected ? "text-select-fg" : "text-foreground",
              )}
            >
              {s.host}
            </span>
            <span
              className={cn(
                isSelected ? "text-select-fg/80" : "text-muted-foreground",
              )}
            >
              {s.path}
            </span>
          </td>

          <td className="h-6 px-2 m-0 border-b border-b-border/40 border-r border-r-border/20 text-[11px] font-medium">
            {s.method}
          </td>

          <td className="h-6 px-2 m-0 border-b border-b-border/40 border-r border-r-border/20 text-[11px] font-medium tabular-nums">
            {!s.complete && s.status === 0 ? (
              <div className="flex items-center gap-1.5 opacity-70">
                <Spinner size={10} />
                <span>...</span>
              </div>
            ) : (
              <>
                {s.status || (s.complete ? "-" : "...")}{" "}
                {s.statusText && s.status !== 0 ? s.statusText : ""}
              </>
            )}
          </td>

          {/* Type */}
          <td className="h-6 px-2 m-0 border-b border-b-border/40 border-r border-r-border/20 text-[11px] truncate">
            {shortType(s.contentType) ||
              (!s.complete ? (
                <div className="flex items-center opacity-40 h-full">
                  <Spinner size={10} />
                </div>
              ) : (
                ""
              ))}
          </td>

          {/* Size */}
          <td className="h-6 px-2 m-0 border-b border-b-border/40 border-r border-r-border/20 tabular-nums text-right whitespace-nowrap">
            {s.responseSize != null ? (
              formatSize(s.responseSize)
            ) : !s.complete ? (
              <div className="flex items-center justify-end opacity-40 h-full">
                <Spinner size={10} />
              </div>
            ) : (
              ""
            )}
          </td>

          {/* Duration */}
          <td className="h-6 px-2 m-0 border-b border-b-border/40 border-r border-r-border/20 tabular-nums text-right whitespace-nowrap">
            {s.duration != null ? (
              formatTime(s.duration)
            ) : !s.complete ? (
              <div className="flex items-center justify-end opacity-40 h-full">
                <Spinner size={10} />
              </div>
            ) : (
              ""
            )}
          </td>

          {/* Filler — absorbs slack so the grid fills the pane */}
          <td className="h-6 m-0 border-b border-b-border/40" />
        </tr>
      </ContextMenuTrigger>
      <ContextMenuContent className="text-[12px] min-w-48">
        <ContextMenuItem onClick={() => onTogglePin(id)}>
          {isPinned ? "Unpin Request" : "Pin Request"}
        </ContextMenuItem>
        <ContextMenuSeparator />
        <ContextMenuItem onClick={() => onCopy(fullUrl)}>
          Copy URL
        </ContextMenuItem>
        <ContextMenuItem onClick={() => onCopy(s.path)}>
          Copy Path
        </ContextMenuItem>
        <ContextMenuSeparator />
        <ContextMenuItem onClick={() => onExport(s, exportToPostman)}>
          Open in Postman
        </ContextMenuItem>
        <ContextMenuItem onClick={() => onExport(s, exportRequest)}>
          Export Request...
        </ContextMenuItem>
        <ContextMenuItem onClick={() => onExport(s, exportResponse)}>
          Export Response...
        </ContextMenuItem>
      </ContextMenuContent>
    </ContextMenu>
  );
});

export default function RequestTable({
  sessions,
  order,
  totalCount,
  hasActiveFilters,
  onClearFilters,
  selectedId,
  onSelect,
  pinnedIds,
  onTogglePin,
}: RequestTableProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const isAtBottomRef = useRef(true);

  // Base column widths (persisted to localStorage). These define the ratio the
  // layout keeps; `fitted` below is what actually gets rendered.
  const [widths, setWidths] = useState<Widths>(() => {
    let stored: Partial<Widths> = {};
    try {
      const saved = localStorage.getItem(WIDTHS_KEY);
      if (saved) stored = JSON.parse(saved);
    } catch {
      // ignore
    }
    // Clamp on the way in: a stale or hand-edited entry (or one written by an
    // older build with different columns) must never yield a zero or NaN width,
    // which would poison the proportional fit below.
    const widths = { ...DEFAULT_WIDTHS };
    for (const id of COL_IDS) {
      // Fixed columns aren't user-adjustable, so they always take the default.
      if (!RESIZABLE.has(id)) continue;
      const value = stored[id];
      if (typeof value === "number" && Number.isFinite(value)) {
        widths[id] = Math.max(minWidth(id), value);
      }
    }
    return widths;
  });
  const widthsRef = useRef(widths);
  widthsRef.current = widths;

  useEffect(() => {
    try {
      localStorage.setItem(WIDTHS_KEY, JSON.stringify(widths));
    } catch {
      // ignore
    }
  }, [widths]);

  // Available width drives the fit, so it has to be re-measured on every pane
  // or window resize — not just on mount.
  const [viewport, setViewport] = useState(0);
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => {
      setViewport(entry.contentRect.width);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const fitted = useMemo(
    () => (viewport > 0 ? fitColumns(widths, viewport) : widths),
    [widths, viewport],
  );
  const fittedRef = useRef(fitted);
  fittedRef.current = fitted;

  const startResize = useCallback((e: React.MouseEvent, colId: ColId) => {
    e.preventDefault();
    e.stopPropagation();
    const startX = e.clientX;
    const startW = widthsRef.current[colId] ?? DEFAULT_WIDTHS[colId];
    const min = minWidth(colId);
    // While the layout is scaled down, a 1px drag moves the edge by less than
    // 1px. Divide the delta by that scale so the column edge tracks the cursor.
    const scale = startW > 0 ? (fittedRef.current[colId] ?? startW) / startW : 1;

    const onMove = (ev: MouseEvent) => {
      const delta = (ev.clientX - startX) / (scale || 1);
      setWidths((w) => ({ ...w, [colId]: Math.max(min, startW + delta) }));
    };
    const onUp = () => {
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  }, []);

  // Only forces a scrollbar once every column has bottomed out at its minimum.
  const totalWidth = COL_IDS.reduce((sum, id) => sum + fitted[id], 0);

  const virtualizer = useVirtualizer({
    count: order.length,
    getScrollElement: () => containerRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 30,
  });

  // Track whether the user is at the bottom of the scroll area
  const handleScroll = () => {
    if (!containerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
    isAtBottomRef.current = scrollHeight - scrollTop - clientHeight < 25;
  };

  // Auto-scroll to bottom when new requests arrive (if user was already at bottom)
  useEffect(() => {
    if (isAtBottomRef.current && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [order.length]);

  const handleCopy = useCallback(async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch (err) {
      console.error("Failed to copy!", err);
    }
  }, []);

  // Bodies aren't in the streamed session, so fetch the full record before
  // running a body-bearing export (Postman / Export Request / Export Response).
  const handleExport = useCallback(
    async (s: HttpSession, fn: (full: HttpSession) => void) => {
      if (!s.hasRequestBody && !s.hasResponseBody) {
        fn(s);
        return;
      }
      try {
        const full = await invoke<HttpSession | null>("get_session", {
          id: s.id,
        });
        fn(full ?? s);
      } catch {
        fn(s);
      }
    },
    [],
  );

  const virtualItems = virtualizer.getVirtualItems();

  return (
    <div className="h-full flex flex-col bg-background relative">
      <div
        className="flex-1 overflow-auto bg-background"
        ref={containerRef}
        onScroll={handleScroll}
      >
        <table
          className="text-left border-separate border-spacing-0 select-none outline-none table-fixed w-full"
          style={{ minWidth: totalWidth }}
        >
          <colgroup>
            {COL_IDS.map((id) => (
              <col key={id} style={{ width: fitted[id] }} />
            ))}
            <col />
          </colgroup>
          <thead className="sticky top-0 z-10 bg-panel-header shadow-sm">
            <tr className="text-[11px] text-muted-foreground font-medium">
              {(
                [
                  ["dot", ""],
                  ["pin", ""],
                  ["id", "ID"],
                  ["url", "URL"],
                  ["method", "Method"],
                  ["status", "Status"],
                  ["type", "Type"],
                  ["size", "Size"],
                  ["time", "Time"],
                ] as [ColId, string][]
              ).map(([id, label]) => (
                <th
                  key={id}
                  className={cn(
                    "relative font-normal px-2 h-6 border-b border-r border-border whitespace-nowrap",
                    (id === "dot" || id === "pin") && "text-center",
                  )}
                >
                  {id === "pin" ? (
                    <Pin className="size-3 mx-auto text-muted-foreground" />
                  ) : (
                    label
                  )}
                  {RESIZABLE.has(id) && (
                    <ResizeHandle onMouseDown={(e) => startResize(e, id)} />
                  )}
                </th>
              ))}
              <th className="border-b border-border h-6" />
            </tr>
          </thead>
          <tbody>
            {order.length === 0 ? (
              <tr>
                <td colSpan={COL_SPAN} className="text-center">
                  {hasActiveFilters && totalCount > 0 ? (
                    <div className="flex flex-col items-center justify-center gap-3 py-16 select-none">
                      <FilterX
                        className="size-7 text-muted-foreground/50"
                        strokeWidth={1.5}
                      />
                      <div className="text-[13px] font-medium text-foreground/70">
                        No requests match your filters
                      </div>
                      <div className="text-[11px] text-muted-foreground max-w-xs">
                        {totalCount} captured{" "}
                        {totalCount === 1 ? "request is" : "requests are"} hidden
                        by the active filters.
                      </div>
                      <Button
                        size="sm"
                        onClick={onClearFilters}
                        className="mt-1"
                      >
                        <FilterX className="size-3.5 mr-1.5" />
                        Clear all filters
                      </Button>
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center gap-2 py-16 select-none">
                      <RadioTower
                        className="size-7 text-muted-foreground/50"
                        strokeWidth={1.5}
                      />
                      <div className="text-[13px] font-medium text-foreground/70">
                        Listening for traffic
                      </div>
                      <div className="text-[11px] text-muted-foreground max-w-xs">
                        Captured requests appear here. Route an app or device
                        through the proxy to get started.
                      </div>
                    </div>
                  )}
                </td>
              </tr>
            ) : (
              <>
                {/* Top spacer row for virtualization */}
                {virtualItems.length > 0 && virtualItems[0].start > 0 && (
                  <tr>
                    <td
                      colSpan={COL_SPAN}
                      style={{ height: virtualItems[0].start }}
                    />
                  </tr>
                )}

                {virtualItems.map((virtualRow) => {
                  const id = order[virtualRow.index];
                  const s = sessions.get(id);
                  if (!s) return null;

                  return (
                    <RequestRow
                      key={id}
                      id={id}
                      session={s}
                      isSelected={selectedId === id}
                      isPinned={pinnedIds.has(id)}
                      onSelect={onSelect}
                      onTogglePin={onTogglePin}
                      onCopy={handleCopy}
                      onExport={handleExport}
                    />
                  );
                })}

                {/* Bottom spacer row for virtualization */}
                {virtualItems.length > 0 && (
                  <tr>
                    <td
                      colSpan={COL_SPAN}
                      style={{
                        height:
                          virtualizer.getTotalSize() -
                          virtualItems[virtualItems.length - 1].end,
                      }}
                    />
                  </tr>
                )}
              </>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
