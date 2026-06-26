import { useRef, useEffect, useState, useCallback, memo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useVirtualizer } from "@tanstack/react-virtual";
import { cn } from "@/lib/utils";
import { formatSize, formatTime, shortType } from "@/lib/utils";
import type { HttpSession } from "@/types";
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
              ? "selected bg-primary text-primary-foreground"
              : "hover:bg-muted/50 text-foreground",
          )}
        >
          <td className="h-6 px-2 m-0 border-b border-b-border/40 group-[.selected]:border-b-primary text-center border-r border-r-border/20 group-[.selected]:border-r-primary">
            <span
              className={cn("inline-block w-2 h-2 rounded-full", dotClass(s))}
            />
          </td>

          <td className="h-6 px-2 m-0 border-b border-b-border/40 group-[.selected]:border-b-primary text-center border-r border-r-border/20 group-[.selected]:border-r-primary">
            {isPinned ? <span className="text-yellow-500">📌</span> : ""}
          </td>

          <td className="h-6 px-2 m-0 border-b border-b-border/40 group-[.selected]:border-b-primary border-r border-r-border/20 group-[.selected]:border-r-primary tabular-nums">
            {s.id}
          </td>

          <td className="h-6 px-2 m-0 border-b border-b-border/40 group-[.selected]:border-b-primary border-r border-r-border/20 group-[.selected]:border-r-primary truncate">
            <span
              className={cn(
                "font-medium",
                isSelected ? "text-primary-foreground" : "text-foreground",
              )}
            >
              {s.host}
            </span>
            <span
              className={cn(
                isSelected
                  ? "text-primary-foreground/80"
                  : "text-muted-foreground",
              )}
            >
              {s.path}
            </span>
          </td>

          <td className="h-6 px-2 m-0 border-b border-b-border/40 group-[.selected]:border-b-primary border-r border-r-border/20 group-[.selected]:border-r-primary text-[11px] font-medium">
            {s.method}
          </td>

          <td className="h-6 px-2 m-0 border-b border-b-border/40 group-[.selected]:border-b-primary border-r border-r-border/20 group-[.selected]:border-r-primary text-[11px] font-medium tabular-nums">
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
          <td className="h-6 px-2 m-0 border-b border-b-border/40 group-[.selected]:border-b-primary border-r border-r-border/20 group-[.selected]:border-r-primary text-[11px] truncate">
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
          <td className="h-6 px-2 m-0 border-b border-b-border/40 group-[.selected]:border-b-primary border-r border-r-border/20 group-[.selected]:border-r-primary tabular-nums text-right whitespace-nowrap">
            {s.responseSize ? (
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
          <td className="h-6 px-2 m-0 border-b border-b-border/40 group-[.selected]:border-b-primary border-r border-r-border/20 group-[.selected]:border-r-primary tabular-nums text-right whitespace-nowrap">
            {s.duration ? (
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
          <td className="h-6 m-0 border-b border-b-border/40 group-[.selected]:border-b-primary" />
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
  selectedId,
  onSelect,
  pinnedIds,
  onTogglePin,
}: RequestTableProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const isAtBottomRef = useRef(true);

  // Resizable column widths (persisted to localStorage).
  const [widths, setWidths] = useState<Record<string, number>>(() => {
    try {
      const saved = localStorage.getItem(WIDTHS_KEY);
      if (saved) return { ...DEFAULT_WIDTHS, ...JSON.parse(saved) };
    } catch {
      // ignore
    }
    return { ...DEFAULT_WIDTHS };
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

  const startResize = useCallback((e: React.MouseEvent, colId: ColId) => {
    e.preventDefault();
    e.stopPropagation();
    const startX = e.clientX;
    const startW = widthsRef.current[colId] ?? DEFAULT_WIDTHS[colId];
    const min = MIN_WIDTHS[colId] ?? 40;

    const onMove = (ev: MouseEvent) => {
      const next = Math.max(min, startW + (ev.clientX - startX));
      setWidths((w) => ({ ...w, [colId]: next }));
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

  const totalWidth = COL_IDS.reduce(
    (sum, id) => sum + (widths[id] ?? DEFAULT_WIDTHS[id]),
    0,
  );

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
              <col
                key={id}
                style={{ width: widths[id] ?? DEFAULT_WIDTHS[id] }}
              />
            ))}
            <col />
          </colgroup>
          <thead className="sticky top-0 z-10 bg-panel-header shadow-sm">
            <tr className="text-[11px] text-muted-foreground font-medium">
              {(
                [
                  ["dot", ""],
                  ["pin", "📌"],
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
                  {label}
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
                <td
                  colSpan={COL_SPAN}
                  className="text-center py-8 text-muted-foreground text-xs"
                >
                  No requests captured
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
