import { useCallback, useEffect, useRef, useState } from "react";
import { cn } from "@/lib/utils";

export type ContentFilter =
  | "All"
  | "HTTP"
  | "HTTPS"
  | "WebSocket"
  | "JSON"
  | "Form"
  | "XML"
  | "JS"
  | "CSS"
  | "GraphQL"
  | "Document"
  | "Media"
  | "Other";

export type StatusClass = "1xx" | "2xx" | "3xx" | "4xx" | "5xx";

/** Protocol/transport group — mutually exclusive with the content group. */
const PROTOCOL: ContentFilter[] = ["All", "HTTP", "HTTPS", "WebSocket"];

/** Content-type group — mutually exclusive single select. */
const CONTENT: ContentFilter[] = [
  "JSON",
  "Form",
  "XML",
  "JS",
  "CSS",
  "GraphQL",
  "Document",
  "Media",
  "Other",
];

/** Status classes, color-coded to mirror the request-row status dot. */
const STATUS: { key: StatusClass; dot: string; tint: string; text: string }[] = [
  { key: "1xx", dot: "#8b8b8b", tint: "rgba(139,139,139,0.15)", text: "#9a9a9a" },
  { key: "2xx", dot: "#00ca50", tint: "rgba(0,202,80,0.15)", text: "#00ca50" },
  { key: "3xx", dot: "#fed000", tint: "rgba(254,208,0,0.16)", text: "#d9b400" },
  { key: "4xx", dot: "#ff7a1a", tint: "rgba(255,122,26,0.15)", text: "#ff7a1a" },
  { key: "5xx", dot: "#ff3b3b", tint: "rgba(255,59,59,0.15)", text: "#ff5252" },
];

interface ContentFilterBarProps {
  activeFilter: ContentFilter;
  onFilterChange: (filter: ContentFilter) => void;
  statusClasses: Set<StatusClass>;
  onToggleStatus: (cls: StatusClass) => void;
}

function Divider() {
  return <div className="w-px h-3.5 bg-border mx-1.5 shrink-0" />;
}

function Pill({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "px-2.5 h-5 text-[11px] font-medium rounded-md transition-colors whitespace-nowrap shrink-0",
        active
          ? "bg-muted text-foreground shadow-sm"
          : "text-muted-foreground hover:bg-muted/50 hover:text-foreground",
      )}
    >
      {label}
    </button>
  );
}

export default function ContentFilterBar({
  activeFilter,
  onFilterChange,
  statusClasses,
  onToggleStatus,
}: ContentFilterBarProps) {
  // The pills can't shrink without becoming unreadable, so a narrow window
  // scrolls them. The scrollbar is hidden to keep the 28px bar clean, which
  // leaves no hint that anything is off-screen — hence the edge fades, plus
  // wheel support so a trackpad or mouse can reach the hidden filters.
  const scrollerRef = useRef<HTMLDivElement>(null);
  const [overflow, setOverflow] = useState({ start: false, end: false });

  const syncOverflow = useCallback(() => {
    const el = scrollerRef.current;
    if (!el) return;
    const max = el.scrollWidth - el.clientWidth;
    setOverflow({
      start: el.scrollLeft > 1,
      end: el.scrollLeft < max - 1,
    });
  }, []);

  useEffect(() => {
    const el = scrollerRef.current;
    if (!el) return;
    syncOverflow();
    const ro = new ResizeObserver(syncOverflow);
    ro.observe(el);
    return () => ro.disconnect();
  }, [syncOverflow]);

  const handleWheel = useCallback((e: React.WheelEvent<HTMLDivElement>) => {
    const el = scrollerRef.current;
    // A vertical wheel over a horizontal-only strip would otherwise do nothing.
    if (!el || e.deltaY === 0 || e.deltaX !== 0) return;
    el.scrollLeft += e.deltaY;
  }, []);

  return (
    <div className="relative shrink-0 bg-background border-b border-border">
      <div
        aria-hidden
        className={cn(
          "pointer-events-none absolute inset-y-0 left-0 z-10 w-6 bg-gradient-to-r from-background to-transparent transition-opacity",
          overflow.start ? "opacity-100" : "opacity-0",
        )}
      />
      <div
        aria-hidden
        className={cn(
          "pointer-events-none absolute inset-y-0 right-0 z-10 w-6 bg-gradient-to-l from-background to-transparent transition-opacity",
          overflow.end ? "opacity-100" : "opacity-0",
        )}
      />
      <div
        ref={scrollerRef}
        onScroll={syncOverflow}
        onWheel={handleWheel}
        className="flex items-center h-7 px-2 gap-0.5 overflow-x-auto scrollbar-hide"
      >
      {/* Protocol */}
      {PROTOCOL.map((f) => (
        <Pill
          key={f}
          label={f}
          active={activeFilter === f}
          onClick={() => onFilterChange(f)}
        />
      ))}

      <Divider />

      {/* Content type */}
      {CONTENT.map((f) => (
        <Pill
          key={f}
          label={f}
          active={activeFilter === f}
          onClick={() => onFilterChange(f)}
        />
      ))}

      <Divider />

      {/* Status class — independent multi-select */}
      {STATUS.map(({ key, dot, tint, text }) => {
        const active = statusClasses.has(key);
        return (
          <button
            key={key}
            onClick={() => onToggleStatus(key)}
            title={`Show ${key} responses`}
            className={cn(
              "flex items-center gap-1.5 pl-1.5 pr-2 h-5 text-[11px] font-medium rounded-md transition-colors whitespace-nowrap shrink-0 tabular-nums border",
              active
                ? "border-transparent"
                : "border-transparent text-muted-foreground hover:bg-muted/50 hover:text-foreground",
            )}
            style={
              active
                ? { backgroundColor: tint, color: text }
                : undefined
            }
          >
            <span
              className="inline-block w-1.5 h-1.5 rounded-full shrink-0 transition-opacity"
              style={{ backgroundColor: dot, opacity: active ? 1 : 0.45 }}
            />
            {key}
          </button>
        );
      })}
      </div>
    </div>
  );
}
