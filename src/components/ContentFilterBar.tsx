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
  return (
    <div className="flex items-center h-7 px-2 gap-0.5 bg-background border-b border-border shrink-0 overflow-x-auto scrollbar-hide">
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
  );
}
