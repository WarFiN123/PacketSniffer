import { useMemo } from "react";
import { cn } from "@/lib/utils";
import { Globe, Pin, Monitor, Smartphone, Apple, Plus, Boxes } from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { ConnectedDevice, HttpSession } from "@/types";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

// "My computer" owns every request that arrived over loopback; a phone's
// requests arrive from its own LAN IP. `LOCAL` is the sidebar's source key for
// this computer.
export const LOCAL_SOURCE = "local";
const LIVE = "#00ca50";

function isLocalAddr(addr?: string): boolean {
  return (
    !addr || addr === "::1" || addr === "localhost" || addr.startsWith("127.")
  );
}

interface SidebarProps {
  sessions: Map<number, HttpSession>;
  order: number[];
  devices: ConnectedDevice[];
  sourceFilter: string;
  onSelectSource: (source: string) => void;
  onAddDevice: () => void;
  onRemoveDevice: (serial: string) => void;
  onPatchDevice: (device: ConnectedDevice) => void;
  selectedDomains: Set<string>;
  onSelectDomain: (domain: string, additive: boolean) => void;
  showPinnedOnly: boolean;
  onTogglePinned: () => void;
  pinnedCount: number;
}

export default function Sidebar({
  sessions,
  order,
  devices,
  sourceFilter,
  onSelectSource,
  onAddDevice,
  onRemoveDevice,
  onPatchDevice,
  selectedDomains,
  onSelectDomain,
  showPinnedOnly,
  onTogglePinned,
  pinnedCount,
}: SidebarProps) {
  // Per-source request counts in a single pass.
  const counts = useMemo(() => {
    let local = 0;
    const byIp = new Map<string, number>();
    for (const id of order) {
      const a = sessions.get(id)?.clientAddr;
      if (isLocalAddr(a)) local++;
      else if (a) byIp.set(a, (byIp.get(a) || 0) + 1);
    }
    return { local, byIp };
  }, [order, sessions]);

  // Domains belonging to the currently-selected source only.
  const domains = useMemo(() => {
    const map = new Map<string, number>();
    for (const id of order) {
      const s = sessions.get(id);
      if (!s) continue;
      const inSource =
        sourceFilter === LOCAL_SOURCE
          ? isLocalAddr(s.clientAddr)
          : s.clientAddr === sourceFilter;
      if (!inSource) continue;
      map.set(s.host, (map.get(s.host) || 0) + 1);
    }
    return [...map.entries()].sort(
      (a, b) => b[1] - a[1] || a[0].localeCompare(b[0]),
    );
  }, [sessions, order, sourceFilter]);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text).catch(() => {});
  };

  return (
    <div
      className="h-full min-w-0 flex flex-col bg-sidebar text-sidebar-foreground text-[12px] font-medium select-none overflow-hidden"
      style={{ boxShadow: "inset -1px 0 0 0 var(--sidebar-border)" }}
    >
      <ScrollArea className="flex-1 min-h-0 w-full overflow-hidden">
        <div className="py-2 px-2 overflow-hidden min-w-0">
          {/* ── Favorites ──────────────────────────────────────────── */}
          <div className="pl-1 mb-1 text-muted-foreground text-[11px] font-semibold">
            Favorites
          </div>
          <div className="mb-4 space-y-0.5 min-w-0">
            <button
              onClick={onTogglePinned}
              className={cn(
                "relative flex items-center gap-1.5 w-full px-2 py-1 rounded-md text-left min-w-0 overflow-hidden",
                showPinnedOnly
                  ? "bg-select text-select-fg font-semibold"
                  : "hover:bg-muted/50 text-foreground",
              )}
            >
              {showPinnedOnly && (
                <span className="absolute left-0 top-1 bottom-1 w-0.5 rounded-full bg-foreground" />
              )}
              <Pin
                className={cn(
                  "size-3.5 shrink-0",
                  showPinnedOnly
                    ? "text-select-fg/80"
                    : "text-muted-foreground",
                )}
              />
              <span className="truncate flex-1 min-w-0">Pinned</span>
              <span
                className={cn(
                  "text-[10px] tabular-nums font-semibold shrink-0",
                  showPinnedOnly
                    ? "text-select-fg"
                    : "text-muted-foreground",
                )}
              >
                {pinnedCount}
              </span>
            </button>
          </div>

          {/* ── Sources ────────────────────────────────────────────── */}
          <div className="pl-1 mb-1 text-muted-foreground text-[11px] font-semibold">
            Sources
          </div>

          <div className="space-y-0.5 min-w-0">
            {/* My computer */}
            <SourceRow
              icon={<Monitor className="size-3.5 shrink-0" />}
              label="My computer"
              count={counts.local}
              selected={sourceFilter === LOCAL_SOURCE}
              onSelect={() => onSelectSource(LOCAL_SOURCE)}
            />
            {sourceFilter === LOCAL_SOURCE && (
              <DomainTree
                domains={domains}
                selectedDomains={selectedDomains}
                onSelectDomain={onSelectDomain}
                onCopy={handleCopy}
              />
            )}

            {/* Connected phones */}
            {devices.map((d) => {
              const selected = sourceFilter === d.ip;
              return (
                <div key={d.serial} className="min-w-0">
                  <ContextMenu>
                    <ContextMenuTrigger asChild>
                      <div>
                        <SourceRow
                          icon={<Smartphone className="size-3.5 shrink-0" />}
                          label={d.model || "Android"}
                          count={counts.byIp.get(d.ip) || 0}
                          selected={selected}
                          onSelect={() => onSelectSource(d.ip)}
                          live
                        />
                      </div>
                    </ContextMenuTrigger>
                    <ContextMenuContent className="text-[12px] min-w-44">
                      <ContextMenuItem onClick={() => handleCopy(d.ip)}>
                        Copy IP ({d.ip})
                      </ContextMenuItem>
                      <ContextMenuItem
                        onClick={() => onPatchDevice(d)}
                        className="gap-2"
                      >
                        <Boxes className="size-3.5" /> Patch APK…
                      </ContextMenuItem>
                      <ContextMenuItem onClick={() => onRemoveDevice(d.serial)}>
                        Disconnect device
                      </ContextMenuItem>
                    </ContextMenuContent>
                  </ContextMenu>
                  {selected && (
                    <DomainTree
                      domains={domains}
                      selectedDomains={selectedDomains}
                      onSelectDomain={onSelectDomain}
                      onCopy={handleCopy}
                    />
                  )}
                </div>
              );
            })}

            {/* Add device */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button className="flex items-center gap-1.5 w-full px-2 py-1 mt-0.5 rounded-md text-left text-muted-foreground hover:text-foreground hover:bg-muted/40 border border-dashed border-border/70 hover:border-border min-w-0">
                  <Plus className="size-3.5 shrink-0" />
                  <span className="truncate">Add device</span>
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent
                align="start"
                className="min-w-44 text-[12px]"
              >
                <DropdownMenuItem onSelect={onAddDevice} className="gap-2">
                  <Smartphone className="size-3.5" /> Android
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </ScrollArea>
    </div>
  );
}

function SourceRow({
  icon,
  label,
  count,
  selected,
  onSelect,
  live,
}: {
  icon: React.ReactNode;
  label: string;
  count: number;
  selected: boolean;
  onSelect: () => void;
  live?: boolean;
}) {
  return (
    <button
      onClick={onSelect}
      className={cn(
        "relative flex items-center gap-1.5 w-full px-2 py-1 rounded-md text-left group min-w-0 overflow-hidden",
        selected
          ? "bg-select text-select-fg font-semibold"
          : "hover:bg-muted/50 text-foreground",
      )}
    >
      {selected && (
        <span className="absolute left-0 top-1 bottom-1 w-0.5 rounded-full bg-foreground" />
      )}
      <span
        className={cn(
          "shrink-0",
          selected
            ? "text-select-fg"
            : "text-muted-foreground group-hover:text-foreground",
        )}
      >
        {icon}
      </span>
      <span className="flex-1 truncate min-w-0">{label}</span>
      {live && (
        <span
          className="size-1.5 rounded-full shrink-0"
          style={{ background: LIVE }}
          aria-label="live"
        />
      )}
      <span
        className={cn(
          "text-[10px] tabular-nums font-semibold shrink-0",
          selected ? "text-select-fg" : "text-muted-foreground",
        )}
      >
        {count}
      </span>
    </button>
  );
}

function DomainTree({
  domains,
  selectedDomains,
  onSelectDomain,
  onCopy,
}: {
  domains: [string, number][];
  selectedDomains: Set<string>;
  onSelectDomain: (domain: string, additive: boolean) => void;
  onCopy: (text: string) => void;
}) {
  if (domains.length === 0) {
    return (
      <div className="pl-7 py-1 text-muted-foreground text-[11px]">
        No requests yet
      </div>
    );
  }

  // Domains sit directly under the source. Clicking one filters the table;
  // clicking it again (or the source row) clears the filter. Ctrl/Cmd-click adds
  // or removes a domain so several can be viewed at once. The list stays open
  // either way.
  return (
    <div className="pl-6 pr-0.5 pt-0.5 pb-1 space-y-0.5 min-w-0">
      {domains.map(([domain, count]) => {
        const isSelected = selectedDomains.has(domain);
        return (
          <ContextMenu key={domain}>
            <ContextMenuTrigger asChild>
              <button
                onClick={(e) => onSelectDomain(domain, e.ctrlKey || e.metaKey)}
                className={cn(
                  "flex items-center gap-1.5 w-full px-2 py-1 rounded-md text-left group min-w-0 overflow-hidden relative",
                  isSelected
                    ? "bg-select text-select-fg"
                    : "hover:bg-muted/50 text-foreground",
                )}
              >
                {isSelected && (
                  <span className="absolute left-0 top-1 bottom-1 w-0.5 rounded-full bg-foreground" />
                )}
                <Globe
                  className={cn(
                    "size-3.5 shrink-0",
                    isSelected
                      ? "text-select-fg/80"
                      : "text-muted-foreground group-hover:text-foreground",
                  )}
                />
                <span className="truncate flex-1 min-w-0 font-mono text-[11px] font-normal leading-none tracking-tight pt-px pr-7">
                  {domain}
                </span>
                <span
                  className={cn(
                    "absolute right-2 text-[10px] tabular-nums font-semibold shrink-0",
                    isSelected
                      ? "text-select-fg/80"
                      : "text-muted-foreground",
                  )}
                >
                  {count}
                </span>
              </button>
            </ContextMenuTrigger>
            <ContextMenuContent className="text-[12px] min-w-40">
              <ContextMenuItem onClick={() => onCopy(domain)}>
                Copy Domain
              </ContextMenuItem>
            </ContextMenuContent>
          </ContextMenu>
        );
      })}
    </div>
  );
}
