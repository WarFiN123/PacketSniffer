import { useMemo } from "react";
import { cn } from "@/lib/utils";
import { Globe, Pin, Save, ChevronRight, ChevronDown } from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { HttpSession } from "@/types";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";

interface SidebarProps {
  sessions: Map<number, HttpSession>;
  order: number[];
  selectedDomain: string | null;
  onSelectDomain: (domain: string | null) => void;
  showPinnedOnly: boolean;
  onTogglePinned: () => void;
  pinnedCount: number;
}

export default function Sidebar({
  sessions,
  order,
  selectedDomain,
  onSelectDomain,
  showPinnedOnly,
  onTogglePinned,
  pinnedCount,
}: SidebarProps) {
  // Build domain → count map
  const domains = useMemo(() => {
    const map = new Map<string, number>();
    for (const id of order) {
      const s = sessions.get(id);
      if (!s) continue;
      map.set(s.host, (map.get(s.host) || 0) + 1);
    }
    return [...map.entries()].sort(
      (a, b) => b[1] - a[1] || a[0].localeCompare(b[0]),
    );
  }, [sessions, order]);

  const totalCount = order.length;

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
          <div className="pl-1 mb-1 text-muted-foreground text-[11px] font-semibold">
            Favorites
          </div>
          <div className="mb-4 space-y-0.5 min-w-0">
            <button
              onClick={onTogglePinned}
              className={cn(
                "flex items-center gap-1.5 w-full px-2 py-1 rounded-md text-left min-w-0 overflow-hidden",
                showPinnedOnly
                  ? "bg-primary text-primary-foreground"
                  : "hover:bg-muted/50 text-foreground",
              )}
            >
              <Pin
                className={cn(
                  "size-3.5 shrink-0",
                  showPinnedOnly
                    ? "text-primary-foreground/80"
                    : "text-muted-foreground",
                )}
              />
              <span className="truncate flex-1 min-w-0">Pinned</span>
              <span
                className={cn(
                  "text-[10px] tabular-nums font-semibold shrink-0",
                  showPinnedOnly
                    ? "text-primary-foreground"
                    : "text-muted-foreground",
                )}
              >
                {pinnedCount}
              </span>
            </button>
          </div>

          <div className="pl-1 mb-1 text-muted-foreground text-[11px] font-semibold">
            All
          </div>

          <div className="space-y-0.5 min-w-0">
            <button
              onClick={() => onSelectDomain(null)}
              className={cn(
                "flex items-center gap-1.5 w-full px-2 py-1 rounded-md text-left min-w-0 overflow-hidden",
                selectedDomain === null
                  ? "bg-primary text-primary-foreground"
                  : "hover:bg-muted/50 text-foreground",
              )}
            >
              <ChevronDown
                className={cn(
                  "size-3.5 shrink-0",
                  selectedDomain === null
                    ? "text-primary-foreground/70"
                    : "text-muted-foreground",
                )}
              />
              <Globe className="size-3.5 shrink-0" />
              <span className="flex-1 truncate min-w-0">Domains</span>
              <span
                className={cn(
                  "text-[10px] tabular-nums font-semibold shrink-0",
                  selectedDomain === null
                    ? "text-primary-foreground"
                    : "text-muted-foreground",
                )}
              >
                {totalCount}
              </span>
            </button>

            <div className="pl-3 pt-0.5 space-y-0.5 min-w-0">
              {domains.map(([domain, count]) => {
                const isSelected = selectedDomain === domain;
                return (
                  <ContextMenu key={domain}>
                    <ContextMenuTrigger asChild>
                      <button
                        onClick={() =>
                          onSelectDomain(isSelected ? null : domain)
                        }
                        className={cn(
                          "flex items-center gap-1.5 w-full px-2 py-1 rounded-md text-left group min-w-0 overflow-hidden relative",
                          isSelected
                            ? "bg-primary text-primary-foreground"
                            : "hover:bg-muted/50 text-foreground",
                        )}
                      >
                        <Globe
                          className={cn(
                            "size-3.5 shrink-0",
                            isSelected
                              ? "text-primary-foreground/80"
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
                              ? "text-primary-foreground/80"
                              : "text-muted-foreground",
                          )}
                        >
                          {count}
                        </span>
                      </button>
                    </ContextMenuTrigger>
                    <ContextMenuContent className="text-[12px] min-w-40">
                      <ContextMenuItem onClick={() => handleCopy(domain)}>
                        Copy Domain
                      </ContextMenuItem>
                    </ContextMenuContent>
                  </ContextMenu>
                );
              })}

              {domains.length === 0 && (
                <div className="pl-2 py-2 text-muted-foreground text-[11px]">
                  No requests
                </div>
              )}
            </div>
          </div>
        </div>
      </ScrollArea>
    </div>
  );
}
