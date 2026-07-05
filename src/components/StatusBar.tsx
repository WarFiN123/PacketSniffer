import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import Spinner from "./Spinner";
import { Play, Pause, Trash2, AlertTriangle } from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";

interface StatusBarProps {
  totalCount: number;
  filteredCount: number;
  selectedId: number | null;
  onClear: () => void;
  connected: boolean;
  recording: boolean;
  onRecordingChange: (recording: boolean) => void;
  proxyPort: number;
}

export default function StatusBar({
  totalCount,
  filteredCount,
  selectedId,
  onClear,
  connected,
  recording,
  onRecordingChange,
  proxyPort,
}: StatusBarProps) {
  const isFiltered = filteredCount !== totalCount;
  const [proxyOverridden, setProxyOverridden] = useState(false);
  const [fixingProxy, setFixingProxy] = useState(false);

  // Note: Backend emits 'proxy_overridden' event if detected.
  useEffect(() => {
    const unlisten = listen<{ overridden: boolean }>(
      "proxy_overridden",
      (event) => {
        setProxyOverridden(event.payload.overridden);
      },
    );

    return () => {
      unlisten.then((f) => f());
    };
  }, []);

  const handleToggleRecording = async () => {
    try {
      if (recording) {
        await invoke("stop_proxy");
        onRecordingChange(false);
      } else {
        await invoke("start_proxy");
        onRecordingChange(true);
      }
    } catch (e) {
      console.error("Failed to toggle proxy:", e);
    }
  };

  const handleFixProxy = async () => {
    setFixingProxy(true);
    try {
      await invoke("fix_proxy");
      setProxyOverridden(false);
      // Wait a moment then check if it's still overridden (handled by backend polling)
    } catch (e) {
      console.error("Failed to fix proxy:", e);
    } finally {
      setFixingProxy(false);
    }
  };

  return (
    <div className="flex items-center justify-between h-8 px-2 bg-background border-t border-border shrink-0 select-none text-[11px]">
      {/* Left side items */}
      <div className="flex items-center gap-2 text-muted-foreground font-medium tabular-nums min-w-[200px]">
        {proxyOverridden && (
          <Button
            variant="ghost"
            size="xs"
            onClick={handleFixProxy}
            disabled={fixingProxy}
            className="h-6 px-2 rounded bg-destructive/10 text-destructive hover:bg-destructive/20 hover:text-destructive border border-destructive/20 transition-colors gap-1.5"
          >
            {fixingProxy ? (
              <Spinner size={14} className="text-destructive" />
            ) : (
              <AlertTriangle className="size-3.5" />
            )}
            {fixingProxy ? "Fixing..." : "Proxy Overridden (Fix)"}
          </Button>
        )}
      </div>

      {/* Center Spacer & Row Count */}
      <div className="flex-1 flex justify-center text-muted-foreground font-medium tabular-nums">
        {totalCount > 0 ? (
          <>
            {isFiltered ? `${filteredCount}/${totalCount}` : `${totalCount}`}{" "}
            {totalCount === 1 ? "row" : "rows"}
            {selectedId !== null && ` (${selectedId} selected)`}
          </>
        ) : (
          "No requests"
        )}
      </div>

      {/* Right side items */}
      <div className="flex items-center justify-end gap-2 text-muted-foreground font-medium tabular-nums min-w-50">
        {/* Status Pill with Dropdown Menu */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="xs"
              className="h-6 border border-border/50 bg-muted/30 hover:bg-muted/60 text-[11px] font-medium text-foreground shadow-sm transition-colors cursor-pointer"
            >
              <div className="flex items-center">
                {connected ? (
                  recording ? (
                    <span className="w-2 h-2 rounded-full bg-green-500 mr-1 shadow-[0_0_4px_rgba(34,197,94,0.5)]" />
                  ) : (
                    <span className="w-2 h-2 rounded-full bg-yellow-500 mr-1 shadow-[0_0_4px_rgba(234,179,8,0.5)]" />
                  )
                ) : (
                  <span className="mr-1">
                    <Spinner size={10} />
                  </span>
                )}
                {connected
                  ? recording
                    ? `${proxyPort}`
                    : "Paused"
                  : "Connecting"}
              </div>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-48">
            <DropdownMenuItem
              onClick={handleToggleRecording}
              className="gap-2 cursor-pointer items-center"
            >
              {recording ? (
                <Pause className="size-4" />
              ) : (
                <Play className="size-4" />
              )}
              <span>{recording ? "Pause Capture" : "Resume Capture"}</span>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={onClear}
              className="gap-2 cursor-pointer "
              variant="destructive"
            >
              <Trash2 className="size-4" />
              <span>Clear Session</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </div>
  );
}
