import { useEffect, useRef } from "react";
import { Search, X, Check } from "lucide-react";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  Menubar,
  MenubarContent,
  MenubarItem,
  MenubarMenu,
  MenubarSeparator,
  MenubarShortcut,
  MenubarTrigger,
} from "@/components/ui/menubar";
import WindowControls from "./WindowControls";

interface ToolbarProps {
  connected: boolean;
  onOpenPreferences: () => void;
  noCache: boolean;
  onToggleNoCache: () => void;
  onOpenNetwork: () => void;
  onOpenBlockList: () => void;
  onOpenMap: () => void;
  onOpenPatchApk: () => void;
  onOpenUpdate: () => void;
  onOpenAbout: () => void;
  onExportSession: () => void;
  onInstallCa: () => void;
  textFilter: string;
  onTextChange: (value: string) => void;
}

export default function Toolbar({
  connected: _,
  onOpenPreferences,
  noCache,
  onToggleNoCache,
  onOpenNetwork,
  onOpenBlockList,
  onOpenMap,
  onOpenPatchApk,
  onOpenUpdate,
  onOpenAbout,
  onExportSession,
  onInstallCa,
  textFilter,
  onTextChange,
}: ToolbarProps) {
  const searchRef = useRef<HTMLInputElement>(null);

  // Ctrl/Cmd+F focuses the app's own filter instead of the webview's find bar.
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === "f" || e.key === "F")) {
        e.preventDefault();
        searchRef.current?.focus();
        searchRef.current?.select();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  const handleQuit = async () => {
    try {
      await invoke("stop_proxy");
    } catch {
      // ignore
    }
    await getCurrentWindow().close();
  };

  const handleMouseDown = async (e: React.MouseEvent) => {
    if (
      e.buttons === 1 &&
      (e.target as HTMLElement).hasAttribute("data-tauri-drag-region")
    ) {
      try {
        await getCurrentWindow().startDragging();
      } catch {
        // ignore
      }
    }
  };

  return (
    <div
      className="flex flex-col bg-background border-b border-border select-none shrink-0"
      data-tauri-drag-region
      onMouseDown={handleMouseDown}
    >
      {/* Top row: Menu bar + Window controls area (macOS style space or Windows controls space depending on OS) */}
      <div className="flex items-center justify-between h-9 px-2 gap-2" data-tauri-drag-region>
        <div className="flex items-center gap-2" data-tauri-drag-region>
          {/* Logo / Brand */}
          <div className="font-bold text-sm px-2 text-primary tracking-tight flex items-center gap-1.5 font-chakra pointer-events-none">
            <img src="/logo.png" alt="Logo" className="w-4 h-4 rounded-sm" />
            PacketSniffer
          </div>

          <Menubar className="border-none bg-transparent h-7 p-0 gap-0">
            <MenubarMenu>
              <MenubarTrigger className="h-7 px-2 text-xs font-medium cursor-default">
                File
              </MenubarTrigger>
              <MenubarContent>
                <MenubarItem onClick={onExportSession}>
                  Export Session... <MenubarShortcut>⌘S</MenubarShortcut>
                </MenubarItem>
                <MenubarSeparator />
                <MenubarItem onClick={onOpenPreferences}>
                  Preferences
                </MenubarItem>
                <MenubarSeparator />
                <MenubarItem onClick={handleQuit}>Quit</MenubarItem>
              </MenubarContent>
            </MenubarMenu>

            <MenubarMenu>
              <MenubarTrigger className="h-7 px-2 text-xs font-medium cursor-default">
                Tools
              </MenubarTrigger>
              <MenubarContent>
                <MenubarItem
                  onSelect={(e) => {
                    e.preventDefault();
                    onToggleNoCache();
                  }}
                >
                  No Cache
                  {noCache && <Check className="ml-auto size-3.5" />}
                </MenubarItem>
                <MenubarItem onClick={onOpenNetwork}>
                  Simulate Network...
                </MenubarItem>
                <MenubarItem onClick={onOpenBlockList}>
                  Block / Allow List...
                </MenubarItem>
                <MenubarItem onClick={onOpenMap}>Map Requests...</MenubarItem>
                <MenubarSeparator />
                <MenubarItem onClick={onOpenPatchApk}>
                  Patch an APK...
                </MenubarItem>
              </MenubarContent>
            </MenubarMenu>

            <MenubarMenu>
              <MenubarTrigger className="h-7 px-2 text-xs font-medium cursor-default">
                Help
              </MenubarTrigger>
              <MenubarContent>
                <MenubarItem onClick={onInstallCa}>
                  Install CA Certificate...
                </MenubarItem>
                <MenubarSeparator />
                <MenubarItem>
                  <a
                    href="https://github.com/WarFiN123/packetsniffer"
                    target="_blank"
                  >
                    Report an Issue
                  </a>
                </MenubarItem>
                <MenubarSeparator />
                <MenubarItem onClick={onOpenUpdate}>
                  Check for Updates...
                </MenubarItem>
                <MenubarSeparator />
                <MenubarItem onClick={onOpenAbout}>
                  About PacketSniffer
                </MenubarItem>
              </MenubarContent>
            </MenubarMenu>
          </Menubar>
        </div>

        {/* Right cluster: filter + window controls */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 bg-muted/50 border border-border rounded-md px-2 h-6 min-w-50 group focus-within:ring-1 focus-within:ring-ring z-10">
            <Search className="size-3.5 text-muted-foreground group-focus-within:text-primary" />
            <input
              ref={searchRef}
              type="text"
              value={textFilter}
              onChange={(e) => onTextChange(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Escape") {
                  if (textFilter) onTextChange("");
                  e.currentTarget.blur();
                }
              }}
              placeholder="Filter (Ctrl + F)"
              className="bg-transparent text-[11px] text-foreground placeholder:text-muted-foreground outline-none flex-1 min-w-0 font-medium"
            />
            {textFilter && (
              <button
                onClick={() => onTextChange("")}
                className="text-muted-foreground hover:text-foreground text-xs leading-none shrink-0"
              >
                <X className="size-3.5" />
              </button>
            )}
          </div>

          <WindowControls onClose={handleQuit} />
        </div>
      </div>
    </div>
  );
}
