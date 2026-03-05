import { useState, useMemo, useCallback, useEffect, useRef } from "react";
import { save, confirm, message } from "@tauri-apps/plugin-dialog";
import { writeTextFile } from "@tauri-apps/plugin-fs";
import { invoke } from "@tauri-apps/api/core";
import { useProxySessions, useWsMessages } from "./hooks/useTauriEvents";
import { useTheme } from "./hooks/useTheme";
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "./components/ui/resizable";
import Toolbar from "./components/Toolbar";
import ContentFilterBar, {
  type ContentFilter,
} from "./components/ContentFilterBar";
import Sidebar from "./components/Sidebar";
import RequestTable from "./components/RequestTable";
import DetailPanel from "./components/DetailPanel";
import StatusBar from "./components/StatusBar";
import PreferencesDialog from "./components/PreferencesDialog";
import AboutDialog from "./components/AboutDialog";
import UpdateDialog from "./components/UpdateDialog";
import Spinner from "./components/Spinner";
import type { HttpSession } from "./types";

function matchesContentFilter(s: HttpSession, filter: ContentFilter): boolean {
  if (filter === "All") return true;

  const ct = (s.contentType || "").toLowerCase();
  const scheme = s.scheme.toLowerCase();

  switch (filter) {
    case "HTTP":
      return scheme === "http";
    case "HTTPS":
      return scheme === "https";
    case "WebSocket":
      return scheme === "ws" || scheme === "wss";
    case "JSON":
      return ct.includes("json");
    case "Form":
      return ct.includes("form");
    case "XML":
      return ct.includes("xml");
    case "JS":
      return ct.includes("javascript");
    case "CSS":
      return ct.includes("css");
    case "GraphQL":
      return ct.includes("graphql") || s.path.includes("graphql");
    case "Document":
      return ct.includes("html");
    case "Media":
      return (
        ct.startsWith("image/") ||
        ct.startsWith("video/") ||
        ct.startsWith("audio/")
      );
    case "Other": {
      const known =
        ct.includes("json") ||
        ct.includes("form") ||
        ct.includes("xml") ||
        ct.includes("javascript") ||
        ct.includes("css") ||
        ct.includes("graphql") ||
        ct.includes("html") ||
        ct.startsWith("image/") ||
        ct.startsWith("video/") ||
        ct.startsWith("audio/");
      return !known;
    }
    default:
      return true;
  }
}

export default function App() {
  const {
    sessions,
    order,
    connected,
    clear: clearSessions,
  } = useProxySessions();
  const { messages: wsMessages, clear: clearWsMessages } = useWsMessages();
  const { theme, setTheme } = useTheme();

  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [textFilter, setTextFilter] = useState("");
  const [contentFilter, setContentFilter] = useState<ContentFilter>("All");
  const [selectedDomain, setSelectedDomain] = useState<string | null>(null);
  const [showPinnedOnly, setShowPinnedOnly] = useState(false);
  const [pinnedIds, setPinnedIds] = useState<Set<number>>(new Set());

  const handleTogglePin = useCallback((id: number) => {
    setPinnedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);
  const [recording, setRecording] = useState(true);
  const [prefsOpen, setPrefsOpen] = useState(false);
  const [aboutOpen, setAboutOpen] = useState(false);
  const [updateOpen, setUpdateOpen] = useState(false);
  const [proxyPort, setProxyPort] = useState(8080);
  const [isInstallingCa, setIsInstallingCa] = useState(false);

  useEffect(() => {
    invoke<string>("get_proxy_status")
      .then((status) => {
        const match = status.match(/port (\d+)/);
        if (match) {
          setProxyPort(parseInt(match[1], 10));
        }
      })
      .catch(console.error);
  }, []);

  useEffect(() => {
    // Check if CA certificate is trusted by the OS
    invoke<boolean>("check_ca_trusted")
      .then(async (isTrusted) => {
        if (!isTrusted) {
          const install = await confirm(
            "The PacketSniffer CA Certificate is not trusted by your system. " +
              "HTTPS interception will not work without it.\n\n" +
              "Would you like to install it now? (Requires Administrator/Root privileges)",
            { title: "Install CA Certificate", kind: "info" }
          );

          if (install) {
            setIsInstallingCa(true);
            try {
              const result = await invoke<string>("install_ca_certificate");
              setIsInstallingCa(false);
              await message(result, { title: "Success", kind: "info" });
            } catch (err: any) {
              setIsInstallingCa(false);
              await message(`Failed to install CA certificate:\n${err}`, {
                title: "Error",
                kind: "error",
              });
            }
          }
        }
      })
      .catch((err) => {
        console.error("Failed to check CA trust status:", err);
      });
  }, []);

  const handleExportSession = useCallback(async () => {
    try {
      const filePath = await save({
        filters: [{ name: "JSON", extensions: ["json"] }],
        defaultPath: "packetsniffer-session.json",
      });
      if (filePath) {
        const dataToExport = {
          sessions: Array.from(sessions.values()),
          wsMessages: Array.from(wsMessages.entries()).map(([id, msgs]) => ({
            id,
            messages: msgs,
          })),
        };
        await writeTextFile(filePath, JSON.stringify(dataToExport, null, 2));
      }
    } catch (err) {
      console.error("Failed to export session:", err);
    }
  }, [sessions, wsMessages]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // ctrl+s
      if ((e.metaKey || e.ctrlKey) && e.key === "s") {
        e.preventDefault();
        handleExportSession();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [handleExportSession]);

  const handleClear = useCallback(() => {
    clearSessions();
    clearWsMessages();
    setSelectedId(null);
  }, [clearSessions, clearWsMessages]);

  const filteredOrder = useMemo(() => {
    const needle = textFilter.toLowerCase();

    return order.filter((id) => {
      if (showPinnedOnly && !pinnedIds.has(id)) return false;

      const s = sessions.get(id);
      if (!s) return false;

      if (selectedDomain && s.host !== selectedDomain) return false;

      if (!matchesContentFilter(s, contentFilter)) return false;

      if (needle) {
        const haystack =
          `${s.method} ${s.scheme} ${s.host} ${s.path} ${s.status} ${s.contentType} ${s.url}`.toLowerCase();
        if (!haystack.includes(needle)) return false;
      }

      return true;
    });
  }, [
    order,
    sessions,
    textFilter,
    contentFilter,
    selectedDomain,
    showPinnedOnly,
    pinnedIds,
  ]);

  const panelGroupRef = useRef<HTMLDivElement>(null);
  const sidebarMaxSize = useMemo(() => {
    let longest = 0;
    for (const id of order) {
      const s = sessions.get(id);
      if (s && s.host.length > longest) longest = s.host.length;
    }
    // Sidebar horizontal overhead: tree indent(20) + row px(8+8) + gap(6) + icon(14) + container pr(8) + scrollbar(12) aprox 76px
    // Monospace 11px char width approx 6.6px
    const neededPx = 76 + longest * 6.6;
    const containerWidth =
      panelGroupRef.current?.offsetWidth || window.innerWidth;
    const pct = Math.ceil((neededPx / containerWidth) * 100);
    // force it between 15-50% (note to self: this takes pixels)
    return `${Math.max(15, Math.min(50, pct))}%`;
  }, [sessions, order]);

  const selectedSession =
    selectedId !== null ? (sessions.get(selectedId) ?? null) : null;
  const selectedWsMessages =
    selectedId !== null ? (wsMessages.get(selectedId) ?? []) : [];

  return (
    <main className="h-screen w-screen flex flex-col overflow-hidden bg-transparent rounded-xl border border-border/20 shadow-2xl">
      <div className="h-full flex flex-col bg-bg-0">
        <Toolbar
          connected={connected}
          onOpenPreferences={() => setPrefsOpen(true)}
          onOpenUpdate={() => setUpdateOpen(true)}
          onOpenAbout={() => setAboutOpen(true)}
          onExportSession={handleExportSession}
          textFilter={textFilter}
          onTextChange={setTextFilter}
        />

        <ContentFilterBar
          activeFilter={contentFilter}
          onFilterChange={setContentFilter}
        />

        <div className="flex-1 flex min-h-0" ref={panelGroupRef}>
          <ResizablePanelGroup orientation="horizontal" className="flex-1">
            <ResizablePanel
              defaultSize="15%"
              minSize="5%"
              maxSize={sidebarMaxSize}
            >
              <Sidebar
                sessions={sessions}
                order={order}
                selectedDomain={selectedDomain}
                onSelectDomain={(d) => {
                  setShowPinnedOnly(false);
                  setSelectedDomain(d);
                }}
                showPinnedOnly={showPinnedOnly}
                onTogglePinned={() => {
                  const next = !showPinnedOnly;
                  setShowPinnedOnly(next);
                  if (next) setSelectedDomain(null);
                }}
                pinnedCount={pinnedIds.size}
              />
            </ResizablePanel>

            <ResizableHandle withHandle />

            <ResizablePanel
              defaultSize="85%"
              minSize="20%"
              style={{ minWidth: 0, overflow: "hidden" }}
            >
              <ResizablePanelGroup
                orientation="vertical"
                className="h-full w-full min-w-0 overflow-hidden"
              >
                <ResizablePanel defaultSize="50%" minSize="10%">
                  <div className="h-full w-full min-w-0 overflow-hidden">
                    <RequestTable
                      sessions={sessions}
                      order={filteredOrder}
                      selectedId={selectedId}
                      onSelect={setSelectedId}
                      pinnedIds={pinnedIds}
                      onTogglePin={handleTogglePin}
                    />
                  </div>
                </ResizablePanel>

                <ResizableHandle withHandle />

                <ResizablePanel defaultSize="50%" minSize="10%">
                  <div className="h-full w-full min-w-0 overflow-hidden">
                    <DetailPanel
                      session={selectedSession}
                      wsMessages={selectedWsMessages}
                    />
                  </div>
                </ResizablePanel>
              </ResizablePanelGroup>
            </ResizablePanel>
          </ResizablePanelGroup>
        </div>

        <StatusBar
          totalCount={order.length}
          filteredCount={filteredOrder.length}
          selectedId={selectedId}
          onClear={handleClear}
          connected={connected}
          recording={recording}
          onRecordingChange={setRecording}
          proxyPort={proxyPort}
        />

        <PreferencesDialog
          open={prefsOpen}
          onOpenChange={setPrefsOpen}
          theme={theme}
          onThemeChange={setTheme}
          onPortChange={setProxyPort}
        />

        <AboutDialog open={aboutOpen} onOpenChange={setAboutOpen} />

        <UpdateDialog open={updateOpen} onOpenChange={setUpdateOpen} />

        {isInstallingCa && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
            <div className="flex flex-col items-center gap-4 p-6 bg-bg-1 border border-border rounded-lg shadow-lg">
              <Spinner size={32} />
              <p className="text-text-0 font-medium">Installing CA Certificate...</p>
              <p className="text-text-1 text-sm text-center max-w-xs">
                Please follow the system prompts to complete the installation.
              </p>
            </div>
          </div>
        )}
      </div>
    </main>
  );
}
