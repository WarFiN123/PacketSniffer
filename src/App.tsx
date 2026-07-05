import { useState, useMemo, useCallback, useEffect, useRef } from "react";
import { save } from "@tauri-apps/plugin-dialog";
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
  type StatusClass,
} from "./components/ContentFilterBar";
import Sidebar from "./components/Sidebar";
import RequestTable from "./components/RequestTable";
import DetailPanel from "./components/DetailPanel";
import StatusBar from "./components/StatusBar";
import PreferencesDialog from "./components/PreferencesDialog";
import AboutDialog from "./components/AboutDialog";
import UpdateDialog from "./components/UpdateDialog";
import CaInstallDialog from "./components/CaInstallDialog";
import DependencyDialog from "./components/DependencyDialog";
import ErrorBoundary from "./components/ErrorBoundary";
import NetworkSimDialog from "./components/NetworkSimDialog";
import BlockListDialog from "./components/BlockListDialog";
import MapRulesDialog from "./components/MapRulesDialog";
import AddDeviceDialog from "./components/AddDeviceDialog";
import PatchApkDialog from "./components/PatchApkDialog";
import { LOCAL_SOURCE } from "./components/Sidebar";
import type { ConnectedDevice, HttpSession } from "./types";
import { DEFAULT_INTERCEPT, type InterceptConfig } from "./lib/intercept";

/** Requests that arrived over loopback belong to "My computer"; a phone's
 * arrive from its LAN IP. Mirrors `isLocalAddr` in Sidebar. */
function isLocalAddr(addr?: string): boolean {
  return !addr || addr === "::1" || addr === "localhost" || addr.startsWith("127.");
}

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
  const [debouncedFilter, setDebouncedFilter] = useState("");
  const [contentFilter, setContentFilter] = useState<ContentFilter>("All");
  const [statusClasses, setStatusClasses] = useState<Set<StatusClass>>(
    new Set(),
  );
  const [selectedDomains, setSelectedDomains] = useState<Set<string>>(
    new Set(),
  );
  const [showPinnedOnly, setShowPinnedOnly] = useState(false);
  const [pinnedIds, setPinnedIds] = useState<Set<number>>(new Set());

  // Traffic source: "My computer" (local) or a connected phone (its LAN IP).
  const [sourceFilter, setSourceFilter] = useState<string>(LOCAL_SOURCE);
  const [devices, setDevices] = useState<ConnectedDevice[]>([]);

  const handleSelectSource = useCallback((source: string) => {
    setSourceFilter(source);
    setSelectedDomains(new Set());
    setShowPinnedOnly(false);
  }, []);

  // Plain click selects a single domain (or clears it if it was the only one);
  // Ctrl/Cmd-click toggles a domain so several show at once.
  const handleSelectDomain = useCallback(
    (domain: string, additive: boolean) => {
      setShowPinnedOnly(false);
      setSelectedDomains((prev) => {
        if (additive) {
          const next = new Set(prev);
          if (next.has(domain)) next.delete(domain);
          else next.add(domain);
          return next;
        }
        if (prev.size === 1 && prev.has(domain)) return new Set();
        return new Set([domain]);
      });
    },
    [],
  );

  const handleConnected = useCallback((device: ConnectedDevice) => {
    setDevices((prev) => {
      const rest = prev.filter((d) => d.serial !== device.serial);
      return [...rest, device];
    });
    handleSelectSource(device.ip);
  }, [handleSelectSource]);

  const handleRemoveDevice = useCallback(
    (serial: string) => {
      // Derive removed device info before state update
      const removed = devices.find((d) => d.serial === serial);

      // Update state
      setDevices((prev) => prev.filter((d) => d.serial !== serial));

      // Perform side effects outside updater
      if (removed && removed.ip === sourceFilter) {
        handleSelectSource(LOCAL_SOURCE);
      }
      invoke("stop_device_capture", { serial }).catch(() => {});
    },
    [devices, sourceFilter, handleSelectSource],
  );

  // Debounce text filter to avoid re-filtering on every keystroke
  useEffect(() => {
    const id = setTimeout(() => setDebouncedFilter(textFilter), 150);
    return () => clearTimeout(id);
  }, [textFilter]);

  const handleToggleStatus = useCallback((cls: StatusClass) => {
    setStatusClasses((prev) => {
      const next = new Set(prev);
      if (next.has(cls)) next.delete(cls);
      else next.add(cls);
      return next;
    });
  }, []);

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
  const [networkOpen, setNetworkOpen] = useState(false);
  const [blockOpen, setBlockOpen] = useState(false);
  const [mapOpen, setMapOpen] = useState(false);
  const [addDeviceOpen, setAddDeviceOpen] = useState(false);
  const [patchApkOpen, setPatchApkOpen] = useState(false);
  // When set, the patch dialog targets an installed app on this device; null
  // means the local-file patch flow from the Tools menu.
  const [patchApkDevice, setPatchApkDevice] =
    useState<ConnectedDevice | null>(null);
  const [aboutOpen, setAboutOpen] = useState(false);

  // Interception rules (No-Cache, block/allow, map, throttle) — single source
  // of truth, mirrored to the backend on every change.
  const [intercept, setIntercept] =
    useState<InterceptConfig>(DEFAULT_INTERCEPT);
  useEffect(() => {
    invoke<InterceptConfig>("get_intercept_config")
      .then((c) => setIntercept({ ...DEFAULT_INTERCEPT, ...c }))
      .catch(() => {});
  }, []);
  const updateIntercept = useCallback((patch: Partial<InterceptConfig>) => {
    setIntercept((prev) => {
      const next = { ...prev, ...patch };
      invoke("set_intercept_config", { config: next }).catch((e) =>
        console.error("set_intercept_config failed", e),
      );
      return next;
    });
  }, []);
  const [updateOpen, setUpdateOpen] = useState(false);
  const [proxyPort, setProxyPort] = useState(8080);
  const [showCaDialog, setShowCaDialog] = useState(false);
  const [showDepDialog, setShowDepDialog] = useState(false);
  const [missingDeps, setMissingDeps] = useState<string[]>([]);

  useEffect(() => {
    invoke<string>("get_proxy_status")
      .then((status) => {
        const match = status.match(/port (\d+)/);
        if (match) {
          setProxyPort(parseInt(match[1], 10));
        }
      })
      .catch(() => {});
  }, []);

  // Check for missing system dependencies
  useEffect(() => {
    invoke<string[]>("check_missing_deps")
      .then((deps) => {
        if (deps.length > 0) {
          setMissingDeps(deps);
          setShowDepDialog(true);
        }
      })
      .catch(() => {});
  }, []);

  // Check if CA certificate is trusted — show in-app dialog instead of system one
  useEffect(() => {
    invoke<boolean>("check_ca_trusted")
      .then((isTrusted) => {
        if (!isTrusted) {
          setShowCaDialog(true);
        }
      })
      .catch(() => {});
  }, []);

  const handleExportSession = useCallback(async () => {
    try {
      const filePath = await save({
        filters: [{ name: "JSON", extensions: ["json"] }],
        defaultPath: "packetsniffer-session.json",
      });
      if (filePath) {
        // Bodies live server-side, so pull the full sessions (with bodies)
        // rather than the slim copies held in the UI.
        const fullSessions = await invoke<HttpSession[]>("export_all_sessions");
        const dataToExport = {
          sessions: fullSessions,
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
  }, [wsMessages]);

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
    // Drop the server-side store too so cleared bodies aren't retained.
    invoke("clear_sessions").catch(() => {});
  }, [clearSessions, clearWsMessages]);

  const filteredOrder = useMemo(() => {
    const needle = debouncedFilter.toLowerCase();

    return order.filter((id) => {
      if (showPinnedOnly && !pinnedIds.has(id)) return false;

      const s = sessions.get(id);
      if (!s) return false;

      // Source: "My computer" shows local traffic; a device shows only its IP.
      const inSource =
        sourceFilter === LOCAL_SOURCE
          ? isLocalAddr(s.clientAddr)
          : s.clientAddr === sourceFilter;
      if (!inSource) return false;

      if (selectedDomains.size > 0 && !selectedDomains.has(s.host))
        return false;

      if (!matchesContentFilter(s, contentFilter)) return false;

      if (statusClasses.size > 0) {
        // status < 100 means pending / no response yet — never matches.
        if (s.status < 100) return false;
        const cls = `${Math.floor(s.status / 100)}xx` as StatusClass;
        if (!statusClasses.has(cls)) return false;
      }

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
    debouncedFilter,
    contentFilter,
    statusClasses,
    selectedDomains,
    showPinnedOnly,
    pinnedIds,
    sourceFilter,
  ]);

  // A "filter" is anything that narrows the request list; the source (device)
  // tab is a selector, not a filter, so it's excluded from the clear action.
  const hasActiveFilters =
    textFilter !== "" ||
    contentFilter !== "All" ||
    statusClasses.size > 0 ||
    selectedDomains.size > 0 ||
    showPinnedOnly;

  const handleClearFilters = useCallback(() => {
    setTextFilter("");
    setContentFilter("All");
    setStatusClasses(new Set());
    setSelectedDomains(new Set());
    setShowPinnedOnly(false);
  }, []);

  const panelGroupRef = useRef<HTMLDivElement>(null);
  const [containerWidth, setContainerWidth] = useState(0);

  // The sidebar max-size is derived from a pixel budget, so it must be
  // recomputed when the window (and thus the panel group) is resized — not
  // only when traffic changes. Without this the % goes stale on resize and the
  // sidebar can over/under-shoot at small widths.
  useEffect(() => {
    const el = panelGroupRef.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => {
      setContainerWidth(entry.contentRect.width);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const sidebarMaxSize = useMemo(() => {
    let longest = 0;
    for (const id of order) {
      const s = sessions.get(id);
      if (s && s.host.length > longest) longest = s.host.length;
    }
    // Sidebar horizontal overhead: tree indent(20) + row px(8+8) + gap(6) + icon(14) + container pr(8) + scrollbar(12) aprox 76px
    // Monospace 11px char width approx 6.6px
    const neededPx = 76 + longest * 6.6;
    const width =
      containerWidth || panelGroupRef.current?.offsetWidth || window.innerWidth;
    const pct = Math.ceil((neededPx / width) * 100);
    // force it between 15-50% (note to self: this takes pixels)
    return `${Math.max(15, Math.min(50, pct))}%`;
  }, [sessions, order, containerWidth]);

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
          noCache={intercept.noCache}
          onToggleNoCache={() =>
            updateIntercept({ noCache: !intercept.noCache })
          }
          onOpenNetwork={() => setNetworkOpen(true)}
          onOpenBlockList={() => setBlockOpen(true)}
          onOpenMap={() => setMapOpen(true)}
          onOpenPatchApk={() => {
            setPatchApkDevice(null);
            setPatchApkOpen(true);
          }}
          onOpenUpdate={() => setUpdateOpen(true)}
          onOpenAbout={() => setAboutOpen(true)}
          onExportSession={handleExportSession}
          onInstallCa={() => setShowCaDialog(true)}
          textFilter={textFilter}
          onTextChange={setTextFilter}
        />

        <ContentFilterBar
          activeFilter={contentFilter}
          onFilterChange={setContentFilter}
          statusClasses={statusClasses}
          onToggleStatus={handleToggleStatus}
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
                devices={devices}
                sourceFilter={sourceFilter}
                onSelectSource={handleSelectSource}
                onAddDevice={() => setAddDeviceOpen(true)}
                onRemoveDevice={handleRemoveDevice}
                onPatchDevice={(d) => {
                  setPatchApkDevice(d);
                  setPatchApkOpen(true);
                }}
                selectedDomains={selectedDomains}
                onSelectDomain={handleSelectDomain}
                showPinnedOnly={showPinnedOnly}
                onTogglePinned={() => {
                  const next = !showPinnedOnly;
                  setShowPinnedOnly(next);
                  if (next) setSelectedDomains(new Set());
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
                      totalCount={order.length}
                      hasActiveFilters={hasActiveFilters}
                      onClearFilters={handleClearFilters}
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
                    <ErrorBoundary resetKey={selectedId ?? "none"}>
                      <DetailPanel
                        session={selectedSession}
                        wsMessages={selectedWsMessages}
                      />
                    </ErrorBoundary>
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

        <NetworkSimDialog
          open={networkOpen}
          onOpenChange={setNetworkOpen}
          config={intercept}
          onUpdate={updateIntercept}
        />

        <BlockListDialog
          open={blockOpen}
          onOpenChange={setBlockOpen}
          config={intercept}
          onUpdate={updateIntercept}
        />

        <MapRulesDialog
          open={mapOpen}
          onOpenChange={setMapOpen}
          config={intercept}
          onUpdate={updateIntercept}
        />

        <AddDeviceDialog
          open={addDeviceOpen}
          onOpenChange={setAddDeviceOpen}
          onConnected={handleConnected}
        />

        <PatchApkDialog
          open={patchApkOpen}
          onOpenChange={setPatchApkOpen}
          device={patchApkDevice}
        />

        <AboutDialog open={aboutOpen} onOpenChange={setAboutOpen} />

        <UpdateDialog open={updateOpen} onOpenChange={setUpdateOpen} />

        <CaInstallDialog open={showCaDialog} onOpenChange={setShowCaDialog} />

        <DependencyDialog
          open={showDepDialog}
          onOpenChange={setShowDepDialog}
          missingDeps={missingDeps}
        />
      </div>
    </main>
  );
}
