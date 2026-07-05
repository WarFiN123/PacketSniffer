import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import Spinner from "./Spinner";
import PatchOptions, {
  type PatchOpts,
  DEFAULT_PATCH_OPTS,
  backendPatchOpts,
  patchOptsValid,
} from "./PatchOptions";
import { useAppProtection, PairipChip, PairipBanner } from "./PairipNotice";
import {
  Boxes,
  Smartphone,
  FolderOpen,
  Check,
  X,
  TriangleAlert,
  RefreshCw,
  Copy,
  Search,
} from "lucide-react";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  // When set, the dialog patches an app already installed on this device
  // (pull → patch → install). When null/undefined it patches a local .apk file.
  device?: { serial: string; model?: string } | null;
}

interface DevicePackage {
  package: string;
}
interface PatchResult {
  outputPath: string;
  warnings: string[];
}
interface PatchProgress {
  stage: string;
  message: string;
}

type RunState = "idle" | "running" | "done" | "error";

interface StageDef {
  key: string;
  code: string;
  label: string;
}

/** Type-to-filter app picker. A device can list hundreds of packages, so a
 *  free-text input that narrows the list beats scrolling a dropdown. The
 *  committed `value` is only ever a real package name (empty until one is
 *  picked), so callers can trust it directly. */
function PackageCombobox({
  packages,
  value,
  onChange,
  disabled,
  loading,
}: {
  packages: DevicePackage[];
  value: string;
  onChange: (pkg: string) => void;
  disabled?: boolean;
  loading?: boolean;
}) {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const rootRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // Clear the typed query whenever the app set is (re)loaded.
  useEffect(() => {
    setQuery("");
  }, [packages]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = q
      ? packages.filter((p) => p.package.toLowerCase().includes(q))
      : packages;
    return list.slice(0, 200); // cap the rendered rows for big device lists
  }, [packages, query]);

  // Close when clicking outside the control.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  // Keep the highlighted row in view while arrowing through the list.
  useEffect(() => {
    if (!open) return;
    listRef.current
      ?.querySelector<HTMLElement>('[data-active="true"]')
      ?.scrollIntoView({ block: "nearest" });
  }, [active, open]);

  // A partial or unknown string isn't a valid target, so commit "" until the
  // text is an exact package name.
  const commit = (val: string) =>
    onChange(packages.some((p) => p.package === val) ? val : "");

  const select = (pkg: string) => {
    setQuery(pkg);
    onChange(pkg);
    setOpen(false);
  };

  return (
    <div ref={rootRef} className="relative flex-1">
      <Search className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 size-3.5 text-muted-foreground" />
      <input
        value={query}
        disabled={disabled}
        spellCheck={false}
        autoComplete="off"
        placeholder={loading ? "Loading apps…" : "Search apps by package name"}
        onChange={(e) => {
          setQuery(e.target.value);
          setActive(0);
          setOpen(true);
          commit(e.target.value);
        }}
        onFocus={() => setOpen(true)}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") {
            e.preventDefault();
            setOpen(true);
            setActive((i) => Math.min(i + 1, filtered.length - 1));
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setActive((i) => Math.max(i - 1, 0));
          } else if (e.key === "Enter") {
            if (open && filtered[active]) {
              e.preventDefault();
              select(filtered[active].package);
            }
          } else if (e.key === "Escape") {
            if (open) {
              e.preventDefault();
              setOpen(false);
            }
          }
        }}
        className="w-full h-8 rounded-md border border-border/60 bg-bg-2/30 pl-8 pr-8 text-sm font-mono text-text-0 outline-none transition-colors placeholder:font-sans placeholder:text-muted-foreground focus:border-foreground/50 focus:ring-1 focus:ring-ring/40 disabled:opacity-50"
      />
      {value && !open && (
        <Check className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 size-3.5 text-text-0" />
      )}
      {open && !disabled && (
        <div
          ref={listRef}
          className="absolute z-50 mt-1 max-h-64 w-full overflow-auto rounded-md border border-border bg-bg-1 py-1 shadow-lg"
        >
          {filtered.length === 0 ? (
            <div className="px-3 py-2 text-[11px] text-muted-foreground">
              {loading
                ? "Loading apps…"
                : packages.length === 0
                  ? "No apps found on device."
                  : "No apps match your search."}
            </div>
          ) : (
            filtered.map((p, i) => (
              <button
                key={p.package}
                type="button"
                data-active={i === active}
                onMouseEnter={() => setActive(i)}
                onClick={() => select(p.package)}
                className={`flex w-full items-center gap-2 px-3 py-1.5 text-left font-mono text-[12px] transition-colors ${
                  i === active ? "bg-bg-2 text-text-0" : "text-text-1"
                }`}
              >
                <Check
                  className={`size-3 shrink-0 ${
                    p.package === value ? "text-text-0" : "opacity-0"
                  }`}
                />
                <span className="truncate">{p.package}</span>
              </button>
            ))
          )}
        </div>
      )}
    </div>
  );
}

export default function PatchApkDialog({ open, onOpenChange, device }: Props) {
  // Device-bound mode pulls/installs against this serial; file mode is local.
  const source: "file" | "device" = device ? "device" : "file";
  const serial = device?.serial ?? "";

  // ── Tooling ────────────────────────────────────────────────────────────
  const [missingTools, setMissingTools] = useState<string[] | null>(null); // null = checking

  // ── Source ─────────────────────────────────────────────────────────────
  const [apkPath, setApkPath] = useState("");
  const [dragOver, setDragOver] = useState(false);

  const [packages, setPackages] = useState<DevicePackage[]>([]);
  const [pkg, setPkg] = useState("");
  const [pkgLoading, setPkgLoading] = useState(false);
  // Flag PAIRIP-protected apps (repackaging can't work) once one is selected.
  const { protection } = useAppProtection(serial, pkg);

  // ── Options ────────────────────────────────────────────────────────────
  const [opts, setOpts] = useState<PatchOpts>(DEFAULT_PATCH_OPTS);
  const patchOpt = useCallback(
    (patch: Partial<PatchOpts>) => setOpts((p) => ({ ...p, ...patch })),
    [],
  );

  // ── Run ────────────────────────────────────────────────────────────────
  const [run, setRun] = useState<RunState>("idle");
  const [activeStage, setActiveStage] = useState<string>("");
  const [errorMsg, setErrorMsg] = useState("");
  const [result, setResult] = useState<PatchResult | null>(null);
  const [installState, setInstallState] = useState<
    "idle" | "installing" | "confirm" | "done" | "error"
  >("idle");
  const [installMsg, setInstallMsg] = useState("");
  const unlistenRef = useRef<UnlistenFn | null>(null);

  // Pipeline stages — computed from the active options so the rail mirrors
  // exactly what the backend will run.
  const stages = useMemo<StageDef[]>(() => {
    const s: StageDef[] = [];
    if (source === "device")
      s.push({ key: "pull", code: "00", label: "Pull from device" });
    s.push({ key: "decode", code: "01", label: "Decompile" });
    s.push({ key: "inject", code: "02", label: "Security config" });
    s.push({ key: "manifest", code: "03", label: "Patch manifest" });
    if (opts.frida) s.push({ key: "frida", code: "04", label: "Frida gadget" });
    s.push({ key: "build", code: opts.frida ? "05" : "04", label: "Rebuild" });
    s.push({ key: "align", code: opts.frida ? "06" : "05", label: "Zipalign" });
    s.push({ key: "sign", code: opts.frida ? "07" : "06", label: "Sign" });
    return s;
  }, [source, opts.frida]);

  // ── Effects ────────────────────────────────────────────────────────────
  useEffect(() => {
    if (!open) return;
    setMissingTools(null); // Start in checking state
    invoke<string[]>("check_apk_tools")
      .then(setMissingTools)
      .catch(() => setMissingTools([]));
    // reset transient run state when reopened
    setOpts(DEFAULT_PATCH_OPTS);
    setApkPath("");
    setPkg("");
    setRun("idle");
    setResult(null);
    setErrorMsg("");
    setActiveStage("");
    setInstallState("idle");
    setInstallMsg("");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  // Native file-drop — drag the .apk straight onto the dialog.
  useEffect(() => {
    if (!open || source !== "file") return;
    let unlisten: UnlistenFn | undefined;
    getCurrentWebview()
      .onDragDropEvent((e) => {
        if (e.payload.type === "over") setDragOver(true);
        else if (e.payload.type === "leave") setDragOver(false);
        else if (e.payload.type === "drop") {
          setDragOver(false);
          const apk = e.payload.paths.find((p) =>
            p.toLowerCase().endsWith(".apk"),
          );
          if (apk) setApkPath(apk);
        }
      })
      .then((fn) => (unlisten = fn));
    return () => unlisten?.();
  }, [open, source]);

  useEffect(() => () => unlistenRef.current?.(), []);

  const refreshPackages = useCallback(() => {
    if (!serial) return;
    setPkgLoading(true);
    setPackages([]);
    invoke<DevicePackage[]>("list_device_packages", { serial })
      .then((p) => setPackages(p))
      .catch(() => setPackages([]))
      .finally(() => setPkgLoading(false));
  }, [serial]);

  // Load the device's apps when patching from a device.
  useEffect(() => {
    if (!open || source !== "device" || !serial) return;
    setPkg("");
    refreshPackages();
  }, [open, source, serial, refreshPackages]);

  const browseApk = async () => {
    try {
      const picked = await openFileDialog({
        multiple: false,
        directory: false,
        filters: [{ name: "Android Package", extensions: ["apk"] }],
      });
      if (typeof picked === "string") setApkPath(picked);
    } catch {
      /* cancelled */
    }
  };

  const canPatch =
    run !== "running" &&
    missingTools !== null &&
    missingTools.length === 0 &&
    patchOptsValid(opts) &&
    !protection?.pairip &&
    (source === "file" ? apkPath !== "" : pkg !== "");

  const startPatch = async () => {
    setRun("running");
    setResult(null);
    setErrorMsg("");
    setActiveStage(source === "device" ? "pull" : "decode");
    setInstallState("idle");

    try {
      // Subscribe to progress for the rail.
      unlistenRef.current?.();
      unlistenRef.current = await listen<PatchProgress>(
        "apk-patch-progress",
        (e) => {
          setActiveStage(e.payload.stage);
        },
      );

      let path = apkPath;
      if (source === "device") {
        path = await invoke<string>("pull_apk", { serial, package: pkg });
        setApkPath(path);
      }
      const res = await invoke<PatchResult>("patch_apk", {
        opts: backendPatchOpts(path, opts),
      });
      setResult(res);
      setActiveStage("done");
      setRun("done");
    } catch (err) {
      setErrorMsg(String(err));
      setRun("error");
    } finally {
      unlistenRef.current?.();
      unlistenRef.current = null;
    }
  };

  const installToDevice = async () => {
    if (!result || !serial) return;
    setInstallState("installing");
    setInstallMsg("");
    try {
      const res = await invoke<{ status: string; message: string }>(
        "install_patched_apk",
        {
          serial,
          apkPath: result.outputPath,
          package: pkg || undefined,
        },
      );
      setInstallMsg(res.message);
      // Signature clash: replacing would wipe the app's data — ask first.
      setInstallState(res.status === "needsReplace" ? "confirm" : "done");
    } catch (err) {
      setInstallState("error");
      setInstallMsg(String(err));
    }
  };

  // User confirmed the data-wiping reinstall from the "confirm" prompt.
  const confirmReplace = async () => {
    if (!result || !serial) return;
    setInstallState("installing");
    try {
      const msg = await invoke<string>("replace_patched_apk", {
        serial,
        apkPath: result.outputPath,
        package: pkg,
      });
      setInstallMsg(msg);
      setInstallState("done");
    } catch (err) {
      setInstallState("error");
      setInstallMsg(String(err));
    }
  };

  // Index of the current stage for rail status math.
  const activeIdx = stages.findIndex((s) => s.key === activeStage);
  const finished = run === "done";

  const stageStatus = (i: number): "done" | "active" | "error" | "pending" => {
    if (finished) return "done";
    if (run === "error") {
      if (i < activeIdx) return "done";
      if (i === activeIdx) return "error";
      return "pending";
    }
    if (activeIdx === -1) return "pending";
    if (i < activeIdx) return "done";
    if (i === activeIdx) return "active";
    return "pending";
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => run !== "running" && onOpenChange(o)}
    >
      <DialogContent className="bg-bg-1 border-border max-w-2xl p-0 flex flex-col gap-0 max-h-[88vh] overflow-hidden">
        <style>{RAIL_CSS}</style>

        <DialogHeader className="px-6 pt-6 pb-4 border-b border-border/60">
          <DialogTitle className="font-chakra text-text-0 text-xl flex items-center gap-2 tracking-wide">
            <Boxes className="size-5" /> Patch APK
          </DialogTitle>
          <DialogDescription className="text-text-2 text-xs">
            {source === "device" ? (
              <>
                Repackage{" "}
                <span className="text-text-1">
                  {device?.model || device?.serial}
                </span>
                's app to trust the proxy CA, then reinstall it — decrypt its
                HTTPS in the inspector. For authorized analysis only.
              </>
            ) : (
              <>
                Repackage a local <span className="text-text-1">.apk</span> to
                trust the proxy CA — decrypt its HTTPS in the inspector. For
                authorized analysis only.
              </>
            )}
          </DialogDescription>
        </DialogHeader>

        {missingTools !== null && missingTools.length > 0 && (
          <div className="mx-6 mt-4 flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2">
            <TriangleAlert className="size-4 text-destructive shrink-0 mt-0.5" />
            <p className="text-[11px] text-text-1 leading-relaxed">
              Missing tools on PATH:{" "}
              <span className="font-mono text-destructive">
                {missingTools.join(", ")}
              </span>
              . Install the Android SDK build-tools, platform-tools and apktool.
            </p>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-[1fr_15rem] min-h-0 flex-1">
          {/* ── Left: configuration ─────────────────────────────────── */}
          <ScrollArea className="min-h-0 border-r border-border/60">
            <div className="px-6 py-5 space-y-5">
              {source === "file" ? (
                <button
                  type="button"
                  onClick={browseApk}
                  className={`group w-full rounded-md border border-dashed px-4 py-7 flex flex-col items-center justify-center gap-2 transition-colors ${
                    dragOver
                      ? "border-foreground bg-bg-2/60"
                      : "border-border hover:border-foreground/50 bg-bg-2/20"
                  }`}
                >
                  <FolderOpen className="size-5 text-muted-foreground group-hover:text-text-0 transition-colors" />
                  {apkPath ? (
                    <span className="text-[11px] font-mono text-text-0 break-all text-center leading-snug">
                      {apkPath}
                    </span>
                  ) : (
                    <span className="text-xs text-muted-foreground">
                      Drag an <span className="text-text-1">.apk</span> here, or
                      click to browse
                    </span>
                  )}
                </button>
              ) : (
                <div className="space-y-3">
                  <div className="space-y-1.5">
                    <Label className="text-[11px] uppercase tracking-wider text-muted-foreground">
                      Device
                    </Label>
                    <div className="flex items-center gap-2 rounded-md border border-border/60 bg-bg-2/30 px-3 h-8 text-sm text-text-0">
                      <Smartphone className="size-3.5 text-muted-foreground shrink-0" />
                      <span className="truncate">
                        {device?.model || device?.serial}
                      </span>
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <Label className="flex items-center gap-2 text-[11px] uppercase tracking-wider text-muted-foreground">
                      <span>
                        Package{" "}
                        {pkgLoading && (
                          <span className="text-text-2">· loading…</span>
                        )}
                      </span>
                      {protection?.pairip && <PairipChip />}
                    </Label>
                    <div className="flex items-center gap-2">
                      <PackageCombobox
                        packages={packages}
                        value={pkg}
                        onChange={setPkg}
                        disabled={!serial}
                        loading={pkgLoading}
                      />
                      <Button
                        variant="outline"
                        size="xs"
                        onClick={refreshPackages}
                        aria-label="Refresh packages"
                      >
                        <RefreshCw className="size-3.5" />
                      </Button>
                    </div>
                  </div>
                  {protection?.pairip && <PairipBanner />}
                </div>
              )}

              {/* Options */}
              <PatchOptions opts={opts} onChange={patchOpt} />

              {!opts.embedCa && !opts.trustUser && (
                <p className="text-[11px] text-destructive">
                  Enable at least one trust anchor (embed CA or user store).
                </p>
              )}
            </div>
          </ScrollArea>

          {/* ── Right: pipeline rail ────────────────────────────────── */}
          <div className="relative bg-bg-0/60 patch-rail-grain overflow-hidden">
            <div className="px-5 py-5">
              <div className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-mono mb-4">
                Pipeline
              </div>
              <div className="relative">
                {stages.map((s, i) => {
                  const st = stageStatus(i);
                  return (
                    <div
                      key={s.key}
                      className="relative flex items-start gap-3 pb-5 last:pb-0"
                    >
                      {/* connector */}
                      {i < stages.length - 1 && (
                        <span
                          className={`absolute left-[11px] top-6 bottom-0 w-px ${
                            st === "done" ? "bg-foreground/50" : "bg-border"
                          }`}
                        />
                      )}
                      {/* node */}
                      <span
                        className={`relative z-10 grid place-items-center size-6 rounded-full border shrink-0 transition-colors ${
                          st === "done"
                            ? "border-foreground bg-foreground text-background"
                            : st === "active"
                              ? "border-foreground text-text-0 rail-node-active"
                              : st === "error"
                                ? "border-destructive text-destructive"
                                : "border-border text-muted-foreground"
                        }`}
                      >
                        {st === "done" ? (
                          <Check className="size-3.5" />
                        ) : st === "error" ? (
                          <X className="size-3.5" />
                        ) : st === "active" ? (
                          <span className="size-1.5 rounded-full bg-foreground rail-blink" />
                        ) : (
                          <span className="text-[9px] font-mono">{s.code}</span>
                        )}
                      </span>
                      <div className="pt-0.5 min-w-0">
                        <div
                          className={`text-[10px] font-mono tracking-wider ${
                            st === "pending"
                              ? "text-muted-foreground"
                              : "text-text-2"
                          }`}
                        >
                          {s.code}
                        </div>
                        <div
                          className={`text-xs leading-tight ${
                            st === "active"
                              ? "text-text-0 font-medium"
                              : st === "pending"
                                ? "text-muted-foreground"
                                : "text-text-1"
                          }`}
                        >
                          {s.label}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* ── Footer ──────────────────────────────────────────────────── */}
        <div className="border-t border-border/60 bg-bg-2/30 px-6 py-3 space-y-3">
          {run === "error" && (
            <div className="flex items-start gap-2 text-[11px] text-destructive">
              <X className="size-3.5 shrink-0 mt-0.5" />
              <span className="font-mono break-all">{errorMsg}</span>
            </div>
          )}

          {finished && result && (
            <div className="space-y-2">
              <div className="flex items-center gap-2 rounded-md border border-foreground/30 bg-bg-2/50 px-3 py-2">
                <Check className="size-4 text-text-0 shrink-0" />
                <span className="text-[11px] font-mono text-text-1 break-all flex-1">
                  {result.outputPath}
                </span>
                <button
                  onClick={() =>
                    navigator.clipboard.writeText(result.outputPath)
                  }
                  className="text-muted-foreground hover:text-text-0 shrink-0"
                  aria-label="Copy path"
                >
                  <Copy className="size-3.5" />
                </button>
              </div>
              {result.warnings.length > 0 && (
                <ul className="space-y-1">
                  {result.warnings.map((w, i) => (
                    <li
                      key={i}
                      className="flex items-start gap-1.5 text-[10px] text-muted-foreground leading-snug"
                    >
                      <TriangleAlert className="size-3 shrink-0 mt-0.5" />
                      <span>{w}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}

          <div className="flex items-center justify-between gap-3">
            <div className="text-[11px] text-muted-foreground">
              {run === "running"
                ? "Patching… do not close"
                : finished
                  ? "Patch complete"
                  : "Output is re-signed with a debug key"}
            </div>
            <div className="flex items-center gap-2">
              {finished && source === "device" && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={installToDevice}
                  disabled={
                    installState === "installing" ||
                    installState === "confirm" ||
                    !serial
                  }
                >
                  {installState === "installing" ? (
                    <Spinner size={14} />
                  ) : installState === "done" ? (
                    <Check className="size-3.5 mr-1" />
                  ) : (
                    <Smartphone className="size-3.5 mr-1" />
                  )}
                  {installState === "done" ? "Installed" : "Install"}
                </Button>
              )}
              {finished ? (
                <Button size="sm" onClick={() => onOpenChange(false)}>
                  Done
                </Button>
              ) : (
                <Button size="sm" onClick={startPatch} disabled={!canPatch}>
                  {run === "running" ? <Spinner size={14} /> : "Patch"}
                </Button>
              )}
            </div>
          </div>
          {installState === "error" && (
            <p className="text-[11px] text-destructive font-mono break-all">
              {installMsg}
            </p>
          )}
          {installState === "confirm" && (
            <div className="flex items-start gap-2 rounded-md border border-yellow-500/40 bg-yellow-500/10 px-3 py-3">
              <TriangleAlert className="size-4 text-yellow-500 shrink-0 mt-0.5" />
              <div className="space-y-2.5">
                <p className="text-[11px] text-text-1 leading-relaxed">
                  {installMsg} Replace it anyway?
                </p>
                <div className="flex items-center gap-2">
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={confirmReplace}
                  >
                    Replace &amp; erase data
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setInstallState("idle")}
                  >
                    Cancel
                  </Button>
                </div>
              </div>
            </div>
          )}
          {installState === "done" && installMsg.includes("data was cleared") && (
            <div className="flex items-start gap-2 rounded-md border border-yellow-500/40 bg-yellow-500/10 px-3 py-2">
              <TriangleAlert className="size-4 text-yellow-500 shrink-0 mt-0.5" />
              <p className="text-[11px] text-text-1 leading-relaxed">
                The installed app was signed differently than the version already
                on the device, so the original had to be uninstalled and replaced
                — <span className="font-medium">its existing data was erased.</span>
              </p>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

const RAIL_CSS = `
.patch-rail-grain {
  background-image:
    repeating-linear-gradient(
      0deg,
      color-mix(in oklch, var(--foreground) 3%, transparent) 0px,
      color-mix(in oklch, var(--foreground) 3%, transparent) 1px,
      transparent 1px,
      transparent 3px
    );
}
.rail-node-active {
  box-shadow: 0 0 0 0 color-mix(in oklch, var(--foreground) 45%, transparent);
  animation: railGlow 1.4s ease-out infinite;
}
@keyframes railGlow {
  0%   { box-shadow: 0 0 0 0 color-mix(in oklch, var(--foreground) 45%, transparent); }
  70%  { box-shadow: 0 0 0 7px color-mix(in oklch, var(--foreground) 0%, transparent); }
  100% { box-shadow: 0 0 0 0 color-mix(in oklch, var(--foreground) 0%, transparent); }
}
.rail-blink { animation: railBlink 1s steps(1) infinite; }
@keyframes railBlink { 0%, 50% { opacity: 1; } 50.01%, 100% { opacity: 0.25; } }
`;
