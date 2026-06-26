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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import Switch from "./Switch";
import Spinner from "./Spinner";
import {
  Boxes,
  Smartphone,
  FileDown,
  FolderOpen,
  Check,
  X,
  TriangleAlert,
  RefreshCw,
  Copy,
  Syringe,
  ShieldCheck,
  Cpu,
} from "lucide-react";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface AdbDevice {
  serial: string;
  state: string;
  model: string;
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

type Source = "file" | "device";
type RunState = "idle" | "running" | "done" | "error";

interface StageDef {
  key: string;
  code: string;
  label: string;
}

export default function PatchApkDialog({ open, onOpenChange }: Props) {
  // ── Tooling ────────────────────────────────────────────────────────────
  const [missingTools, setMissingTools] = useState<string[]>([]);

  // ── Source ─────────────────────────────────────────────────────────────
  const [source, setSource] = useState<Source>("file");
  const [apkPath, setApkPath] = useState("");
  const [dragOver, setDragOver] = useState(false);

  const [devices, setDevices] = useState<AdbDevice[]>([]);
  const [serial, setSerial] = useState("");
  const [packages, setPackages] = useState<DevicePackage[]>([]);
  const [pkg, setPkg] = useState("");
  const [pkgLoading, setPkgLoading] = useState(false);

  // ── Options ────────────────────────────────────────────────────────────
  const [embedCa, setEmbedCa] = useState(true);
  const [trustUser, setTrustUser] = useState(false);
  const [debuggable, setDebuggable] = useState(false);
  const [frida, setFrida] = useState(false);
  const [fridaPath, setFridaPath] = useState("");
  const [fridaAbi, setFridaAbi] = useState("auto");

  // ── Run ────────────────────────────────────────────────────────────────
  const [run, setRun] = useState<RunState>("idle");
  const [activeStage, setActiveStage] = useState<string>("");
  const [errorMsg, setErrorMsg] = useState("");
  const [result, setResult] = useState<PatchResult | null>(null);
  const [installState, setInstallState] = useState<
    "idle" | "installing" | "done" | "error"
  >("idle");
  const [installMsg, setInstallMsg] = useState("");
  const unlistenRef = useRef<UnlistenFn | null>(null);

  // Pipeline stages — computed from the active options so the rail mirrors
  // exactly what the backend will run.
  const stages = useMemo<StageDef[]>(() => {
    const s: StageDef[] = [];
    if (source === "device") s.push({ key: "pull", code: "00", label: "Pull from device" });
    s.push({ key: "decode", code: "01", label: "Decompile" });
    s.push({ key: "inject", code: "02", label: "Security config" });
    s.push({ key: "manifest", code: "03", label: "Patch manifest" });
    if (frida) s.push({ key: "frida", code: "04", label: "Frida gadget" });
    s.push({ key: "build", code: frida ? "05" : "04", label: "Rebuild" });
    s.push({ key: "align", code: frida ? "06" : "05", label: "Zipalign" });
    s.push({ key: "sign", code: frida ? "07" : "06", label: "Sign" });
    return s;
  }, [source, frida]);

  // ── Effects ────────────────────────────────────────────────────────────
  useEffect(() => {
    if (!open) return;
    invoke<string[]>("check_apk_tools").then(setMissingTools).catch(() => {});
    refreshDevices();
    // reset transient run state when reopened
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
          const apk = e.payload.paths.find((p) => p.toLowerCase().endsWith(".apk"));
          if (apk) setApkPath(apk);
        }
      })
      .then((fn) => (unlisten = fn));
    return () => unlisten?.();
  }, [open, source]);

  useEffect(() => () => unlistenRef.current?.(), []);

  const refreshDevices = useCallback(async () => {
    try {
      const ds = await invoke<AdbDevice[]>("list_adb_devices");
      setDevices(ds);
      if (ds.length && !ds.some((d) => d.serial === serial)) {
        setSerial(ds[0].serial);
      }
    } catch {
      setDevices([]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [serial]);

  // Load packages when a device is chosen.
  useEffect(() => {
    if (source !== "device" || !serial) return;
    setPkgLoading(true);
    setPackages([]);
    setPkg("");
    invoke<DevicePackage[]>("list_device_packages", { serial })
      .then((p) => setPackages(p))
      .catch(() => setPackages([]))
      .finally(() => setPkgLoading(false));
  }, [source, serial]);

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

  const browseGadget = async () => {
    try {
      const picked = await openFileDialog({
        multiple: false,
        directory: false,
        filters: [{ name: "Frida gadget", extensions: ["so"] }],
      });
      if (typeof picked === "string") setFridaPath(picked);
    } catch {
      /* cancelled */
    }
  };

  const canPatch =
    run !== "running" &&
    missingTools.length === 0 &&
    (embedCa || trustUser) &&
    (source === "file" ? apkPath !== "" : serial !== "" && pkg !== "") &&
    (!frida || fridaPath !== "");

  const startPatch = async () => {
    setRun("running");
    setResult(null);
    setErrorMsg("");
    setActiveStage(source === "device" ? "pull" : "decode");
    setInstallState("idle");

    // Subscribe to progress for the rail.
    unlistenRef.current?.();
    unlistenRef.current = await listen<PatchProgress>("apk-patch-progress", (e) => {
      setActiveStage(e.payload.stage);
    });

    try {
      let path = apkPath;
      if (source === "device") {
        path = await invoke<string>("pull_apk", { serial, package: pkg });
        setApkPath(path);
      }
      const res = await invoke<PatchResult>("patch_apk", {
        opts: {
          apkPath: path,
          embedProxyCa: embedCa,
          trustUserStore: trustUser,
          makeDebuggable: debuggable,
          injectFrida: frida,
          fridaGadgetPath: fridaPath,
          fridaAbi: fridaAbi,
        },
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
      await invoke<string>("install_patched_apk", {
        serial,
        apkPath: result.outputPath,
        package: source === "device" ? pkg : undefined,
      });
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
    <Dialog open={open} onOpenChange={(o) => run !== "running" && onOpenChange(o)}>
      <DialogContent className="bg-bg-1 border-border max-w-2xl p-0 flex flex-col gap-0 max-h-[88vh] overflow-hidden">
        <style>{RAIL_CSS}</style>

        <DialogHeader className="px-6 pt-6 pb-4 border-b border-border/60">
          <DialogTitle className="font-chakra text-text-0 text-xl flex items-center gap-2 tracking-wide">
            <Boxes className="size-5" /> Patch APK
          </DialogTitle>
          <DialogDescription className="text-text-2 text-xs">
            Repackage an Android app to trust the proxy CA — decrypt its HTTPS in
            the inspector. For authorized analysis only.
          </DialogDescription>
        </DialogHeader>

        {missingTools.length > 0 && (
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
              {/* Source toggle */}
              <Segmented
                value={source}
                onChange={(v) => setSource(v as Source)}
                options={[
                  { value: "file", label: "Local file", icon: <FileDown className="size-3.5" /> },
                  { value: "device", label: "From device", icon: <Smartphone className="size-3.5" /> },
                ]}
              />

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
                      Drag an <span className="text-text-1">.apk</span> here, or click to browse
                    </span>
                  )}
                </button>
              ) : (
                <div className="space-y-3">
                  <div className="space-y-1.5">
                    <Label className="text-[11px] uppercase tracking-wider text-muted-foreground">
                      Device
                    </Label>
                    <div className="flex items-center gap-2">
                      <Select value={serial} onValueChange={setSerial}>
                        <SelectTrigger className="h-8 text-sm flex-1">
                          <SelectValue placeholder={devices.length ? "Select device" : "No devices"} />
                        </SelectTrigger>
                        <SelectContent>
                          {devices.map((d) => (
                            <SelectItem key={d.serial} value={d.serial}>
                              {d.model || d.serial}
                              <span className="text-muted-foreground ml-1.5 text-[11px]">
                                {d.state}
                              </span>
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <Button variant="outline" size="xs" onClick={refreshDevices} aria-label="Refresh devices">
                        <RefreshCw className="size-3.5" />
                      </Button>
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <Label className="text-[11px] uppercase tracking-wider text-muted-foreground">
                      Package {pkgLoading && <span className="text-text-2">· loading…</span>}
                    </Label>
                    <Select value={pkg} onValueChange={setPkg} disabled={!serial || pkgLoading}>
                      <SelectTrigger className="h-8 text-sm">
                        <SelectValue placeholder="Select app" />
                      </SelectTrigger>
                      <SelectContent className="max-h-72">
                        {packages.map((p) => (
                          <SelectItem key={p.package} value={p.package}>
                            <span className="font-mono text-[12px]">{p.package}</span>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              )}

              {/* Options */}
              <div className="space-y-px rounded-md border border-border/60 overflow-hidden">
                <OptionRow
                  icon={<ShieldCheck className="size-3.5" />}
                  title="Embed proxy CA"
                  hint="Bake the CA into the app — no cert install on the phone."
                  checked={embedCa}
                  onChange={setEmbedCa}
                />
                <OptionRow
                  title="Trust user CA store"
                  hint="Also trust certs installed on the device."
                  checked={trustUser}
                  onChange={setTrustUser}
                />
                <OptionRow
                  title="Make debuggable"
                  hint="Set android:debuggable — eases runtime hooking."
                  checked={debuggable}
                  onChange={setDebuggable}
                />
                <OptionRow
                  icon={<Syringe className="size-3.5" />}
                  title="Inject Frida gadget"
                  hint="Defeat code-level cert pinning on non-rooted devices."
                  checked={frida}
                  onChange={setFrida}
                />
                {frida && (
                  <div className="px-3 py-3 bg-bg-2/40 space-y-2">
                    <div className="flex items-center gap-2">
                      <Input
                        value={fridaPath}
                        placeholder="path to libfrida-gadget.so"
                        spellCheck={false}
                        onChange={(e) => setFridaPath(e.target.value)}
                        className="h-7 text-[12px] font-mono flex-1"
                      />
                      <Button variant="outline" size="xs" onClick={browseGadget}>
                        <FolderOpen className="size-3.5" />
                      </Button>
                    </div>
                    <div className="flex items-center gap-2">
                      <Cpu className="size-3.5 text-muted-foreground" />
                      <Label className="text-[11px] text-muted-foreground">ABI</Label>
                      <Select value={fridaAbi} onValueChange={setFridaAbi}>
                        <SelectTrigger className="h-7 text-xs w-40">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="auto">auto-detect</SelectItem>
                          <SelectItem value="arm64-v8a">arm64-v8a</SelectItem>
                          <SelectItem value="armeabi-v7a">armeabi-v7a</SelectItem>
                          <SelectItem value="x86_64">x86_64</SelectItem>
                          <SelectItem value="x86">x86</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                )}
              </div>

              {!embedCa && !trustUser && (
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
                    <div key={s.key} className="relative flex items-start gap-3 pb-5 last:pb-0">
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
                            st === "pending" ? "text-muted-foreground" : "text-text-2"
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
                  onClick={() => navigator.clipboard.writeText(result.outputPath)}
                  className="text-muted-foreground hover:text-text-0 shrink-0"
                  aria-label="Copy path"
                >
                  <Copy className="size-3.5" />
                </button>
              </div>
              {result.warnings.length > 0 && (
                <ul className="space-y-1">
                  {result.warnings.map((w, i) => (
                    <li key={i} className="flex items-start gap-1.5 text-[10px] text-muted-foreground leading-snug">
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
              {finished && devices.length > 0 && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={installToDevice}
                  disabled={installState === "installing" || !serial}
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
            <p className="text-[11px] text-destructive font-mono break-all">{installMsg}</p>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ── Small building blocks ──────────────────────────────────────────────────

function Segmented({
  value,
  onChange,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string; icon: React.ReactNode }[];
}) {
  return (
    <div className="grid grid-cols-2 gap-1 p-1 rounded-md bg-bg-2/50 border border-border/60">
      {options.map((o) => (
        <button
          key={o.value}
          onClick={() => onChange(o.value)}
          className={`flex items-center justify-center gap-1.5 h-7 rounded text-xs transition-colors ${
            value === o.value
              ? "bg-bg-1 text-text-0 shadow-sm border border-border/80"
              : "text-muted-foreground hover:text-text-1"
          }`}
        >
          {o.icon}
          {o.label}
        </button>
      ))}
    </div>
  );
}

function OptionRow({
  icon,
  title,
  hint,
  checked,
  onChange,
}: {
  icon?: React.ReactNode;
  title: string;
  hint: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="flex items-center gap-3 px-3 py-2.5 bg-bg-1 hover:bg-bg-2/30 transition-colors cursor-pointer border-b border-border/40 last:border-b-0">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-1.5 text-sm text-text-0">
          {icon}
          {title}
        </div>
        <div className="text-[11px] text-muted-foreground leading-snug">{hint}</div>
      </div>
      <Switch checked={checked} onChange={onChange} />
    </label>
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
