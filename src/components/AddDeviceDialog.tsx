import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import Switch from "./Switch";
import Spinner from "./Spinner";
import PatchOptions, {
  type PatchOpts,
  DEFAULT_PATCH_OPTS,
  backendPatchOpts,
  patchOptsValid,
} from "./PatchOptions";
import { useAppProtection, PairipChip, PairipBanner } from "./PairipNotice";
import type { ConnectedDevice, SessionEvent } from "@/types";
import {
  Monitor,
  Smartphone,
  Check,
  X,
  Search,
  RefreshCw,
  Download,
  ShieldCheck,
  TriangleAlert,
  ChevronLeft,
  Usb,
  Wifi,
  Activity,
} from "lucide-react";

// ── The one earned spot of color: the "live" green, matching the 2xx status dot.
const LIVE = "#00ca50";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onConnected: (device: ConnectedDevice) => void;
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

type Phase = "tools" | "connect" | "app" | "live";

const STATIONS: { key: Phase; code: string; label: string }[] = [
  { key: "tools", code: "01", label: "Toolchain" },
  { key: "connect", code: "02", label: "Connect" },
  { key: "app", code: "03", label: "Choose app" },
  { key: "live", code: "04", label: "Capture" },
];

// Tools that only matter for the advanced "patch the app" path. adb (the one
// essential) is handled separately and can be auto-installed.
const PATCH_TOOLS: { bin: string; role: string }[] = [
  { bin: "apktool", role: "Unpacks the app" },
  { bin: "apksigner", role: "Re-signs it" },
  { bin: "zipalign", role: "Aligns the rebuild" },
  { bin: "keytool", role: "Makes the signing key" },
  { bin: "java", role: "Runs the tools" },
];

export default function AddDeviceDialog({
  open,
  onOpenChange,
  onConnected,
}: Props) {
  const [phase, setPhase] = useState<Phase>("tools");

  // Toolchain
  const [missing, setMissing] = useState<string[] | null>(null); // null = probing
  const [installing, setInstalling] = useState(false);
  const [toolsMsg, setToolsMsg] = useState("");
  const [installingPatch, setInstallingPatch] = useState(false);
  const [patchMsg, setPatchMsg] = useState("");

  // Connect
  const [devices, setDevices] = useState<AdbDevice[]>([]);
  const [serial, setSerial] = useState("");

  // App
  const [packages, setPackages] = useState<DevicePackage[]>([]);
  const [pkg, setPkg] = useState("");
  const [query, setQuery] = useState("");
  const [pkgLoading, setPkgLoading] = useState(false);
  // PAIRIP-protected apps can't be repackaged — flag the selected one.
  const { protection: pkgProtection } = useAppProtection(serial, pkg);
  const pairip = !!pkgProtection?.pairip;
  const [patchApp, setPatchApp] = useState(false);
  const [patchOpts, setPatchOpts] = useState<PatchOpts>(DEFAULT_PATCH_OPTS);
  const [connecting, setConnecting] = useState(false);
  const [stage, setStage] = useState("");
  const [connectErr, setConnectErr] = useState("");

  // Live
  const [device, setDevice] = useState<ConnectedDevice | null>(null);
  const [liveCount, setLiveCount] = useState(0);
  const [dataWiped, setDataWiped] = useState(false);
  // Set when an install hit a signature clash mid-onboarding: the patched APK
  // path + device tag are stashed so a user-confirmed replace can resume the flow.
  const [pendingReplace, setPendingReplace] = useState<{
    apkPath: string;
    tag: string;
  } | null>(null);

  const busy = installing || installingPatch || connecting;
  const adbMissing = (missing ?? []).includes("adb");
  const patchToolsMissing = (missing ?? []).filter((t) => t !== "adb");
  const canPatch = missing !== null && patchToolsMissing.length === 0;
  const authDevice = devices.find(
    (d) => d.serial === serial && d.state === "device",
  );
  const pendingDevice = devices.find(
    (d) => d.serial === serial && d.state !== "device",
  );

  const phaseIndex = STATIONS.findIndex((s) => s.key === phase);
  const linkActive = phase === "app" || phase === "live";

  // ── Reset on open ──────────────────────────────────────────────────────
  useEffect(() => {
    if (!open) return;
    setPhase("tools");
    setMissing(null);
    setToolsMsg("");
    setPatchMsg("");
    setInstallingPatch(false);
    setSerial("");
    setPkg("");
    setQuery("");
    setPatchApp(false);
    setPatchOpts(DEFAULT_PATCH_OPTS);
    setDevice(null);
    setLiveCount(0);
    setDataWiped(false);
    setPendingReplace(null);
    setConnectErr("");
    setStage("");
    invoke<string[]>("check_apk_tools")
      .then(setMissing)
      .catch(() => setMissing([]));
  }, [open]);

  // ── Poll for devices while the user is plugging in ─────────────────────
  useEffect(() => {
    if (!open || phase === "live") return;
    let active = true;
    const tick = async () => {
      try {
        const ds = await invoke<AdbDevice[]>("list_adb_devices");
        if (!active) return;
        setDevices(ds);
        setSerial((prev) =>
          prev && ds.some((d) => d.serial === prev)
            ? prev
            : (ds.find((d) => d.state === "device")?.serial ??
              ds[0]?.serial ??
              ""),
        );
      } catch {
        if (active) setDevices([]);
      }
    };
    tick();
    const id = setInterval(tick, 2000);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, [open, phase]);

  // ── Load the device's apps when we reach the picker ────────────────────
  useEffect(() => {
    if (phase !== "app" || !serial) return;
    setPkgLoading(true);
    setPackages([]);
    setPkg("");
    invoke<DevicePackage[]>("list_device_packages", { serial })
      .then(setPackages)
      .catch(() => setPackages([]))
      .finally(() => setPkgLoading(false));
  }, [phase, serial]);

  // ── Count this phone's requests live, for the payoff screen ────────────
  useEffect(() => {
    if (phase !== "live" || !device) return;
    let un: UnlistenFn | undefined;
    listen<SessionEvent>("proxy-session", (e) => {
      if (
        e.payload.type === "start" &&
        e.payload.session.clientAddr === device.ip
      ) {
        setLiveCount((c) => c + 1);
      }
    }).then((fn) => (un = fn));
    return () => un?.();
  }, [phase, device]);

  const installAdb = useCallback(async () => {
    setInstalling(true);
    setToolsMsg("");
    const un = await listen<{ message: string }>(
      "android-tools-progress",
      (e) => setToolsMsg(e.payload.message),
    );
    try {
      await invoke("install_android_tools");
      const m = await invoke<string[]>("check_apk_tools");
      setMissing(m);
    } catch (e) {
      setToolsMsg(String(e));
    } finally {
      setInstalling(false);
      un();
    }
  }, []);

  const recheck = useCallback(() => {
    setMissing(null);
    invoke<string[]>("check_apk_tools")
      .then(setMissing)
      .catch(() => setMissing([]));
  }, []);

  const installPatch = useCallback(async () => {
    setInstallingPatch(true);
    setPatchMsg("");
    const un = await listen<{ message: string }>(
      "android-tools-progress",
      (e) => setPatchMsg(e.payload.message),
    );
    try {
      const summary = await invoke<string>("install_patch_tools");
      const m = await invoke<string[]>("check_apk_tools");
      setMissing(m);
      setPatchMsg(summary);
    } catch (e) {
      setPatchMsg(String(e));
    } finally {
      setInstallingPatch(false);
      un();
    }
  }, []);

  const filteredPkgs = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q
      ? packages.filter((p) => p.package.toLowerCase().includes(q))
      : packages;
  }, [packages, query]);

  // Finish onboarding: open the app (best-effort) and switch to the live view.
  // Shared by the clean-install path and the confirmed-replace path.
  const goLive = useCallback(
    async (tag: string) => {
      if (pkg) {
        setStage("Opening the app…");
        try {
          await invoke("launch_package", { serial, package: pkg });
        } catch {
          /* launch is best-effort — the capture is already live */
        }
      }
      const model = devices.find((d) => d.serial === serial)?.model || serial;
      setDevice({ serial, model, ip: tag, platform: "android" });
      setPhase("live");
      setPendingReplace(null);
      setStage("");
      setConnecting(false);
    },
    [pkg, serial, devices],
  );

  const startCapture = useCallback(async () => {
    if (!serial) return;
    setConnecting(true);
    setConnectErr("");
    setPendingReplace(null);
    let captureStarted = false;
    try {
      setStage("Identifying the phone…");
      let ip = "";
      try {
        ip = await invoke<string>("get_device_ip", { serial });
      } catch {
        /* Wi-Fi may be off — the tag falls back to the serial below */
      }
      const tag = ip || serial;

      // Route the phone through the proxy over the USB cable (adb reverse) — no
      // firewall or Wi-Fi to fight, and a dedicated listener tags its traffic.
      setStage("Linking the phone over USB…");
      await invoke("start_device_capture", { serial, tag });
      captureStarted = true;

      if (pkg && patchApp && !pairip) {
        setStage("Unpacking the app…");
        const path = await invoke<string>("pull_apk", { serial, package: pkg });
        setStage("Embedding the certificate…");
        const res = await invoke<PatchResult>("patch_apk", {
          opts: backendPatchOpts(path, patchOpts),
        });
        setStage("Reinstalling the app…");
        const install = await invoke<{ status: string; message: string }>(
          "install_patched_apk",
          { serial, apkPath: res.outputPath, package: pkg },
        );
        if (install.status === "needsReplace") {
          // Replacing wipes the app's data — pause and let the user decide. The
          // capture is already live, so we resume to "live" once they choose.
          setPendingReplace({ apkPath: res.outputPath, tag });
          setStage("");
          setConnecting(false);
          return;
        }
      }

      await goLive(tag);
    } catch (e) {
      setConnectErr(String(e));
      // Clean up capture if it was started but subsequent steps failed
      if (captureStarted) {
        invoke("stop_device_capture", { serial }).catch(() => {});
      }
    } finally {
      setConnecting(false);
    }
  }, [serial, pkg, patchApp, pairip, patchOpts, devices, goLive]);

  // User accepted the data-wiping reinstall: replace the app, then resume onboarding.
  const confirmReplace = useCallback(async () => {
    if (!pendingReplace) return;
    setConnecting(true);
    setConnectErr("");
    setStage("Replacing the app…");
    try {
      await invoke<string>("replace_patched_apk", {
        serial,
        apkPath: pendingReplace.apkPath,
        package: pkg,
      });
      setDataWiped(true);
      await goLive(pendingReplace.tag);
    } catch (e) {
      setConnectErr(String(e));
      setConnecting(false);
      setStage("");
    }
  }, [pendingReplace, serial, pkg, goLive]);

  // User declined: go live without patching. The app keeps its data but won't
  // trust our CA, so clear the patched marker to surface the "HTTPS is opaque" hint.
  const skipReplace = useCallback(async () => {
    if (!pendingReplace) return;
    const { tag } = pendingReplace;
    setPatchApp(false);
    await goLive(tag);
  }, [pendingReplace, goLive]);

  const finish = useCallback(() => {
    if (device) onConnected(device);
    onOpenChange(false);
  }, [device, onConnected, onOpenChange]);

  return (
    <Dialog open={open} onOpenChange={(o) => !busy && onOpenChange(o)}>
      <DialogContent
        // Inline width beats the base component's responsive `sm:max-w-lg`
        // (32rem), which otherwise squeezes the two-column layout and clips text.
        style={{ width: "min(48rem, 94vw)", maxWidth: "48rem" }}
        className="bg-bg-1 border-border p-0 flex flex-col gap-0 max-h-[88vh] overflow-hidden"
      >
        <style>{CSS}</style>

        <DialogHeader className="px-6 pt-6 pb-4 border-b border-border/60">
          <DialogTitle className="font-chakra text-text-0 text-xl flex items-center gap-2 tracking-wide">
            <Smartphone className="size-5" /> Add an Android phone
          </DialogTitle>
          <DialogDescription className="text-text-2 text-xs">
            Route a phone's traffic through PacketSniffer over USB, then watch
            its requests live. For apps and devices you own.
          </DialogDescription>
        </DialogHeader>

        <div className="grid grid-cols-1 md:grid-cols-[14.5rem_1fr] min-h-0 flex-1">
          {/* ── Spine: the computer ⟷ phone tether ─────────────────────── */}
          <Spine
            phaseIndex={phaseIndex}
            linkActive={linkActive}
            live={phase === "live"}
            deviceLabel={device?.model ?? authDevice?.model ?? "Your phone"}
          />

          {/* ── Step content ───────────────────────────────────────────── */}
          <div className="min-h-0 flex flex-col border-l border-border/60">
            <ScrollArea className="min-h-0 flex-1">
              <div className="px-6 py-5">
                {phase === "tools" && (
                  <ToolchainStep
                    missing={missing}
                    adbMissing={adbMissing}
                    patchToolsMissing={patchToolsMissing}
                    installing={installing}
                    toolsMsg={toolsMsg}
                    onInstall={installAdb}
                    onInstallPatch={installPatch}
                    installingPatch={installingPatch}
                    patchMsg={patchMsg}
                    onRecheck={recheck}
                  />
                )}
                {phase === "connect" && (
                  <ConnectStep
                    devices={devices}
                    serial={serial}
                    onPick={setSerial}
                    authDevice={authDevice}
                    pendingDevice={pendingDevice}
                  />
                )}
                {phase === "app" && (
                  <AppStep
                    pkgLoading={pkgLoading}
                    packages={filteredPkgs}
                    total={packages.length}
                    pkg={pkg}
                    onPick={setPkg}
                    query={query}
                    onQuery={setQuery}
                    patchApp={patchApp}
                    onPatchApp={setPatchApp}
                    patchOpts={patchOpts}
                    onPatchOpts={(p) =>
                      setPatchOpts((prev) => ({ ...prev, ...p }))
                    }
                    canPatch={canPatch}
                    pairip={pairip}
                    connecting={connecting}
                    stage={stage}
                    connectErr={connectErr}
                  />
                )}
                {phase === "app" && pendingReplace && (
                  <div className="mt-4 flex items-start gap-2 rounded-md border border-yellow-500/40 bg-yellow-500/10 px-3 py-3">
                    <TriangleAlert className="size-4 text-yellow-500 shrink-0 mt-0.5" />
                    <div className="space-y-2.5">
                      <p className="text-[11px] text-text-1 leading-relaxed">
                        <span className="font-medium">{pkg}</span> is already
                        installed and signed differently than our patched build, so
                        it can't be updated in place. Replacing it means
                        uninstalling the original first —{" "}
                        <span className="font-medium">
                          its data on the phone will be erased.
                        </span>{" "}
                        Or skip patching and still capture its traffic, just without
                        decrypting HTTPS.
                      </p>
                      <div className="flex items-center gap-2">
                        <Button
                          variant="destructive"
                          size="sm"
                          onClick={confirmReplace}
                          disabled={connecting}
                        >
                          {connecting ? <Spinner size={14} /> : null} Replace &amp;
                          erase data
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={skipReplace}
                          disabled={connecting}
                        >
                          Skip patching
                        </Button>
                      </div>
                    </div>
                  </div>
                )}
                {phase === "live" && device && (
                  <LiveStep
                    device={device}
                    count={liveCount}
                    patched={patchApp}
                    dataWiped={dataWiped}
                  />
                )}
              </div>
            </ScrollArea>

            {/* ── Footer ──────────────────────────────────────────────── */}
            <div className="border-t border-border/60 bg-bg-2/30 px-6 py-3 flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                {(phase === "connect" || phase === "app") &&
                  !busy &&
                  !pendingReplace && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() =>
                        setPhase(phase === "connect" ? "tools" : "connect")
                      }
                    >
                      <ChevronLeft className="size-3.5 mr-1" /> Back
                    </Button>
                  )}
              </div>

              <div className="flex items-center gap-2">
                {phase === "tools" &&
                  (adbMissing ? (
                    <Button
                      size="sm"
                      onClick={installAdb}
                      disabled={installing || missing === null}
                    >
                      {installing ? (
                        <Spinner size={14} />
                      ) : (
                        <Download className="size-3.5 mr-1" />
                      )}
                      {installing ? "Installing…" : "Install adb"}
                    </Button>
                  ) : (
                    <Button
                      size="sm"
                      onClick={() => setPhase("connect")}
                      disabled={missing === null || busy}
                    >
                      Continue
                    </Button>
                  ))}

                {phase === "connect" && (
                  <Button
                    size="sm"
                    onClick={() => setPhase("app")}
                    disabled={!authDevice}
                  >
                    Continue
                  </Button>
                )}

                {phase === "app" && !pendingReplace && (
                  <Button
                    size="sm"
                    onClick={startCapture}
                    disabled={
                      connecting || (patchApp && !patchOptsValid(patchOpts))
                    }
                  >
                    {connecting ? <Spinner size={14} /> : null}
                    {connecting ? "Connecting…" : "Start capturing"}
                  </Button>
                )}

                {phase === "live" && (
                  <Button size="sm" onClick={finish}>
                    Open inspector
                  </Button>
                )}
              </div>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Spine (left) ────────────────────────────────────────────────────────────

function Spine({
  phaseIndex,
  linkActive,
  live,
  deviceLabel,
}: {
  phaseIndex: number;
  linkActive: boolean;
  live: boolean;
  deviceLabel: string;
}) {
  return (
    <div className="relative bg-bg-0/60 spine-grain overflow-hidden px-5 py-5 flex flex-col">
      {/* All points — computer, the four stations, phone — share one evenly
          spaced column so the tether line threads dead-centre through every
          icon and no gap is bigger than another. */}
      <div className="relative flex flex-col flex-1 justify-between">
        {/* one continuous tether line: computer ↕ phone. The captured-traffic
            packet rides it bottom→top so it's never on an invisible segment.
            It sits behind the icons (lower z-index). */}
        <span className="spine-track">
          {linkActive && (
            <span
              className="packet"
              style={{ background: live ? LIVE : undefined }}
            />
          )}
        </span>

        {/* this computer */}
        <Endpoint
          icon={<Monitor className="size-3.5" />}
          label="This computer"
          active
        />

        {/* stations */}
        {STATIONS.map((s, i) => {
          const status =
            i < phaseIndex ? "done" : i === phaseIndex ? "active" : "pending";
          return (
            <div key={s.key} className="relative flex items-center gap-3">
              <span className="w-7 flex justify-center shrink-0">
                <span
                  className={`relative z-10 grid place-items-center size-6 rounded-full border transition-colors ${
                    status === "done"
                      ? "border-foreground bg-foreground text-background"
                      : status === "active"
                        ? "border-foreground bg-bg-0 text-text-0 station-active"
                        : "border-border bg-bg-0 text-muted-foreground"
                  }`}
                >
                  {status === "done" ? (
                    <Check className="size-3.5" />
                  ) : status === "active" ? (
                    <span className="size-1.5 rounded-full bg-foreground station-blink" />
                  ) : (
                    <span className="text-[9px] font-mono">{s.code}</span>
                  )}
                </span>
              </span>
              <div className="min-w-0">
                <div className="text-[10px] font-mono tracking-wider text-text-2">
                  {s.code}
                </div>
                <div
                  className={`text-xs leading-tight ${
                    status === "active"
                      ? "text-text-0 font-medium"
                      : status === "pending"
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

        {/* the phone */}
        <Endpoint
          icon={<Smartphone className="size-3.5" />}
          label={deviceLabel}
          active={linkActive}
          live={live}
        />
      </div>
    </div>
  );
}

function Endpoint({
  icon,
  label,
  active,
  live,
}: {
  icon: React.ReactNode;
  label: string;
  active?: boolean;
  live?: boolean;
}) {
  return (
    <div className="flex items-center gap-3 min-w-0">
      <span className="w-7 flex justify-center shrink-0">
        <span
          className={`relative z-10 grid place-items-center size-7 rounded-md border bg-bg-0 ${
            active
              ? "border-foreground/60 text-text-0"
              : "border-border text-muted-foreground"
          }`}
          style={live ? { borderColor: LIVE, color: LIVE } : undefined}
        >
          {icon}
        </span>
      </span>
      <span
        className={`text-[11px] truncate ${active ? "text-text-1" : "text-muted-foreground"}`}
      >
        {label}
      </span>
    </div>
  );
}

// ─── Step 01 · Toolchain ─────────────────────────────────────────────────────

function ToolchainStep({
  missing,
  adbMissing,
  patchToolsMissing,
  installing,
  toolsMsg,
  onInstall,
  onInstallPatch,
  installingPatch,
  patchMsg,
  onRecheck,
}: {
  missing: string[] | null;
  adbMissing: boolean;
  patchToolsMissing: string[];
  installing: boolean;
  toolsMsg: string;
  onInstall: () => void;
  onInstallPatch: () => void;
  installingPatch: boolean;
  patchMsg: string;
  onRecheck: () => void;
}) {
  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between gap-3">
        <StepHeading
          title="Toolchain"
          sub="PacketSniffer talks to your phone with adb. That's the only thing you need to watch traffic — the rest is for the optional app-patching step."
        />
        {missing !== null && (
          <button
            onClick={onRecheck}
            className="shrink-0 inline-flex items-center gap-1.5 text-[11px] text-muted-foreground hover:text-text-1 transition-colors mt-0.5"
            title="Re-scan for installed tools"
          >
            <RefreshCw className="size-3" /> Re-check
          </button>
        )}
      </div>

      {missing === null ? (
        <div className="flex items-center gap-2 text-xs text-muted-foreground py-6">
          <Spinner size={14} /> Checking what's installed…
        </div>
      ) : (
        <>
          {/* Essential */}
          <div>
            <SectionLabel>Essential</SectionLabel>
            <div className="rounded-md border border-border/60 overflow-hidden">
              <ToolRow
                name="adb"
                role="Connects to your phone over USB"
                present={!adbMissing}
              />
            </div>
            {adbMissing && (
              <div className="mt-2 flex items-start gap-2 rounded-md border border-border bg-bg-2/40 px-3 py-2">
                <Download className="size-4 text-text-1 shrink-0 mt-0.5" />
                <div className="min-w-0 flex-1">
                  <p className="text-[11px] text-text-1 leading-relaxed">
                    adb isn't on this computer. Use{" "}
                    <span className="text-text-0 font-medium">Install adb</span>{" "}
                    below — we'll fetch Google's platform-tools, no setup
                    needed.
                  </p>
                  {installing && (
                    <p className="text-[10px] font-mono text-muted-foreground mt-1.5 break-all flex items-center gap-1.5">
                      <Spinner size={11} /> {toolsMsg || "Working…"}
                    </p>
                  )}
                  {!installing && toolsMsg && (
                    <p className="text-[10px] font-mono text-destructive mt-1.5 break-all">
                      {toolsMsg}
                    </p>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Patch tools */}
          <div>
            <SectionLabel>For patching apps · optional</SectionLabel>
            <div className="rounded-md border border-border/60 overflow-hidden">
              {PATCH_TOOLS.map((t) => (
                <ToolRow
                  key={t.bin}
                  name={t.bin}
                  role={t.role}
                  present={!patchToolsMissing.includes(t.bin)}
                />
              ))}
            </div>
            {patchToolsMissing.length > 0 && (
              <div className="mt-2 space-y-2">
                <p className="text-[11px] text-muted-foreground leading-relaxed">
                  Only needed to patch apps that pin their certificate — you can
                  connect and watch normal traffic without them.
                </p>
                {installingPatch ? (
                  <p className="text-[10px] font-mono text-muted-foreground flex items-center gap-1.5">
                    <Spinner size={11} /> {patchMsg || "Installing…"}
                  </p>
                ) : (
                  <>
                    <button
                      onClick={onInstallPatch}
                      className="inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-2/40 px-2.5 py-1 text-[11px] font-medium text-text-1 hover:text-text-0 hover:bg-bg-2/70 transition-colors"
                    >
                      <Download className="size-3.5" /> Install patch tools
                    </button>
                    {patchMsg && (
                      <p className="text-[10px] font-mono text-text-2 leading-relaxed wrap-break-word">
                        {patchMsg}
                      </p>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function ToolRow({
  name,
  role,
  present,
}: {
  name: string;
  role: string;
  present: boolean;
}) {
  return (
    <div className="flex items-center gap-3 px-3 py-2.5 bg-bg-1 border-b border-border/40 last:border-b-0">
      <span
        className={`grid place-items-center size-5 rounded-full shrink-0 ${
          present
            ? "bg-foreground text-background"
            : "border border-border text-muted-foreground"
        }`}
      >
        {present ? <Check className="size-3" /> : <X className="size-3" />}
      </span>
      <span className="font-mono text-[12px] text-text-0 w-24 shrink-0">
        {name}
      </span>
      <span className="text-[11px] text-muted-foreground truncate">{role}</span>
      <span
        className={`ml-auto text-[10px] font-mono uppercase tracking-wider shrink-0 ${
          present ? "text-text-2" : "text-muted-foreground"
        }`}
      >
        {present ? "ready" : "missing"}
      </span>
    </div>
  );
}

// ─── Step 02 · Connect ───────────────────────────────────────────────────────

function ConnectStep({
  devices,
  serial,
  onPick,
  authDevice,
  pendingDevice,
}: {
  devices: AdbDevice[];
  serial: string;
  onPick: (s: string) => void;
  authDevice?: AdbDevice;
  pendingDevice?: AdbDevice;
}) {
  const steps = [
    "Open Settings ▸ About phone and tap Build number seven times to unlock Developer options.",
    "In Settings ▸ System ▸ Developer options, turn on USB debugging.",
    "Plug the phone into this computer with a USB cable.",
    "On the phone, tap Allow when it asks to trust this computer.",
  ];

  return (
    <div className="space-y-5">
      <StepHeading
        title="Connect your phone"
        sub="A USB cable lets PacketSniffer set things up for you. Walk through these on the phone:"
      />

      <ol className="space-y-2.5">
        {steps.map((s, i) => (
          <li key={i} className="flex items-start gap-3">
            <span className="grid place-items-center size-5 rounded-full border border-border text-[10px] font-mono text-text-2 shrink-0 mt-px">
              {i + 1}
            </span>
            <span className="text-[12px] text-text-1 leading-relaxed">{s}</span>
          </li>
        ))}
      </ol>

      {/* Live detection */}
      {authDevice ? (
        <DeviceCard device={authDevice} state="ready" />
      ) : pendingDevice ? (
        <DeviceCard device={pendingDevice} state="pending" />
      ) : (
        <div className="flex items-center gap-3 rounded-md border border-dashed border-border bg-bg-2/20 px-4 py-4">
          <span className="relative grid place-items-center size-6 shrink-0">
            <span className="absolute inset-0 rounded-full border border-border scan-ring" />
            <Usb className="size-3.5 text-muted-foreground" />
          </span>
          <div className="min-w-0">
            <div className="text-[12px] text-text-1">
              Waiting for your phone…
            </div>
            <div className="text-[11px] text-muted-foreground">
              It'll appear here the moment it's plugged in and trusted.
            </div>
          </div>
        </div>
      )}

      {/* >1 device — let them choose */}
      {devices.length > 1 && (
        <div className="space-y-1.5">
          <SectionLabel>{devices.length} devices found</SectionLabel>
          <div className="space-y-1">
            {devices.map((d) => (
              <button
                key={d.serial}
                onClick={() => onPick(d.serial)}
                className={`flex items-center gap-2 w-full px-3 py-2 rounded-md border text-left transition-colors ${
                  d.serial === serial
                    ? "border-foreground/50 bg-bg-2/50"
                    : "border-border hover:bg-bg-2/30"
                }`}
              >
                <Smartphone className="size-3.5 text-muted-foreground shrink-0" />
                <span className="text-[12px] text-text-0 truncate">
                  {d.model || d.serial}
                </span>
                <span className="ml-auto text-[10px] font-mono text-muted-foreground">
                  {d.state}
                </span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function DeviceCard({
  device,
  state,
}: {
  device: AdbDevice;
  state: "ready" | "pending";
}) {
  const ready = state === "ready";
  return (
    <div
      className="flex items-center gap-3 rounded-md border px-4 py-3"
      style={{
        borderColor: ready ? `${LIVE}66` : undefined,
        background: ready ? `${LIVE}10` : undefined,
      }}
    >
      <span
        className="grid place-items-center size-8 rounded-md border shrink-0"
        style={{
          borderColor: ready ? `${LIVE}66` : "var(--border)",
          color: ready ? LIVE : undefined,
        }}
      >
        <Smartphone className="size-4" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="text-[13px] text-text-0 font-medium truncate">
          {device.model || "Android device"}
        </div>
        <div className="text-[11px] font-mono text-muted-foreground truncate">
          {device.serial}
        </div>
      </div>
      {ready ? (
        <span
          className="flex items-center gap-1.5 text-[11px] font-medium"
          style={{ color: LIVE }}
        >
          <Check className="size-3.5" /> Connected
        </span>
      ) : (
        <span className="flex items-center gap-1.5 text-[11px] text-text-2">
          <TriangleAlert className="size-3.5" /> Tap Allow on phone
        </span>
      )}
    </div>
  );
}

// ─── Step 03 · Choose app ────────────────────────────────────────────────────

function AppStep({
  pkgLoading,
  packages,
  total,
  pkg,
  onPick,
  query,
  onQuery,
  patchApp,
  onPatchApp,
  patchOpts,
  onPatchOpts,
  canPatch,
  pairip,
  connecting,
  stage,
  connectErr,
}: {
  pkgLoading: boolean;
  packages: DevicePackage[];
  total: number;
  pkg: string;
  onPick: (p: string) => void;
  query: string;
  onQuery: (q: string) => void;
  patchApp: boolean;
  onPatchApp: (v: boolean) => void;
  patchOpts: PatchOpts;
  onPatchOpts: (patch: Partial<PatchOpts>) => void;
  canPatch: boolean;
  pairip: boolean;
  connecting: boolean;
  stage: string;
  connectErr: string;
}) {
  if (connecting) {
    return (
      <div className="space-y-5">
        <StepHeading
          title="Connecting…"
          sub="Setting the phone up to route through PacketSniffer."
        />
        <div className="flex items-center gap-3 rounded-md border border-border bg-bg-2/30 px-4 py-4">
          <Spinner size={16} />
          <span className="text-[12px] text-text-1">{stage}</span>
        </div>
        <p className="text-[11px] text-muted-foreground">
          Keep the phone plugged in — this can take a moment if the app is being
          patched.
        </p>
      </div>
    );
  }

  const patchEnabled = canPatch && !!pkg && !pairip;

  return (
    <div className="space-y-5">
      <StepHeading
        title="Choose an app — optional"
        sub="Leave this empty to capture everything the phone sends — no reinstall, nothing touched. Pick an app only to patch it (for apps that pin their certificate)."
      />

      <div className="space-y-2">
        <div className="flex items-center gap-1.5 bg-muted/50 border border-border rounded-md px-2 h-8">
          <Search className="size-3.5 text-muted-foreground shrink-0" />
          <input
            value={query}
            onChange={(e) => onQuery(e.target.value)}
            placeholder={total ? `Search ${total} apps` : "Search apps"}
            spellCheck={false}
            className="bg-transparent text-[12px] text-foreground placeholder:text-muted-foreground outline-none flex-1 min-w-0"
          />
        </div>

        <div className="rounded-md border border-border/60 max-h-56 overflow-y-auto">
          {pkgLoading ? (
            <div className="flex items-center gap-2 text-[11px] text-muted-foreground px-3 py-4">
              <Spinner size={13} /> Reading the phone's apps…
            </div>
          ) : packages.length === 0 ? (
            <div className="text-[11px] text-muted-foreground px-3 py-4">
              No matching apps.
            </div>
          ) : (
            packages.map((p) => (
              <button
                key={p.package}
                onClick={() => onPick(pkg === p.package ? "" : p.package)}
                className={`flex items-center gap-2 w-full px-3 py-2 text-left border-b border-border/40 last:border-b-0 transition-colors ${
                  pkg === p.package ? "bg-bg-2/60" : "hover:bg-bg-2/30"
                }`}
              >
                <span
                  className={`grid place-items-center size-4 rounded-full border shrink-0 ${
                    pkg === p.package
                      ? "bg-foreground border-foreground text-background"
                      : "border-border"
                  }`}
                >
                  {pkg === p.package && <Check className="size-2.5" />}
                </span>
                <span className="font-mono text-[12px] text-text-0 truncate flex-1">
                  {p.package}
                </span>
                {pkg === p.package && pairip && <PairipChip />}
              </button>
            ))
          )}
        </div>
      </div>

      {!pkg && (
        <p className="text-[11px] text-muted-foreground leading-relaxed">
          No app selected — PacketSniffer captures every app that respects the
          phone's proxy (all HTTP; HTTPS where the certificate is already
          trusted). Nothing is reinstalled.
        </p>
      )}

      {pkg && pairip && <PairipBanner />}

      {/* Advanced: patch the selected app */}
      <label
        className={`flex items-start gap-3 rounded-md border px-3 py-2.5 ${
          patchEnabled
            ? "border-border/60 bg-bg-1 cursor-pointer"
            : "border-border/40 bg-bg-2/20"
        }`}
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5 text-sm text-text-0">
            <ShieldCheck className="size-3.5" /> Patch this app to decrypt its
            HTTPS
          </div>
          <div className="text-[11px] text-muted-foreground leading-snug mt-0.5">
            {pairip
              ? "This app is PAIRIP-protected — patching can't work. You can still capture it, just without decrypting its HTTPS."
              : !pkg
                ? "Select an app above to enable this. Only needed for apps that pin their certificate."
                : !canPatch
                  ? "Needs the patch toolchain (step 1)."
                  : "Repackages the app to trust PacketSniffer. Reinstalls it once, which clears its data — Android won't update a re-signed app. Leave off to keep the app and its data untouched."}
          </div>
        </div>
        <Switch
          checked={patchApp && patchEnabled}
          onChange={(v) => patchEnabled && onPatchApp(v)}
        />
      </label>

      {/* Advanced patch knobs — the same set the Tools › Patch APK dialog
          exposes, revealed once patching is on. */}
      {patchApp && patchEnabled && (
        <div className="space-y-2">
          <SectionLabel>Patch options</SectionLabel>
          <PatchOptions opts={patchOpts} onChange={onPatchOpts} />
          {!patchOpts.embedCa && !patchOpts.trustUser && (
            <p className="text-[11px] text-destructive">
              Enable at least one trust anchor (embed CA or user store).
            </p>
          )}
        </div>
      )}

      {connectErr && (
        <div className="flex items-start gap-2 text-[11px] text-destructive">
          <X className="size-3.5 shrink-0 mt-0.5" />
          <span className="font-mono break-all">{connectErr}</span>
        </div>
      )}
    </div>
  );
}

// ─── Step 04 · Live ──────────────────────────────────────────────────────────

function LiveStep({
  device,
  count,
  patched,
  dataWiped,
}: {
  device: ConnectedDevice;
  count: number;
  patched: boolean;
  dataWiped: boolean;
}) {
  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2.5">
        <span className="relative grid place-items-center size-3">
          <span
            className="absolute inset-0 rounded-full live-pulse"
            style={{ background: LIVE }}
          />
          <span className="size-2 rounded-full" style={{ background: LIVE }} />
        </span>
        <span
          className="font-chakra text-lg tracking-[0.18em] uppercase"
          style={{ color: LIVE }}
        >
          Live
        </span>
      </div>

      <div>
        <div className="text-text-0 text-[15px] font-medium flex items-center gap-2">
          <Smartphone className="size-4" /> Watching {device.model}
        </div>
        <div className="flex items-center gap-2 mt-1 text-[11px] font-mono text-muted-foreground">
          <Wifi className="size-3" /> {device.ip}
        </div>
      </div>

      <div className="rounded-md border border-border/60 bg-bg-2/30 px-4 py-4 flex items-center gap-3">
        <Activity className="size-5 text-text-1 shrink-0" />
        <div>
          <div className="text-2xl font-chakra tabular-nums text-text-0 leading-none">
            {count}
          </div>
          <div className="text-[11px] text-muted-foreground mt-1">
            request{count === 1 ? "" : "s"} captured from this phone so far
          </div>
        </div>
      </div>

      <p className="text-[12px] text-text-1 leading-relaxed">
        The phone now routes through PacketSniffer. Use the app and its requests
        stream into the inspector. Open the inspector to watch them — it's
        filtered to this device under{" "}
        <span className="text-text-0 font-medium">Devices</span> in the sidebar.
      </p>

      {dataWiped && (
        <div className="flex items-start gap-2 rounded-md border border-yellow-500/40 bg-yellow-500/10 px-3 py-2">
          <TriangleAlert className="size-4 text-yellow-500 shrink-0 mt-0.5" />
          <p className="text-[11px] text-text-1 leading-relaxed">
            The patched app was signed differently than the version already on the
            phone, so the original had to be uninstalled and replaced —{" "}
            <span className="font-medium">its existing data was erased.</span>
          </p>
        </div>
      )}

      {!patched && (
        <p className="text-[11px] text-muted-foreground leading-relaxed">
          Seeing HTTPS lines with no detail? That app doesn't trust our
          certificate. Re-add it and turn on{" "}
          <span className="text-text-1">
            Patch this app to decrypt its HTTPS
          </span>
          .
        </p>
      )}
    </div>
  );
}

// ─── Shared bits ─────────────────────────────────────────────────────────────

function StepHeading({ title, sub }: { title: string; sub: string }) {
  return (
    <div>
      <h3 className="font-chakra text-text-0 text-base tracking-wide">
        {title}
      </h3>
      <p className="text-[12px] text-muted-foreground leading-relaxed mt-1">
        {sub}
      </p>
    </div>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-[10px] uppercase tracking-[0.18em] text-muted-foreground font-mono mb-1.5">
      {children}
    </div>
  );
}

const CSS = `
.spine-grain {
  background-image: repeating-linear-gradient(
    0deg,
    color-mix(in oklch, var(--foreground) 3%, transparent) 0px,
    color-mix(in oklch, var(--foreground) 3%, transparent) 1px,
    transparent 1px,
    transparent 3px
  );
}
.station-active {
  box-shadow: 0 0 0 0 color-mix(in oklch, var(--foreground) 45%, transparent);
  animation: stationGlow 1.4s ease-out infinite;
}
@keyframes stationGlow {
  0%   { box-shadow: 0 0 0 0 color-mix(in oklch, var(--foreground) 45%, transparent); }
  70%  { box-shadow: 0 0 0 7px color-mix(in oklch, var(--foreground) 0%, transparent); }
  100% { box-shadow: 0 0 0 0 color-mix(in oklch, var(--foreground) 0%, transparent); }
}
.station-blink { animation: stationBlink 1s steps(1) infinite; }
@keyframes stationBlink { 0%, 50% { opacity: 1; } 50.01%, 100% { opacity: 0.25; } }
/* continuous tether line — threads the centre (x=14px) of every icon column,
   computer icon centre down to phone icon centre. Sits behind the icons. */
.spine-track {
  position: absolute;
  left: 13.5px;
  top: 14px;
  bottom: 14px;
  width: 1px;
  background: var(--border);
  z-index: 0;
}
/* travelling packet: a short line segment the width of the track that rides it
   phone → computer (captured traffic in). z-index stays below the icons (z-10)
   so it passes behind them. */
.packet {
  position: absolute;
  left: 0;
  width: 1px;
  height: 16px;
  border-radius: 1px;
  background: var(--foreground);
  box-shadow: 0 0 8px 1px color-mix(in oklch, var(--foreground) 60%, transparent);
  animation: packetTravel 2.4s linear infinite;
  z-index: 1;
}
@keyframes packetTravel {
  0%   { top: 100%; opacity: 0; }
  12%  { opacity: 1; }
  88%  { opacity: 1; }
  100% { top: 0%; opacity: 0; }
}
.scan-ring { animation: scanRing 1.6s ease-out infinite; }
@keyframes scanRing {
  0%   { transform: scale(0.7); opacity: 0.9; }
  100% { transform: scale(1.6); opacity: 0; }
}
.live-pulse { animation: livePulse 1.6s ease-out infinite; }
@keyframes livePulse {
  0%   { transform: scale(1); opacity: 0.5; }
  100% { transform: scale(2.6); opacity: 0; }
}
@media (prefers-reduced-motion: reduce) {
  .packet, .station-active, .station-blink, .scan-ring, .live-pulse { animation: none; }
  .packet { display: none; }
}
`;
