import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { Theme } from "@/hooks/useTheme";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Check,
  ShieldCheck,
  Waypoints,
  SunMoon,
  HardDrive,
  Trash2,
} from "lucide-react";
import Spinner from "./Spinner";
import {
  InputGroup,
  InputGroupAddon,
  InputGroupInput,
} from "./ui/input-group";

interface PreferencesDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  theme: Theme;
  onThemeChange: (theme: Theme) => void;
  onPortChange?: (port: number) => void;
}

interface WorkspaceInfo {
  bytes: number;
  files: number;
}

/** Compact human byte size — the APK workspace can hold hundreds of MB. */
function formatBytes(n: number): string {
  if (n <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  const val = n / 1024 ** i;
  return `${val >= 100 || i === 0 ? Math.round(val) : val.toFixed(1)} ${units[i]}`;
}

/** A labeled divider: mono eyebrow + icon, then a hairline filling the row. The
 *  recurring structural motif of the app's technical/terminal identity. */
function SectionHeader({
  icon,
  children,
}: {
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-center gap-2.5">
      <span className="flex items-center gap-1.5 text-[10px] font-mono font-semibold uppercase tracking-[0.18em] text-muted-foreground">
        {icon}
        {children}
      </span>
      <span className="h-px flex-1 bg-border/60" />
    </div>
  );
}

export default function PreferencesDialog({
  open,
  onOpenChange,
  theme,
  onThemeChange,
  onPortChange,
}: PreferencesDialogProps) {
  const [caStatus, setCaStatus] = useState<string | null>(null);
  const [installingCa, setInstallingCa] = useState(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [port, setPort] = useState("8080");
  const [portSaved, setPortSaved] = useState(false);
  const [portError, setPortError] = useState<string | null>(null);

  const [work, setWork] = useState<WorkspaceInfo | null>(null);
  const [clearing, setClearing] = useState(false);
  const [clearedMsg, setClearedMsg] = useState<string | null>(null);

  const refreshWork = useCallback(() => {
    invoke<WorkspaceInfo>("apk_work_info")
      .then(setWork)
      .catch(() => setWork(null));
  }, []);

  useEffect(() => {
    if (open) {
      invoke<string>("get_proxy_status")
        .then((status) => {
          const match = status.match(/port (\d+)/);
          if (match) {
            setPort(match[1]);
          }
        })
        .catch(() => {});
      setCaStatus(null);
      setPortSaved(false);
      setPortError(null);
      setClearedMsg(null);
      refreshWork();
    }
  }, [open, refreshWork]);

  const handleReinstallCA = async () => {
    setInstallingCa(true);
    setCaStatus("Installing...");
    try {
      const result = await invoke<string>("install_ca_certificate");
      setCaStatus(result);
    } catch (e) {
      setCaStatus(`Error: ${e}`);
    } finally {
      setInstallingCa(false);
    }
  };

  const handleSavePort = async () => {
    setLoading(true);
    setPortSaved(false);
    setPortError(null);
    try {
      const parsedPort = parseInt(port, 10);
      if (isNaN(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
        setPortError("Invalid port number (1–65535)");
        return;
      }
      await invoke("set_proxy_port", { port: parsedPort });
      onPortChange?.(parsedPort);
      setPortSaved(true);
      setTimeout(() => setPortSaved(false), 2000);
    } catch (e) {
      setPortError(`Port change failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setLoading(false);
    }
  };

  const handleClearWork = async () => {
    setClearing(true);
    setClearedMsg(null);
    try {
      const reclaimed = await invoke<WorkspaceInfo>("clear_apk_work");
      setWork({ bytes: 0, files: 0 });
      setClearedMsg(
        reclaimed.files > 0 ? `Freed ${formatBytes(reclaimed.bytes)}` : "Already empty",
      );
    } catch (e) {
      setClearedMsg(`Error: ${e}`);
    } finally {
      setClearing(false);
    }
  };

  const workEmpty = !work || work.files === 0;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-bg-1 border-border max-w-sm p-6 overflow-hidden flex flex-col gap-6">
        <DialogHeader className="space-y-1">
          <DialogTitle className="font-chakra text-text-0 text-xl tracking-wide">
            Preferences
          </DialogTitle>
          <DialogDescription className="text-text-2 text-xs">
            Proxy, appearance, and the Android patching workspace.
          </DialogDescription>
        </DialogHeader>

        {/* Network */}
        <div className="space-y-3">
          <SectionHeader icon={<Waypoints className="size-3" />}>
            Network
          </SectionHeader>
          <div className="flex items-center justify-between gap-3">
            <Label className="text-sm text-text-1">Proxy listening port</Label>
            <InputGroup className="rounded-full w-28">
              <InputGroupInput
                value={port}
                onChange={(e) => setPort(e.target.value)}
                className="text-sm [appearance:textfield] [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:appearance-none"
                type="number"
                min="1"
                max="65535"
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleSavePort();
                }}
              />
              <InputGroupAddon
                align={"inline-end"}
                onClick={handleSavePort}
                className={loading ? "cursor-wait" : "cursor-pointer"}
              >
                {loading ? (
                  <Spinner />
                ) : portSaved ? (
                  <Check className="size-4 text-text-0" />
                ) : (
                  <Check className="size-4 text-muted-foreground hover:text-text-0" />
                )}
              </InputGroupAddon>
            </InputGroup>
          </div>
          {portError && <p className="text-xs text-destructive">{portError}</p>}
        </div>

        {/* Appearance */}
        <div className="space-y-3">
          <SectionHeader icon={<SunMoon className="size-3" />}>
            Appearance
          </SectionHeader>
          <div className="flex items-center justify-between gap-3">
            <Label className="text-sm text-text-1">Theme</Label>
            <Select
              value={theme}
              onValueChange={(val) => onThemeChange(val as Theme)}
            >
              <SelectTrigger className="w-30 h-8 text-sm">
                <SelectValue placeholder="Theme" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="light">Light</SelectItem>
                <SelectItem value="dark">Dark</SelectItem>
                <SelectItem value="system">System</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        {/* Certificate */}
        <div className="space-y-3">
          <SectionHeader icon={<ShieldCheck className="size-3" />}>
            Certificate
          </SectionHeader>
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0">
                <div className="text-sm text-text-1">Root CA certificate</div>
                <div className="text-[11px] text-muted-foreground leading-snug">
                  Reinstall in the OS trust store if HTTPS won't decrypt.
                </div>
              </div>
              <Button
                variant="outline"
                size="xs"
                onClick={handleReinstallCA}
                disabled={installingCa}
              >
                {installingCa && <Spinner className="mr-2" size={14} />}
                {installingCa ? "Installing" : "Reinstall"}
              </Button>
            </div>
            {caStatus && !installingCa && (
              <p
                className={`text-xs ${caStatus.startsWith("Error") ? "text-destructive" : "text-muted-foreground"}`}
              >
                {caStatus}
              </p>
            )}
          </div>
        </div>

        {/* Android workspace */}
        <div className="space-y-3">
          <SectionHeader icon={<HardDrive className="size-3" />}>
            Android workspace
          </SectionHeader>
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0">
                <div className="text-sm text-text-1">Patch scratch files</div>
                <div className="text-[11px] text-muted-foreground leading-snug">
                  Decoded APKs, pulled packages & patched builds.
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <span className="font-mono text-[11px] tabular-nums text-muted-foreground">
                  {work ? formatBytes(work.bytes) : "—"}
                </span>
                <Button
                  variant="outline"
                  size="xs"
                  onClick={handleClearWork}
                  disabled={clearing || workEmpty}
                >
                  {clearing ? (
                    <Spinner className="mr-1.5" size={13} />
                  ) : (
                    <Trash2 className="size-3.5 mr-1.5" />
                  )}
                  {clearing ? "Clearing" : "Clear"}
                </Button>
              </div>
            </div>
            {(work && work.files > 0) || clearedMsg ? (
              <p
                className={`text-[11px] ${clearedMsg?.startsWith("Error") ? "text-destructive" : "text-muted-foreground"}`}
              >
                {clearedMsg
                  ? clearedMsg
                  : `${work!.files} file${work!.files === 1 ? "" : "s"} · cached for faster re-patching`}
              </p>
            ) : null}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
