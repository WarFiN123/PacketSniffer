import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Check,
  Copy,
  RefreshCw,
} from "lucide-react";
import Spinner from "./Spinner";

interface CaInstallDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/** Mirrors `CaInstallResult` in `src-tauri/src/cert_store.rs`. */
interface CaInstallResult {
  message: string;
  certPath: string;
  warnings: string[];
  needsBrowserRestart: boolean;
}

type InstallState = "prompt" | "installing" | "success" | "error";

/** Path of the CA on disk, so a manual install is always one copy away. */
function CertPath({ path }: { path: string }) {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const id = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(id);
  }, [copied]);

  if (!path) return null;

  return (
    <div className="flex items-center gap-2 rounded-md border border-border bg-muted/30 p-2">
      <code className="flex-1 min-w-0 truncate font-mono text-[11px] text-text-1">
        {path}
      </code>
      <Button
        variant="ghost"
        size="xs"
        className="shrink-0"
        aria-label="Copy certificate path"
        onClick={() => {
          navigator.clipboard.writeText(path).then(
            () => setCopied(true),
            () => {},
          );
        }}
      >
        {copied ? (
          <Check className="size-3.5 text-green-500" />
        ) : (
          <Copy className="size-3.5" />
        )}
      </Button>
    </div>
  );
}

export default function CaInstallDialog({
  open,
  onOpenChange,
}: CaInstallDialogProps) {
  const [state, setState] = useState<InstallState>("prompt");
  const [result, setResult] = useState<CaInstallResult | null>(null);
  const [error, setError] = useState("");
  const [certPath, setCertPath] = useState("");

  // Fetched up front so the manual-install path is available even when the
  // privileged install is refused (or the platform has no automated route).
  useEffect(() => {
    if (!open || certPath) return;
    invoke<string>("get_ca_cert_path")
      .then(setCertPath)
      .catch(() => {});
  }, [open, certPath]);

  const handleInstall = useCallback(async () => {
    setState("installing");
    try {
      const res = await invoke<CaInstallResult>("install_ca_certificate");
      setResult(res);
      if (res.certPath) setCertPath(res.certPath);
      setState("success");
    } catch (err) {
      setError(String(err));
      setState("error");
    }
  }, []);

  const handleClose = (next: boolean) => {
    if (!next) {
      // Reset after the close animation so the dialog doesn't flicker.
      setTimeout(() => {
        setState("prompt");
        setResult(null);
        setError("");
      }, 200);
    }
    onOpenChange(next);
  };

  const title =
    state === "success"
      ? "Certificate Installed"
      : state === "error"
        ? "Installation Failed"
        : "CA Certificate";

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="bg-bg-1 border-border max-w-md p-6 overflow-hidden flex flex-col gap-5">
        <DialogHeader>
          <DialogTitle className="font-chakra text-text-0 text-lg flex items-center gap-2">
            {state === "success" ? (
              <ShieldCheck className="size-5 text-green-500" />
            ) : state === "error" ? (
              <ShieldAlert className="size-5 text-destructive" />
            ) : (
              <AlertTriangle className="size-5 text-yellow-500" />
            )}
            {title}
          </DialogTitle>
          <DialogDescription className="text-text-2 text-sm sr-only">
            Install the PacketSniffer root CA certificate
          </DialogDescription>
        </DialogHeader>

        {state === "prompt" && (
          <div className="space-y-4">
            <p className="text-sm text-text-1 leading-relaxed">
              The PacketSniffer CA certificate is not trusted yet. HTTPS
              interception needs it installed, and browsers will refuse every
              secure page until it is.
            </p>
            <p className="text-xs text-muted-foreground">
              This requires administrator/root privileges. The certificate is
              only used locally for traffic inspection.
            </p>
            <CertPath path={certPath} />
            <div className="flex justify-end gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleClose(false)}
              >
                Skip
              </Button>
              <Button size="sm" onClick={handleInstall}>
                Install Certificate
              </Button>
            </div>
          </div>
        )}

        {state === "installing" && (
          <div className="flex flex-col items-center gap-3 py-4">
            <Spinner size={28} />
            <p className="text-sm text-text-1">Installing certificate...</p>
            <p className="text-xs text-muted-foreground text-center">
              Please follow any system prompts that appear.
            </p>
          </div>
        )}

        {state === "success" && result && (
          <div className="space-y-4">
            <p className="text-sm text-text-1 leading-relaxed">
              {result.message}
            </p>

            {result.needsBrowserRestart && (
              <div className="flex items-start gap-2 rounded-md border border-yellow-500/20 bg-yellow-500/10 p-3">
                <RefreshCw className="size-4 shrink-0 text-yellow-500 mt-px" />
                <p className="text-xs text-text-1 leading-relaxed">
                  Fully quit and reopen your browsers. Firefox and Chrome only
                  read trusted certificates at startup, so an already-running
                  window will keep showing security errors.
                </p>
              </div>
            )}

            {result.warnings.length > 0 && (
              <ul className="space-y-2">
                {result.warnings.map((warning) => (
                  <li
                    key={warning}
                    className="flex items-start gap-2 text-xs text-muted-foreground leading-relaxed"
                  >
                    <AlertTriangle className="size-3.5 shrink-0 text-yellow-500 mt-0.5" />
                    <span>{warning}</span>
                  </li>
                ))}
              </ul>
            )}

            <CertPath path={certPath} />

            <div className="flex justify-end">
              <Button size="sm" onClick={() => handleClose(false)}>
                Done
              </Button>
            </div>
          </div>
        )}

        {state === "error" && (
          <div className="space-y-4">
            <p className="text-sm text-destructive leading-relaxed whitespace-pre-line">
              {error}
            </p>
            <p className="text-xs text-muted-foreground">
              You can also install this file into your system trust store
              manually:
            </p>
            <CertPath path={certPath} />
            <div className="flex justify-end gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleClose(false)}
              >
                Close
              </Button>
              <Button size="sm" onClick={handleInstall}>
                Retry
              </Button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
