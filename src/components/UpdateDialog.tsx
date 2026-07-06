import { useState, useEffect } from "react";
import { getVersion } from "@tauri-apps/api/app";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import Spinner from "@/components/Spinner";
import Markdown from "@/components/ui/markdown";
import {
  ArrowRight,
  Check,
  Download,
  RotateCw,
  TriangleAlert,
} from "lucide-react";

interface UpdateDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

type Status =
  | "idle"
  | "checking"
  | "available"
  | "uptodate"
  | "error"
  | "downloading";

export default function UpdateDialog({
  open,
  onOpenChange,
}: UpdateDialogProps) {
  const [status, setStatus] = useState<Status>("idle");
  const [current, setCurrent] = useState("");
  const [version, setVersion] = useState("");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState("");
  const [updateObj, setUpdateObj] = useState<any>(null);

  useEffect(() => {
    getVersion()
      .then(setCurrent)
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (open) {
      checkUpdate();
    } else {
      setStatus("idle");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const checkUpdate = async () => {
    setStatus("checking");
    setError("");
    try {
      const { check } = await import("@tauri-apps/plugin-updater");
      const update = await check();
      if (update) {
        setVersion(update.version);
        setNotes((update.body ?? "").trim());
        setUpdateObj(update);
        setStatus("available");
      } else {
        setStatus("uptodate");
      }
    } catch (e) {
      setError(String(e));
      setStatus("error");
    }
  };

  const doUpdate = async () => {
    if (updateObj) {
      setStatus("downloading");
      try {
        await updateObj.downloadAndInstall();
        const { relaunch } = await import("@tauri-apps/plugin-process");
        await relaunch();
      } catch (e) {
        setError(String(e));
        setStatus("error");
      }
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-bg-1 border-border max-w-sm p-6 flex flex-col gap-5">
        <DialogHeader className="space-y-1">
          <DialogTitle className="font-chakra text-text-0 text-xl tracking-wide">
            Software Update
          </DialogTitle>
          <DialogDescription className="text-text-2 text-xs">
            PacketSniffer{" "}
            <span className="font-mono text-text-1">
              {current ? `v${current}` : "—"}
            </span>
          </DialogDescription>
        </DialogHeader>

        {(status === "checking" || status === "downloading") && (
          <div className="flex flex-col items-center justify-center gap-3 py-8">
            <Spinner size={22} />
            <p className="text-sm font-medium text-text-1">
              {status === "checking"
                ? "Checking for updates…"
                : "Downloading & installing…"}
            </p>
            {status === "downloading" && (
              <p className="text-[11px] text-muted-foreground">
                The app will restart when it's done.
              </p>
            )}
          </div>
        )}

        {status === "uptodate" && (
          <div className="flex flex-col items-center justify-center gap-3 py-8">
            <span className="grid place-items-center size-11 rounded-full border border-border bg-bg-2/50">
              <Check className="size-5 text-text-0" />
            </span>
            <p className="text-sm font-medium text-text-1">
              You're on the latest version.
            </p>
          </div>
        )}

        {status === "available" && (
          <div className="flex flex-col gap-4">
            {/* current → new */}
            <div className="flex items-center justify-center gap-3 rounded-md border border-border/60 bg-bg-2/30 px-4 py-4">
              <div className="text-center">
                <div className="text-[9px] font-mono uppercase tracking-[0.15em] text-muted-foreground">
                  Current
                </div>
                <div className="font-mono text-sm text-text-2 tabular-nums">
                  v{current || "?"}
                </div>
              </div>
              <ArrowRight className="size-4 text-muted-foreground shrink-0" />
              <div className="text-center">
                <div className="text-[9px] font-mono uppercase tracking-[0.15em] text-muted-foreground">
                  New
                </div>
                <div className="font-chakra text-lg font-bold text-text-0 tabular-nums leading-none">
                  v{version}
                </div>
              </div>
            </div>

            {notes && (
              <div className="space-y-1.5">
                <div className="text-[10px] font-mono font-semibold uppercase tracking-[0.15em] text-muted-foreground">
                  Release notes
                </div>
                <div className="max-h-40 overflow-auto rounded-md border border-border/60 bg-bg-0/40 px-3 py-2.5">
                  <Markdown source={notes} />
                </div>
              </div>
            )}

            <div className="flex gap-2">
              <Button
                variant="outline"
                className="flex-1"
                onClick={() => onOpenChange(false)}
              >
                Later
              </Button>
              <Button onClick={doUpdate} className="flex-1">
                <Download className="size-4 mr-1.5" />
                Install
              </Button>
            </div>
          </div>
        )}

        {status === "error" && (
          <div className="flex flex-col items-center gap-3 py-6 text-center">
            <span className="grid place-items-center size-11 rounded-full border border-destructive/40 bg-destructive/10">
              <TriangleAlert className="size-5 text-destructive" />
            </span>
            <p className="text-sm font-medium text-text-1">
              Couldn't check for updates
            </p>
            <p className="text-[11px] text-muted-foreground break-all">{error}</p>
            <Button variant="outline" size="sm" onClick={checkUpdate}>
              <RotateCw className="size-3.5 mr-1.5" />
              Retry
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
