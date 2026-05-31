import { useEffect, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { Minus, X, Square, Copy } from "lucide-react";
import { cn } from "@/lib/utils";

/** Custom titlebar window buttons. The app runs with `decorations: false`, so
 *  these drive the OS window via the Tauri window API. They live inside the
 *  toolbar drag region; the global CSS rule marks buttons as no-drag. */
export default function WindowControls({ onClose }: { onClose: () => void }) {
  const [maximized, setMaximized] = useState(false);

  useEffect(() => {
    const win = getCurrentWindow();
    let unlisten: (() => void) | undefined;
    let cancelled = false;

    const sync = () => win.isMaximized().then(setMaximized).catch(() => {});
    sync();
    win
      .onResized(() => sync())
      .then((fn) => {
        if (cancelled) fn();
        else unlisten = fn;
      })
      .catch(() => {});

    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  const base =
    "flex items-center justify-center size-7 rounded-md text-muted-foreground transition-colors outline-none";

  return (
    <div className="flex items-center gap-0.5 pl-1">
      <button
        type="button"
        aria-label="Minimize"
        onClick={() => getCurrentWindow().minimize()}
        className={cn(base, "hover:bg-muted hover:text-foreground")}
      >
        <Minus className="size-3.5" />
      </button>
      <button
        type="button"
        aria-label={maximized ? "Restore" : "Maximize"}
        onClick={() => getCurrentWindow().toggleMaximize()}
        className={cn(base, "hover:bg-muted hover:text-foreground")}
      >
        {maximized ? (
          <Copy className="size-3 -scale-x-100" />
        ) : (
          <Square className="size-3" />
        )}
      </button>
      <button
        type="button"
        aria-label="Close"
        onClick={onClose}
        className={cn(base, "hover:bg-destructive hover:text-white")}
      >
        <X className="size-4" />
      </button>
    </div>
  );
}
