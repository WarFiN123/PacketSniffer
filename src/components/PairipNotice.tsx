import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ShieldAlert } from "lucide-react";

export interface AppProtection {
  pairip: boolean;
}

/**
 * Probe whether an installed app is armored with Google Play Automatic Integrity
 * Protection (PAIRIP), which makes repackaging impossible. Cheap on-device check;
 * re-runs when the selected package changes. Idle (null) without a serial+package.
 */
export function useAppProtection(serial: string, pkg: string) {
  const [protection, setProtection] = useState<AppProtection | null>(null);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    if (!serial || !pkg) {
      setProtection(null);
      setChecking(false);
      return;
    }
    let cancelled = false;
    setChecking(true);
    setProtection(null);
    invoke<AppProtection>("check_app_protection", { serial, package: pkg })
      .then((p) => !cancelled && setProtection(p))
      .catch(() => !cancelled && setProtection(null))
      .finally(() => !cancelled && setChecking(false));
    return () => {
      cancelled = true;
    };
  }, [serial, pkg]);

  return { protection, checking };
}

/**
 * Compact tamper-seal tag shown beside a PAIRIP-protected package — a monospace
 * micro-cap stamp, reusing the destructive token as a passive "sealed" mark.
 */
export function PairipChip() {
  return (
    <span className="inline-flex shrink-0 items-center gap-1 rounded-[3px] border border-destructive/50 bg-destructive/10 px-1.5 py-px text-[9px] font-mono uppercase tracking-[0.14em] text-destructive">
      <ShieldAlert className="size-2.5" />
      PAIRIP
    </span>
  );
}

/** Explains why a PAIRIP app can't be patched, and the way around it. */
export function PairipBanner() {
  return (
    <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2">
      <ShieldAlert className="size-4 text-destructive shrink-0 mt-0.5" />
      <p className="text-[11px] text-text-1 leading-relaxed">
        <span className="font-medium text-text-0">
          Play Integrity (PAIRIP) protected.
        </span>{" "}
        The app checks its own signature in native code, so a repackage can't work
        — it bounces to the Play Store on launch. Capture it with a rooted device
        and the proxy CA installed as a system certificate.
      </p>
    </div>
  );
}
