import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import Switch from "./Switch";
import { ShieldCheck, Syringe, Cpu, FolderOpen } from "lucide-react";

// Patch knobs shared by the Tools › Patch APK dialog and the device-onboarding
// flow so the two never drift apart.
export interface PatchOpts {
  embedCa: boolean;
  trustUser: boolean;
  debuggable: boolean;
  frida: boolean;
  fridaPath: string;
  fridaAbi: string;
}

export const DEFAULT_PATCH_OPTS: PatchOpts = {
  embedCa: true,
  trustUser: false,
  debuggable: false,
  frida: false,
  fridaPath: "",
  fridaAbi: "auto",
};

// Map the UI options onto the serde shape `patch_apk` expects.
export function backendPatchOpts(apkPath: string, o: PatchOpts) {
  return {
    apkPath,
    embedProxyCa: o.embedCa,
    trustUserStore: o.trustUser,
    makeDebuggable: o.debuggable,
    injectFrida: o.frida,
    fridaGadgetPath: o.fridaPath,
    fridaAbi: o.fridaAbi,
  };
}

// A patch config is runnable only with a trust anchor, and a Frida gadget path
// when injection is on.
export function patchOptsValid(o: PatchOpts): boolean {
  return (o.embedCa || o.trustUser) && (!o.frida || o.fridaPath !== "");
}

export default function PatchOptions({
  opts,
  onChange,
}: {
  opts: PatchOpts;
  onChange: (patch: Partial<PatchOpts>) => void;
}) {
  const browseGadget = async () => {
    try {
      const picked = await openFileDialog({
        multiple: false,
        directory: false,
        filters: [{ name: "Frida gadget", extensions: ["so"] }],
      });
      if (typeof picked === "string") onChange({ fridaPath: picked });
    } catch {
      /* cancelled */
    }
  };

  return (
    <div className="space-y-px rounded-md border border-border/60 overflow-hidden">
      <OptionRow
        icon={<ShieldCheck className="size-3.5" />}
        title="Embed proxy CA"
        hint="Bake the CA into the app — no cert install on the phone."
        checked={opts.embedCa}
        onChange={(v) => onChange({ embedCa: v })}
      />
      <OptionRow
        title="Trust user CA store"
        hint="Also trust certs installed on the device."
        checked={opts.trustUser}
        onChange={(v) => onChange({ trustUser: v })}
      />
      <OptionRow
        title="Make debuggable"
        hint="Set android:debuggable — eases runtime hooking."
        checked={opts.debuggable}
        onChange={(v) => onChange({ debuggable: v })}
      />
      <OptionRow
        icon={<Syringe className="size-3.5" />}
        title="Inject Frida gadget"
        hint="Defeat code-level cert pinning on non-rooted devices."
        checked={opts.frida}
        onChange={(v) => onChange({ frida: v })}
      />
      {opts.frida && (
        <div className="px-3 py-3 bg-bg-2/40 space-y-2">
          <div className="flex items-center gap-2">
            <Input
              value={opts.fridaPath}
              placeholder="path to libfrida-gadget.so"
              spellCheck={false}
              onChange={(e) => onChange({ fridaPath: e.target.value })}
              className="h-7 text-[12px] font-mono flex-1"
            />
            <Button variant="outline" size="xs" onClick={browseGadget}>
              <FolderOpen className="size-3.5" />
            </Button>
          </div>
          <div className="flex items-center gap-2">
            <Cpu className="size-3.5 text-muted-foreground" />
            <Label className="text-[11px] text-muted-foreground">ABI</Label>
            <Select
              value={opts.fridaAbi}
              onValueChange={(v) => onChange({ fridaAbi: v })}
            >
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
        <div className="text-[11px] text-muted-foreground leading-snug">
          {hint}
        </div>
      </div>
      <Switch checked={checked} onChange={onChange} />
    </label>
  );
}
