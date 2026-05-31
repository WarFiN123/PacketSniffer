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
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import Switch from "./Switch";
import { Plus, Trash2, FolderOpen, Waypoints } from "lucide-react";
import {
  type InterceptConfig,
  type MapKind,
  type MapRule,
} from "@/lib/intercept";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  config: InterceptConfig;
  onUpdate: (patch: Partial<InterceptConfig>) => void;
}

export default function MapRulesDialog({
  open,
  onOpenChange,
  config,
  onUpdate,
}: Props) {
  const rules = config.mapRules;

  const updateRule = (i: number, patch: Partial<MapRule>) =>
    onUpdate({
      mapRules: rules.map((r, idx) => (idx === i ? { ...r, ...patch } : r)),
    });

  const addRule = () =>
    onUpdate({
      mapRules: [
        ...rules,
        { pattern: "", kind: "local", target: "", enabled: true },
      ],
    });

  const removeRule = (i: number) =>
    onUpdate({ mapRules: rules.filter((_, idx) => idx !== i) });

  const browseLocal = async (i: number) => {
    try {
      const picked = await openFileDialog({ multiple: false, directory: false });
      if (typeof picked === "string") updateRule(i, { target: picked });
    } catch {
      // cancelled
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-bg-1 border-border max-w-lg p-0 flex flex-col gap-0 max-h-[85vh]">
        <DialogHeader className="px-6 pt-6 pb-4 border-b border-border/60">
          <DialogTitle className="font-chakra text-text-0 text-xl flex items-center gap-2">
            <Waypoints className="size-5" /> Map Requests
          </DialogTitle>
          <DialogDescription className="text-text-2 text-xs">
            Redirect matching URLs to a local file or another URL.
          </DialogDescription>
        </DialogHeader>

        <ScrollArea className="flex-1 min-h-0">
          <div className="px-6 py-4">
            {rules.length === 0 ? (
              <p className="text-xs text-muted-foreground italic py-6 text-center">
                No map rules yet.
              </p>
            ) : (
              <div className="space-y-2">
                {rules.map((rule, i) => (
                  <div
                    key={i}
                    className="rounded-md border border-border bg-background/40 p-2 space-y-2"
                  >
                    <div className="flex items-center gap-2">
                      <Switch
                        checked={rule.enabled}
                        onChange={(v) => updateRule(i, { enabled: v })}
                      />
                      <Input
                        value={rule.pattern}
                        placeholder="match URL (e.g. *.example.com/api/*)"
                        spellCheck={false}
                        onChange={(e) =>
                          updateRule(i, { pattern: e.target.value })
                        }
                        className="h-7 text-[12px] font-mono flex-1"
                      />
                      <Select
                        value={rule.kind}
                        onValueChange={(k) =>
                          updateRule(i, { kind: k as MapKind })
                        }
                      >
                        <SelectTrigger className="w-24 h-7 text-xs">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="local">Local</SelectItem>
                          <SelectItem value="remote">Remote</SelectItem>
                        </SelectContent>
                      </Select>
                      <button
                        onClick={() => removeRule(i)}
                        className="text-muted-foreground hover:text-destructive p-1 shrink-0"
                        aria-label="Remove rule"
                      >
                        <Trash2 className="size-3.5" />
                      </button>
                    </div>
                    <div className="flex items-center gap-2 pl-11">
                      <Input
                        value={rule.target}
                        placeholder={
                          rule.kind === "local"
                            ? "/path/to/file"
                            : "https://other.host/path"
                        }
                        spellCheck={false}
                        onChange={(e) =>
                          updateRule(i, { target: e.target.value })
                        }
                        className="h-7 text-[12px] font-mono flex-1"
                      />
                      {rule.kind === "local" && (
                        <Button
                          variant="outline"
                          size="xs"
                          onClick={() => browseLocal(i)}
                        >
                          <FolderOpen className="size-3.5" />
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </ScrollArea>

        <div className="flex items-center justify-between px-6 py-3 border-t border-border/60 bg-bg-2/30">
          <span className="text-[11px] text-muted-foreground">
            Local → serve a file · Remote → same-scheme URL
          </span>
          <Button variant="outline" size="xs" onClick={addRule}>
            <Plus className="size-3.5 mr-1" /> Add rule
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
