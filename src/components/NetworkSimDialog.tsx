import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Gauge } from "lucide-react";
import { NET_PRESETS, type InterceptConfig } from "@/lib/intercept";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  config: InterceptConfig;
  onUpdate: (patch: Partial<InterceptConfig>) => void;
}

export default function NetworkSimDialog({
  open,
  onOpenChange,
  config,
  onUpdate,
}: Props) {
  const activePreset =
    NET_PRESETS.find(
      (p) => p.latencyMs === config.latencyMs && p.kbps === config.kbps,
    )?.name ?? "custom";

  const active = config.latencyMs > 0 || config.kbps > 0;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-bg-1 border-border max-w-sm p-6 flex flex-col gap-5">
        <DialogHeader>
          <DialogTitle className="font-chakra text-text-0 text-xl flex items-center gap-2">
            <Gauge className="size-5" /> Simulate Network
          </DialogTitle>
          <DialogDescription className="text-text-2 text-xs">
            Add latency and throttle download bandwidth on intercepted traffic.
          </DialogDescription>
        </DialogHeader>

        <div className="flex items-center justify-between gap-3">
          <Label className="text-sm text-text-1">Preset</Label>
          <Select
            value={activePreset}
            onValueChange={(name) => {
              const p = NET_PRESETS.find((x) => x.name === name);
              if (p) onUpdate({ latencyMs: p.latencyMs, kbps: p.kbps });
            }}
          >
            <SelectTrigger className="w-44 h-8 text-sm">
              <SelectValue placeholder="Custom" />
            </SelectTrigger>
            <SelectContent>
              {activePreset === "custom" && (
                <SelectItem value="custom" disabled>
                  Custom
                </SelectItem>
              )}
              {NET_PRESETS.map((p) => (
                <SelectItem key={p.name} value={p.name}>
                  {p.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1">
            <Label className="text-xs text-muted-foreground">Latency (ms)</Label>
            <Input
              type="number"
              min={0}
              value={config.latencyMs}
              onChange={(e) =>
                onUpdate({ latencyMs: Math.max(0, +e.target.value || 0) })
              }
              className="h-8 text-sm"
            />
          </div>
          <div className="space-y-1">
            <Label className="text-xs text-muted-foreground">
              Bandwidth (kbps, 0 = ∞)
            </Label>
            <Input
              type="number"
              min={0}
              value={config.kbps}
              onChange={(e) =>
                onUpdate({ kbps: Math.max(0, +e.target.value || 0) })
              }
              className="h-8 text-sm"
            />
          </div>
        </div>

        <p className="text-[11px] text-muted-foreground">
          {active
            ? `Active: +${config.latencyMs}ms latency` +
              (config.kbps > 0 ? `, ${config.kbps} kbps cap` : "")
            : "Disabled — traffic flows at full speed."}
        </p>
      </DialogContent>
    </Dialog>
  );
}
