import { useState, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { ShieldBan } from "lucide-react";
import { cn } from "@/lib/utils";
import { type InterceptConfig, type ListMode } from "@/lib/intercept";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  config: InterceptConfig;
  onUpdate: (patch: Partial<InterceptConfig>) => void;
}

export default function BlockListDialog({
  open,
  onOpenChange,
  config,
  onUpdate,
}: Props) {
  // Local text buffer so blank lines while typing aren't dropped.
  const [listText, setListText] = useState("");

  useEffect(() => {
    if (open) setListText(config.listRules.join("\n"));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-bg-1 border-border max-w-md p-6 flex flex-col gap-5">
        <DialogHeader>
          <DialogTitle className="font-chakra text-text-0 text-xl flex items-center gap-2">
            <ShieldBan className="size-5" /> Block / Allow List
          </DialogTitle>
          <DialogDescription className="text-text-2 text-xs">
            Block matching requests, or allow only matches through.
          </DialogDescription>
        </DialogHeader>

        <div className="flex items-center gap-0.5 rounded-md bg-muted/60 p-0.5 self-start">
          {(["off", "block", "allow"] as ListMode[]).map((m) => (
            <button
              key={m}
              onClick={() => onUpdate({ listMode: m })}
              className={cn(
                "px-3 h-7 text-xs font-medium rounded capitalize transition-colors",
                config.listMode === m
                  ? m === "block"
                    ? "bg-destructive/15 text-destructive"
                    : m === "allow"
                      ? "bg-[#00ca50]/15 text-[#00ca50]"
                      : "bg-background text-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              {m}
            </button>
          ))}
        </div>

        <div className="space-y-2">
          <Textarea
            value={listText}
            placeholder={"*.doubleclick.net\nhttps://example.com/ads/*\nanalytics"}
            spellCheck={false}
            disabled={config.listMode === "off"}
            onChange={(e) => {
              setListText(e.target.value);
              onUpdate({
                listRules: e.target.value
                  .split("\n")
                  .map((s) => s.trim())
                  .filter(Boolean),
              });
            }}
            className="h-40 text-[12px] font-mono resize-none disabled:opacity-50"
          />
          <p className="text-xs text-muted-foreground">
            One pattern per line. <code>*</code> is a wildcard, matched against
            the full URL. Blocked requests appear as <code>403 Blocked</code>.
          </p>
        </div>
      </DialogContent>
    </Dialog>
  );
}
