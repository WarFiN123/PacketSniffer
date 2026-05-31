import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { cn } from "@/lib/utils";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
} from "@/components/ui/dropdown-menu";
import { MoreHorizontal } from "lucide-react";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import HeadersTable from "./HeadersTable";
import BodyViewer from "./BodyViewer";
import MessagesTab from "./MessagesTab";
import Spinner from "./Spinner";
import type { HttpSession, WsMessage } from "@/types";
import {
  parseQueryParams,
  getFullUrl,
  exportToPostman,
  exportRequest,
  exportResponse,
  getRawRequest,
  getRawResponse,
} from "@/lib/exportUtils";

interface DetailPanelProps {
  session: HttpSession | null;
  wsMessages: WsMessage[];
}

type RequestTab = "Header" | "Query" | "Cookies" | "Body";
type ResponseTab = "Header" | "Cookies" | "Body" | "Messages";

function TabButton({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "px-2 h-full text-[12px] font-medium transition-colors border-b-2",
        active
          ? "border-primary text-primary"
          : "border-transparent text-muted-foreground hover:text-foreground",
      )}
    >
      {label}
    </button>
  );
}

function MethodBadge({ method }: { method: string }) {
  return (
    <span className="bg-muted text-muted-foreground px-2 py-0.5 rounded text-[10px] font-bold tracking-wide shadow-sm border border-border/50">
      {method}
    </span>
  );
}

function StatusBadge({
  status,
  statusText,
}: {
  status: number;
  statusText: string;
}) {
  if (status === 0) return null;
  let bg = "bg-muted text-muted-foreground";
  if (status >= 200 && status < 300) bg = "bg-status-success text-secondary";
  else if (status >= 300 && status < 400) bg = "bg-status-redirect text-white";
  else if (status >= 400) bg = "bg-destructive text-destructive-foreground";

  return (
    <span
      className={cn(
        "px-2 py-0.5 rounded text-[10px] font-bold tracking-wide shadow-sm",
        bg,
      )}
    >
      {status} {statusText}
    </span>
  );
}

export default function DetailPanel({ session, wsMessages }: DetailPanelProps) {
  const [reqTab, setReqTab] = useState<RequestTab>("Header");
  const [resTab, setResTab] = useState<ResponseTab>("Header");

  // Bodies are stripped from the streamed session; fetch the full record (with
  // bodies) on demand whenever the selection or its body availability changes.
  const [fetched, setFetched] = useState<HttpSession | null>(null);
  useEffect(() => {
    if (!session || (!session.hasRequestBody && !session.hasResponseBody)) {
      setFetched(null);
      return;
    }
    let cancelled = false;
    invoke<HttpSession | null>("get_session", { id: session.id })
      .then((full) => {
        if (!cancelled) setFetched(full);
      })
      .catch(() => {
        if (!cancelled) setFetched(null);
      });
    return () => {
      cancelled = true;
    };
  }, [
    session?.id,
    session?.hasRequestBody,
    session?.hasResponseBody,
  ]);

  // Track the user's preferred tabs so we can restore them when switching requests
  const preferredReqTab = useRef<RequestTab>("Header");
  const preferredResTab = useRef<ResponseTab>("Header");
  const prevSessionId = useRef<number | null>(null);

  // Smart tab switching: when the selected session changes, pick the best tab
  useEffect(() => {
    if (!session) return;
    if (session.id === prevSessionId.current) return;
    prevSessionId.current = session.id;

    const isWs = session.scheme === "ws" || session.scheme === "wss";
    const hasReqBody = session.hasRequestBody;
    const hasResBody = session.hasResponseBody;
    const queryParams = parseQueryParams(session.path);
    const hasQuery = queryParams.length > 0;
    const hasReqCookies = session.requestHeaders.some(
      (h) => h.name.toLowerCase() === "cookie",
    );
    const hasResCookies = session.responseHeaders.some(
      (h) => h.name.toLowerCase() === "set-cookie",
    );

    // Request tab: try to keep the user's preferred tab, fall back to Header
    const reqAvailable: RequestTab[] = ["Header"];
    if (hasQuery) reqAvailable.push("Query");
    if (hasReqBody) reqAvailable.push("Body");
    if (hasReqCookies) reqAvailable.push("Cookies");

    if (reqAvailable.includes(preferredReqTab.current)) {
      setReqTab(preferredReqTab.current);
    } else {
      setReqTab("Header");
    }

    // Response tab: try preferred, handle WS specially
    const resAvailable: ResponseTab[] = ["Header"];
    if (hasResBody) resAvailable.push("Body");
    if (hasResCookies) resAvailable.push("Cookies");
    if (isWs) resAvailable.push("Messages");

    if (resAvailable.includes(preferredResTab.current)) {
      setResTab(preferredResTab.current);
    } else if (isWs) {
      setResTab("Messages");
    } else {
      setResTab("Header");
    }
  }, [session]);

  // Update preferred tab whenever the user explicitly clicks a tab
  const handleReqTab = (tab: RequestTab) => {
    preferredReqTab.current = tab;
    setReqTab(tab);
  };

  const handleResTab = (tab: ResponseTab) => {
    preferredResTab.current = tab;
    setResTab(tab);
  };

  if (!session) {
    return (
      <div className="h-full flex items-center justify-center bg-background text-muted-foreground text-xs">
        Select a request to inspect
      </div>
    );
  }

  // Render bodies/exports from the fetched full record when available, falling
  // back to the slim streamed session (metadata + body-presence flags).
  const view =
    fetched && fetched.id === session.id ? fetched : session;

  const isWs = session.scheme === "ws" || session.scheme === "wss";
  const queryParams = parseQueryParams(session.path);
  const hasQuery = queryParams.length > 0;
  const hasReqBody = session.hasRequestBody;
  const hasResBody = session.hasResponseBody;
  const isJson = (session.contentType || "").includes("json");

  const requestCookies = session.requestHeaders
    .filter((h) => h.name.toLowerCase() === "cookie")
    .flatMap((h) =>
      h.value.split(";").map((c) => {
        const [k, ...v] = c.split("=");
        return [k.trim(), v.join("=")];
      }),
    ) as [string, string][];

  const responseCookies = session.responseHeaders
    .filter((h) => h.name.toLowerCase() === "set-cookie")
    .map((h) => {
      const parts = h.value.split(";");
      const [k, ...v] = parts[0].split("=");
      return [k.trim(), v.join("=")];
    }) as [string, string][];

  const hasReqCookies = requestCookies.length > 0;
  const hasResCookies = responseCookies.length > 0;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text).catch(() => {});
  };

  const fullUrl = getFullUrl(session);

  return (
    <div className="h-full flex flex-col bg-background">
      <ContextMenu>
        <ContextMenuTrigger asChild>
          <div className="flex items-center gap-2 px-3 h-9 border-b border-border bg-panel-header shrink-0 select-none">
            <MethodBadge method={session.method} />
            <StatusBadge
              status={session.status}
              statusText={session.statusText}
            />

            <span
              className="flex-1 min-w-0 truncate text-[11px] font-mono text-foreground ml-1"
              title={fullUrl}
            >
              {fullUrl}
            </span>
          </div>
        </ContextMenuTrigger>
        <ContextMenuContent className="text-[12px] min-w-48">
          <ContextMenuItem onClick={() => handleCopy(fullUrl)}>
            Copy URL
          </ContextMenuItem>
          <ContextMenuItem onClick={() => handleCopy(session.path)}>
            Copy Path
          </ContextMenuItem>
          <ContextMenuItem onClick={() => handleCopy(session.method)}>
            Copy Method
          </ContextMenuItem>
          {session.status > 0 && (
            <ContextMenuItem
              onClick={() => handleCopy(session.status.toString())}
            >
              Copy Status Code
            </ContextMenuItem>
          )}
          <ContextMenuSeparator />
          <ContextMenuItem onClick={() => exportToPostman(view)}>
            Open in Postman
          </ContextMenuItem>
        </ContextMenuContent>
      </ContextMenu>

      <div className="flex-1 flex min-h-0">
        <div className="flex-1 flex flex-col min-w-0 border-r border-border">
          <div className="flex items-center gap-2 px-2 h-7 border-b border-border bg-panel-header shrink-0 select-none">
            <span className="text-[11px] font-semibold text-foreground mr-1">
              Request
            </span>
            <TabButton
              label="Header"
              active={reqTab === "Header"}
              onClick={() => handleReqTab("Header")}
            />
            {hasQuery && (
              <TabButton
                label="Query"
                active={reqTab === "Query"}
                onClick={() => handleReqTab("Query")}
              />
            )}
            {hasReqBody && (
              <TabButton
                label="Body"
                active={reqTab === "Body"}
                onClick={() => handleReqTab("Body")}
              />
            )}
            {hasReqCookies && (
              <TabButton
                label="Cookies"
                active={reqTab === "Cookies"}
                onClick={() => handleReqTab("Cookies")}
              />
            )}

            <div className="flex-1" />
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button className="px-2 h-full text-muted-foreground hover:text-foreground transition-colors flex items-center justify-center outline-none">
                  <MoreHorizontal className="size-3.5" />
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="text-[12px] min-w-32">
                <DropdownMenuItem
                  onClick={() => handleCopy(getRawRequest(view))}
                >
                  Copy Raw Request
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => exportRequest(view)}>
                  Export Request
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => exportToPostman(view)}>
                  Open in Postman
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>

          <ScrollArea className="flex-1 min-h-0">
            {reqTab === "Header" && (
              <HeadersTable headers={session.requestHeaders} />
            )}
            {reqTab === "Cookies" && (
              <div className="w-full">
                <table className="w-full text-left border-collapse">
                  <thead className="bg-panel-header text-[11px] text-muted-foreground font-medium border-b border-border">
                    <tr>
                      <th className="font-normal px-2 py-1 w-1/3 border-r border-border">
                        Name
                      </th>
                      <th className="font-normal px-2 py-1">Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {requestCookies.map(([key, val], i) => (
                      <tr
                        key={`${key}-${i}`}
                        className="border-b border-border/50 text-[11px]"
                      >
                        <td className="px-2 py-1 border-r border-border/50 font-mono text-foreground">
                          {key}
                        </td>
                        <td className="px-2 py-1 font-mono text-foreground break-all">
                          {val}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {reqTab === "Query" && (
              <div className="w-full">
                <table className="w-full text-left border-collapse">
                  <thead className="bg-panel-header text-[11px] text-muted-foreground font-medium border-b border-border">
                    <tr>
                      <th className="font-normal px-2 py-1 w-1/3 border-r border-border">
                        Key
                      </th>
                      <th className="font-normal px-2 py-1">Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {queryParams.map(([key, val], i) => (
                      <tr
                        key={`${key}-${i}`}
                        className="border-b border-border/50 text-[11px]"
                      >
                        <td className="px-2 py-1 border-r border-border/50 font-mono text-foreground">
                          {key}
                        </td>
                        <td className="px-2 py-1 font-mono text-foreground break-all">
                          {val}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {reqTab === "Body" &&
              (view.requestBody ? (
                <BodyViewer
                  body={view.requestBody}
                  isJson={isJson}
                  contentType={view.contentType || ""}
                />
              ) : (
                <div className="p-4 text-[11px] text-muted-foreground flex items-center gap-1">
                  <Spinner size={14} />
                  <span>Loading body…</span>
                </div>
              ))}
          </ScrollArea>
        </div>

        <div className="flex-1 flex flex-col min-w-0">
          <div className="flex items-center gap-2 px-2 h-7 border-b border-border bg-panel-header shrink-0 select-none">
            <span className="text-[11px] font-semibold text-foreground mr-1">
              Response
            </span>
            <TabButton
              label="Header"
              active={resTab === "Header"}
              onClick={() => handleResTab("Header")}
            />
            {hasResBody && (
              <TabButton
                label="Body"
                active={resTab === "Body"}
                onClick={() => handleResTab("Body")}
              />
            )}
            {hasResCookies && (
              <TabButton
                label="Cookies"
                active={resTab === "Cookies"}
                onClick={() => handleResTab("Cookies")}
              />
            )}
            {isWs && (
              <TabButton
                label="Messages"
                active={resTab === "Messages"}
                onClick={() => handleResTab("Messages")}
              />
            )}

            <div className="flex-1" />
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button className="px-2 h-full text-muted-foreground hover:text-foreground transition-colors flex items-center justify-center outline-none">
                  <MoreHorizontal className="size-3.5" />
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="text-[12px] min-w-32">
                <DropdownMenuItem
                  onClick={() => handleCopy(getRawResponse(view))}
                >
                  Copy Raw Response
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => exportResponse(view)}>
                  Export Response
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>

          <ScrollArea className="flex-1 min-h-0">
            {resTab === "Header" && (
              <HeadersTable headers={session.responseHeaders} />
            )}
            {resTab === "Cookies" && (
              <div className="w-full">
                <table className="w-full text-left border-collapse">
                  <thead className="bg-panel-header text-[11px] text-muted-foreground font-medium border-b border-border">
                    <tr>
                      <th className="font-normal px-2 py-1 w-1/3 border-r border-border">
                        Name
                      </th>
                      <th className="font-normal px-2 py-1">Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {responseCookies.map(([key, val], i) => (
                      <tr
                        key={`${key}-${i}`}
                        className="border-b border-border/50 text-[11px]"
                      >
                        <td className="px-2 py-1 border-r border-border/50 font-mono text-foreground">
                          {key}
                        </td>
                        <td className="px-2 py-1 font-mono text-foreground break-all">
                          {val}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {resTab === "Body" &&
              (view.responseBody ? (
                <BodyViewer
                  body={view.responseBody}
                  isJson={isJson}
                  contentType={view.contentType || ""}
                />
              ) : (
                <div className="p-4 text-[11px] text-muted-foreground flex items-center gap-1">
                  <Spinner size={14} />
                  <span>Loading body…</span>
                </div>
              ))}
            {resTab === "Messages" && <MessagesTab messages={wsMessages} />}

            {!session.complete && (
              <div className="p-4 text-[11px] text-muted-foreground flex items-center gap-1">
                <Spinner size={14} />
                <span>Waiting for response...</span>
              </div>
            )}
          </ScrollArea>
        </div>
      </div>
    </div>
  );
}
