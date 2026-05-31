export interface HttpHeader {
  name: string;
  value: string;
}

export interface HttpSession {
  id: number;
  scheme: string;
  method: string;
  host: string;
  path: string;
  url: string;
  httpVersion: string;
  status: number;
  statusText: string;
  respHttpVersion: string;
  contentType: string;
  requestSize: number;
  responseSize: number;
  duration: number;
  complete: boolean;
  requestHeaders: HttpHeader[];
  responseHeaders: HttpHeader[];
  // Bodies are stripped from the live event stream to keep it small; they are
  // null on streamed sessions and only populated when fetched via `get_session`.
  requestBody: string | null;
  responseBody: string | null;
  // Present on every streamed session so the UI knows whether a Body tab should
  // be shown without transporting the body itself.
  hasRequestBody: boolean;
  hasResponseBody: boolean;
}

export interface SessionEvent {
  type: string; // "start" | "finish"
  session: HttpSession;
}

export interface WsMessage {
  sessionId: number;
  index: number;
  direction: "send" | "recv";
  opcode: string; // "text" | "binary" | "close" | "ping" | "pong"
  length: number;
  data: string | null;
  timestampMs: number;
}

export interface WsMessageEvent {
  message: WsMessage;
}
