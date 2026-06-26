export interface HttpHeader {
  name: string;
  value: string;
}

export interface HttpSession {
  id: number;
  /** IP the proxied request came from — "127.0.0.1" for this computer, a LAN IP
   * for a connected phone. Used to separate "My computer" from each device. */
  clientAddr: string;
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

/** A phone connected through the "Add device" walkthrough. Its traffic is
 * tagged by `ip` (the LAN address its proxied requests arrive from). */
export interface ConnectedDevice {
  serial: string;
  model: string;
  ip: string;
  platform: "android";
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
