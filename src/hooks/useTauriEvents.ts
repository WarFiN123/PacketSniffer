import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  HttpSession,
  SessionEvent,
  WsMessage,
  WsMessageEvent,
} from "../types";

/** Keep at most this many sessions in the UI. Matches the server-side
 *  `MAX_SESSIONS` cap so any row still visible can have its bodies fetched
 *  back. Bounds memory during very long capture runs. */
const MAX_SESSIONS = 5000;

/* ─── Batched proxy session hook ─────────────────────────────────────────────
 * Collects all proxy-session events that arrive within a single animation
 * frame and flushes them as one React state update, dramatically reducing
 * re-renders under heavy traffic (e.g. page loads with 100+ sub-requests).
 */
export function useProxySessions() {
  const [sessions, setSessions] = useState<Map<number, HttpSession>>(new Map());
  const [order, setOrder] = useState<number[]>([]);
  const [connected, setConnected] = useState(false);

  // Accumulate events between frames
  const pendingUpdates = useRef<HttpSession[]>([]);
  const pendingStarts = useRef<number[]>([]);
  const rafId = useRef<number | null>(null);
  // Canonical order, mirrored here so eviction is computed deterministically
  // (independent of React's per-hook state-update ordering).
  const orderRef = useRef<number[]>([]);

  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    let cancelled = false;

    const flush = () => {
      rafId.current = null;
      const updates = pendingUpdates.current;
      const starts = pendingStarts.current;
      pendingUpdates.current = [];
      pendingStarts.current = [];

      if (updates.length === 0) return;

      // Grow the canonical order and compute oldest-first eviction up front so
      // both state updates below agree on which ids to drop.
      let evicted: number[] = [];
      if (starts.length > 0) {
        let nextOrder = orderRef.current.concat(starts);
        if (nextOrder.length > MAX_SESSIONS) {
          const overflow = nextOrder.length - MAX_SESSIONS;
          evicted = nextOrder.slice(0, overflow);
          nextOrder = nextOrder.slice(overflow);
        }
        orderRef.current = nextOrder;
        setOrder(nextOrder);
      }

      setSessions((prev) => {
        const next = new Map(prev);
        for (const session of updates) {
          next.set(session.id, session);
        }
        for (const id of evicted) {
          next.delete(id);
        }
        return next;
      });
    };

    listen<SessionEvent>("proxy-session", (event) => {
      if (cancelled) return;
      const { type, session } = event.payload;
      setConnected(true);

      pendingUpdates.current.push(session);
      if (type === "start") {
        pendingStarts.current.push(session.id);
      }

      // Schedule a flush on the next animation frame (coalesces all events in this frame)
      if (rafId.current === null) {
        rafId.current = requestAnimationFrame(flush);
      }
    }).then((fn) => {
      if (cancelled) {
        fn();
      } else {
        unlisten = fn;
      }
    });

    const pollStatus = async () => {
      for (let i = 0; i < 10; i++) {
        if (cancelled) return;
        try {
          const status = await invoke<string>("get_proxy_status");
          if (!cancelled && status.startsWith("running")) {
            setConnected(true);
            return;
          }
        } catch {
          // ignore
        }
        await new Promise((r) => setTimeout(r, 500));
      }
    };
    pollStatus();

    return () => {
      cancelled = true;
      unlisten?.();
      if (rafId.current !== null) {
        cancelAnimationFrame(rafId.current);
      }
    };
  }, []);

  const clear = useCallback(() => {
    orderRef.current = [];
    setSessions(new Map());
    setOrder([]);
  }, []);

  return { sessions, order, connected, clear };
}

export function useWsMessages() {
  const [messages, setMessages] = useState<Map<number, WsMessage[]>>(new Map());

  const pendingMessages = useRef<WsMessage[]>([]);
  const rafId = useRef<number | null>(null);

  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    let cancelled = false;

    const flush = () => {
      rafId.current = null;
      const batch = pendingMessages.current;
      pendingMessages.current = [];

      if (batch.length === 0) return;

      setMessages((prev) => {
        const next = new Map(prev);
        const grouped = new Map<number, typeof batch>();
        for (const msg of batch) {
          const arr = grouped.get(msg.sessionId) ?? [];
          arr.push(msg);
          grouped.set(msg.sessionId, arr);
        }
        for (const [sessionId, msgs] of grouped) {
          const existing = next.get(sessionId) ?? [];
          next.set(sessionId, existing.concat(msgs));
        }
        return next;
      });
    };

    listen<WsMessageEvent>("ws-message", (event) => {
      if (cancelled) return;
      pendingMessages.current.push(event.payload.message);

      if (rafId.current === null) {
        rafId.current = requestAnimationFrame(flush);
      }
    }).then((fn) => {
      if (cancelled) {
        fn();
      } else {
        unlisten = fn;
      }
    });

    return () => {
      cancelled = true;
      unlisten?.();
      if (rafId.current !== null) {
        cancelAnimationFrame(rafId.current);
      }
    };
  }, []);

  const clear = useCallback(() => {
    setMessages(new Map());
  }, []);

  return { messages, clear };
}
