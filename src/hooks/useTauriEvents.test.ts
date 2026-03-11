import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { renderHook, act, waitFor } from '@testing-library/react';
import { useProxySessions, useWsMessages } from './useTauriEvents';
import type { SessionEvent, WsMessageEvent } from '../types';

// Mock @tauri-apps/api modules
vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(),
}));

import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

describe('useProxySessions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should initialize with empty sessions and order', () => {
    vi.mocked(listen).mockResolvedValue(() => {});
    vi.mocked(invoke).mockResolvedValue('stopped');

    const { result } = renderHook(() => useProxySessions());

    expect(result.current.sessions.size).toBe(0);
    expect(result.current.order).toEqual([]);
    expect(result.current.connected).toBe(false);
  });

  it('should set connected to true when receiving session events', async () => {
    let eventHandler: ((event: any) => void) | undefined;

    vi.mocked(listen).mockImplementation((eventName, handler) => {
      eventHandler = handler;
      return Promise.resolve(() => {});
    });
    vi.mocked(invoke).mockResolvedValue('stopped');

    const { result } = renderHook(() => useProxySessions());

    // Wait for the listen to be called
    await waitFor(() => {
      expect(listen).toHaveBeenCalled();
    });

    // Simulate event
    const sessionEvent: SessionEvent = {
      type: 'start',
      session: {
        id: 1,
        method: 'GET',
        scheme: 'https',
        host: 'example.com',
        path: '/',
        url: 'https://example.com/',
        status: 0,
        statusText: '',
        contentType: null,
        requestHeaders: [],
        responseHeaders: [],
        requestBody: null,
        responseBody: null,
        responseSize: null,
        duration: null,
        complete: false,
      },
    };

    await act(async () => {
      eventHandler?.({ payload: sessionEvent });
      // Wait for RAF flush
      await new Promise((resolve) => requestAnimationFrame(resolve));
    });

    expect(result.current.connected).toBe(true);
  });

  it('should add sessions to the map when events are received', async () => {
    let eventHandler: ((event: any) => void) | undefined;

    vi.mocked(listen).mockImplementation((eventName, handler) => {
      eventHandler = handler;
      return Promise.resolve(() => {});
    });
    vi.mocked(invoke).mockResolvedValue('stopped');

    const { result } = renderHook(() => useProxySessions());

    await waitFor(() => {
      expect(listen).toHaveBeenCalled();
    });

    const sessionEvent: SessionEvent = {
      type: 'start',
      session: {
        id: 1,
        method: 'POST',
        scheme: 'https',
        host: 'api.example.com',
        path: '/api/data',
        url: 'https://api.example.com/api/data',
        status: 0,
        statusText: '',
        contentType: null,
        requestHeaders: [],
        responseHeaders: [],
        requestBody: '{"key":"value"}',
        responseBody: null,
        responseSize: null,
        duration: null,
        complete: false,
      },
    };

    await act(async () => {
      eventHandler?.({ payload: sessionEvent });
      await new Promise((resolve) => requestAnimationFrame(resolve));
    });

    expect(result.current.sessions.get(1)).toBeDefined();
    expect(result.current.sessions.get(1)?.method).toBe('POST');
  });

  it('should add session ID to order on "start" events', async () => {
    let eventHandler: ((event: any) => void) | undefined;

    vi.mocked(listen).mockImplementation((eventName, handler) => {
      eventHandler = handler;
      return Promise.resolve(() => {});
    });
    vi.mocked(invoke).mockResolvedValue('stopped');

    const { result } = renderHook(() => useProxySessions());

    await waitFor(() => {
      expect(listen).toHaveBeenCalled();
    });

    const sessionEvent: SessionEvent = {
      type: 'start',
      session: {
        id: 42,
        method: 'GET',
        scheme: 'http',
        host: 'test.com',
        path: '/test',
        url: 'http://test.com/test',
        status: 0,
        statusText: '',
        contentType: null,
        requestHeaders: [],
        responseHeaders: [],
        requestBody: null,
        responseBody: null,
        responseSize: null,
        duration: null,
        complete: false,
      },
    };

    await act(async () => {
      eventHandler?.({ payload: sessionEvent });
      await new Promise((resolve) => requestAnimationFrame(resolve));
    });

    expect(result.current.order).toContain(42);
  });

  it('should not duplicate session ID in order for non-start events', async () => {
    let eventHandler: ((event: any) => void) | undefined;

    vi.mocked(listen).mockImplementation((eventName, handler) => {
      eventHandler = handler;
      return Promise.resolve(() => {});
    });
    vi.mocked(invoke).mockResolvedValue('stopped');

    const { result } = renderHook(() => useProxySessions());

    await waitFor(() => {
      expect(listen).toHaveBeenCalled();
    });

    const startEvent: SessionEvent = {
      type: 'start',
      session: {
        id: 1,
        method: 'GET',
        scheme: 'https',
        host: 'example.com',
        path: '/',
        url: 'https://example.com/',
        status: 0,
        statusText: '',
        contentType: null,
        requestHeaders: [],
        responseHeaders: [],
        requestBody: null,
        responseBody: null,
        responseSize: null,
        duration: null,
        complete: false,
      },
    };

    const updateEvent: SessionEvent = {
      ...startEvent,
      type: 'update',
      session: { ...startEvent.session, status: 200 },
    };

    await act(async () => {
      eventHandler?.({ payload: startEvent });
      await new Promise((resolve) => requestAnimationFrame(resolve));
    });

    const orderLengthAfterStart = result.current.order.length;

    await act(async () => {
      eventHandler?.({ payload: updateEvent });
      await new Promise((resolve) => requestAnimationFrame(resolve));
    });

    expect(result.current.order.length).toBe(orderLengthAfterStart);
  });

  it('should clear sessions and order when clear is called', async () => {
    vi.mocked(listen).mockResolvedValue(() => {});
    vi.mocked(invoke).mockResolvedValue('stopped');

    const { result } = renderHook(() => useProxySessions());

    await act(async () => {
      result.current.clear();
    });

    expect(result.current.sessions.size).toBe(0);
    expect(result.current.order).toEqual([]);
  });

  it('should batch multiple events in single animation frame', async () => {
    let eventHandler: ((event: any) => void) | undefined;

    vi.mocked(listen).mockImplementation((eventName, handler) => {
      eventHandler = handler;
      return Promise.resolve(() => {});
    });
    vi.mocked(invoke).mockResolvedValue('stopped');

    const { result } = renderHook(() => useProxySessions());

    await waitFor(() => {
      expect(listen).toHaveBeenCalled();
    });

    const events: SessionEvent[] = [1, 2, 3].map((id) => ({
      type: 'start',
      session: {
        id,
        method: 'GET',
        scheme: 'https',
        host: 'example.com',
        path: '/',
        url: 'https://example.com/',
        status: 0,
        statusText: '',
        contentType: null,
        requestHeaders: [],
        responseHeaders: [],
        requestBody: null,
        responseBody: null,
        responseSize: null,
        duration: null,
        complete: false,
      },
    }));

    await act(async () => {
      events.forEach((event) => eventHandler?.({ payload: event }));
      await new Promise((resolve) => requestAnimationFrame(resolve));
    });

    expect(result.current.sessions.size).toBe(3);
    expect(result.current.order).toEqual([1, 2, 3]);
  });
});

describe('useWsMessages', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should initialize with empty messages map', () => {
    vi.mocked(listen).mockResolvedValue(() => {});

    const { result } = renderHook(() => useWsMessages());

    expect(result.current.messages.size).toBe(0);
  });

  it('should add WebSocket messages to the map', async () => {
    let eventHandler: ((event: any) => void) | undefined;

    vi.mocked(listen).mockImplementation((eventName, handler) => {
      eventHandler = handler;
      return Promise.resolve(() => {});
    });

    const { result } = renderHook(() => useWsMessages());

    await waitFor(() => {
      expect(listen).toHaveBeenCalled();
    });

    const wsEvent: WsMessageEvent = {
      message: {
        sessionId: 1,
        timestamp: 12345,
        direction: 'sent',
        data: 'Hello WebSocket',
        messageType: 'text',
      },
    };

    await act(async () => {
      eventHandler?.({ payload: wsEvent });
      await new Promise((resolve) => requestAnimationFrame(resolve));
    });

    const messages = result.current.messages.get(1);
    expect(messages).toBeDefined();
    expect(messages?.length).toBe(1);
    expect(messages?.[0].data).toBe('Hello WebSocket');
  });

  it('should batch multiple WebSocket messages in single animation frame', async () => {
    let eventHandler: ((event: any) => void) | undefined;

    vi.mocked(listen).mockImplementation((eventName, handler) => {
      eventHandler = handler;
      return Promise.resolve(() => {});
    });

    const { result } = renderHook(() => useWsMessages());

    await waitFor(() => {
      expect(listen).toHaveBeenCalled();
    });

    const events: WsMessageEvent[] = [1, 2, 3].map((i) => ({
      message: {
        sessionId: 1,
        timestamp: 12345 + i,
        direction: 'sent',
        data: `Message ${i}`,
        messageType: 'text',
      },
    }));

    await act(async () => {
      events.forEach((event) => eventHandler?.({ payload: event }));
      await new Promise((resolve) => requestAnimationFrame(resolve));
    });

    const messages = result.current.messages.get(1);
    expect(messages?.length).toBe(3);
  });

  it('should clear all messages when clear is called', async () => {
    vi.mocked(listen).mockResolvedValue(() => {});

    const { result } = renderHook(() => useWsMessages());

    await act(async () => {
      result.current.clear();
    });

    expect(result.current.messages.size).toBe(0);
  });

  it('should group messages by sessionId', async () => {
    let eventHandler: ((event: any) => void) | undefined;

    vi.mocked(listen).mockImplementation((eventName, handler) => {
      eventHandler = handler;
      return Promise.resolve(() => {});
    });

    const { result } = renderHook(() => useWsMessages());

    await waitFor(() => {
      expect(listen).toHaveBeenCalled();
    });

    const events: WsMessageEvent[] = [
      {
        message: {
          sessionId: 1,
          timestamp: 1,
          direction: 'sent',
          data: 'Session 1 Message 1',
          messageType: 'text',
        },
      },
      {
        message: {
          sessionId: 2,
          timestamp: 2,
          direction: 'sent',
          data: 'Session 2 Message 1',
          messageType: 'text',
        },
      },
      {
        message: {
          sessionId: 1,
          timestamp: 3,
          direction: 'received',
          data: 'Session 1 Message 2',
          messageType: 'text',
        },
      },
    ];

    await act(async () => {
      events.forEach((event) => eventHandler?.({ payload: event }));
      await new Promise((resolve) => requestAnimationFrame(resolve));
    });

    expect(result.current.messages.get(1)?.length).toBe(2);
    expect(result.current.messages.get(2)?.length).toBe(1);
  });
});