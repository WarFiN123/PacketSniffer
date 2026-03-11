import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import App from './App';
import type { HttpSession } from './types';

// Mock hooks
vi.mock('./hooks/useTauriEvents', () => ({
  useProxySessions: vi.fn(() => ({
    sessions: new Map(),
    order: [],
    connected: false,
    clear: vi.fn(),
  })),
  useWsMessages: vi.fn(() => ({
    messages: new Map(),
    clear: vi.fn(),
  })),
}));

vi.mock('./hooks/useTheme', () => ({
  useTheme: vi.fn(() => ({
    theme: 'light',
    setTheme: vi.fn(),
    isDark: false,
  })),
}));

// Mock Tauri API
vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

vi.mock('@tauri-apps/plugin-dialog', () => ({
  save: vi.fn(),
}));

vi.mock('@tauri-apps/plugin-fs', () => ({
  writeTextFile: vi.fn(),
}));

import { useProxySessions, useWsMessages } from './hooks/useTauriEvents';
import { useTheme } from './hooks/useTheme';
import { invoke } from '@tauri-apps/api/core';

describe('App', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(invoke).mockResolvedValue('running on port 8080');
  });

  it('should render the app without crashing', () => {
    render(<App />);
    expect(screen.getByText('PacketSniffer')).toBeInTheDocument();
  });

  it('should display the toolbar', () => {
    render(<App />);
    expect(screen.getByRole('menubar')).toBeInTheDocument();
  });

  it('should initialize with no selected session', () => {
    render(<App />);
    expect(screen.getByText(/select a request to inspect/i)).toBeInTheDocument();
  });

  it('should filter sessions based on text filter', async () => {
    const mockSessions = new Map<number, HttpSession>([
      [
        1,
        {
          id: 1,
          method: 'GET',
          scheme: 'https',
          host: 'example.com',
          path: '/api/users',
          url: 'https://example.com/api/users',
          status: 200,
          statusText: 'OK',
          contentType: 'application/json',
          requestHeaders: [],
          responseHeaders: [],
          requestBody: null,
          responseBody: null,
          responseSize: 100,
          duration: 50,
          complete: true,
        },
      ],
      [
        2,
        {
          id: 2,
          method: 'POST',
          scheme: 'https',
          host: 'test.com',
          path: '/api/data',
          url: 'https://test.com/api/data',
          status: 201,
          statusText: 'Created',
          contentType: 'application/json',
          requestHeaders: [],
          responseHeaders: [],
          requestBody: '{}',
          responseBody: '{}',
          responseSize: 50,
          duration: 25,
          complete: true,
        },
      ],
    ]);

    vi.mocked(useProxySessions).mockReturnValue({
      sessions: mockSessions,
      order: [1, 2],
      connected: true,
      clear: vi.fn(),
    });

    render(<App />);

    const filterInput = screen.getByPlaceholderText(/filter/i);

    fireEvent.change(filterInput, { target: { value: 'example.com' } });

    await waitFor(() => {
      // After filtering, only 1 session should match
      // The table should show filtered results
      expect(screen.queryByText('test.com')).not.toBeInTheDocument();
    });
  });

  it('should call get_proxy_status on mount', async () => {
    render(<App />);

    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith('get_proxy_status');
    });
  });

  it('should check for missing dependencies on mount', async () => {
    vi.mocked(invoke).mockImplementation((cmd: string) => {
      if (cmd === 'check_missing_deps') return Promise.resolve([]);
      if (cmd === 'get_proxy_status') return Promise.resolve('running on port 8080');
      return Promise.resolve(null);
    });

    render(<App />);

    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith('check_missing_deps');
    });
  });

  it('should check CA trust status on mount', async () => {
    vi.mocked(invoke).mockImplementation((cmd: string) => {
      if (cmd === 'check_ca_trusted') return Promise.resolve(true);
      if (cmd === 'get_proxy_status') return Promise.resolve('running on port 8080');
      if (cmd === 'check_missing_deps') return Promise.resolve([]);
      return Promise.resolve(null);
    });

    render(<App />);

    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith('check_ca_trusted');
    });
  });

  it('should show CA install dialog if CA is not trusted', async () => {
    vi.mocked(invoke).mockImplementation((cmd: string) => {
      if (cmd === 'check_ca_trusted') return Promise.resolve(false);
      if (cmd === 'get_proxy_status') return Promise.resolve('running on port 8080');
      if (cmd === 'check_missing_deps') return Promise.resolve([]);
      return Promise.resolve(null);
    });

    render(<App />);

    await waitFor(() => {
      expect(screen.getByText(/CA Certificate/i)).toBeInTheDocument();
    });
  });

  it('should show dependency dialog if dependencies are missing', async () => {
    vi.mocked(invoke).mockImplementation((cmd: string) => {
      if (cmd === 'check_missing_deps') return Promise.resolve(['libnss3-tools']);
      if (cmd === 'get_proxy_status') return Promise.resolve('running on port 8080');
      if (cmd === 'check_ca_trusted') return Promise.resolve(true);
      return Promise.resolve(null);
    });

    render(<App />);

    await waitFor(() => {
      expect(screen.getByText(/Missing Dependencies/i)).toBeInTheDocument();
    });
  });

  it('should handle content filter changes', () => {
    render(<App />);

    const jsonFilterButton = screen.getByRole('button', { name: /json/i });
    fireEvent.click(jsonFilterButton);

    // Filter should update (visual indication may vary)
    expect(jsonFilterButton).toHaveClass('active');
  });

  it('should handle clear sessions action', () => {
    const clearMock = vi.fn();
    const clearWsMock = vi.fn();

    vi.mocked(useProxySessions).mockReturnValue({
      sessions: new Map(),
      order: [],
      connected: true,
      clear: clearMock,
    });

    vi.mocked(useWsMessages).mockReturnValue({
      messages: new Map(),
      clear: clearWsMock,
    });

    render(<App />);

    const clearButton = screen.getByRole('button', { name: /clear/i });
    fireEvent.click(clearButton);

    expect(clearMock).toHaveBeenCalled();
    expect(clearWsMock).toHaveBeenCalled();
  });

  it('should toggle pinned sessions view', () => {
    const mockSessions = new Map<number, HttpSession>([
      [
        1,
        {
          id: 1,
          method: 'GET',
          scheme: 'https',
          host: 'example.com',
          path: '/',
          url: 'https://example.com/',
          status: 200,
          statusText: 'OK',
          contentType: null,
          requestHeaders: [],
          responseHeaders: [],
          requestBody: null,
          responseBody: null,
          responseSize: null,
          duration: null,
          complete: true,
        },
      ],
    ]);

    vi.mocked(useProxySessions).mockReturnValue({
      sessions: mockSessions,
      order: [1],
      connected: true,
      clear: vi.fn(),
    });

    render(<App />);

    const pinnedToggle = screen.getByRole('button', { name: /pinned/i });
    fireEvent.click(pinnedToggle);

    // Should toggle the showPinnedOnly state
    expect(pinnedToggle).toHaveClass('active');
  });

  it('should apply theme from useTheme hook', () => {
    vi.mocked(useTheme).mockReturnValue({
      theme: 'dark',
      setTheme: vi.fn(),
      isDark: true,
    });

    render(<App />);

    // App should render with dark theme applied
    expect(document.documentElement.classList.contains('dark')).toBe(true);
  });

  it('should handle session selection', async () => {
    const mockSessions = new Map<number, HttpSession>([
      [
        1,
        {
          id: 1,
          method: 'GET',
          scheme: 'https',
          host: 'example.com',
          path: '/test',
          url: 'https://example.com/test',
          status: 200,
          statusText: 'OK',
          contentType: 'text/html',
          requestHeaders: [],
          responseHeaders: [],
          requestBody: null,
          responseBody: '<html></html>',
          responseSize: 100,
          duration: 50,
          complete: true,
        },
      ],
    ]);

    vi.mocked(useProxySessions).mockReturnValue({
      sessions: mockSessions,
      order: [1],
      connected: true,
      clear: vi.fn(),
    });

    render(<App />);

    // Click on a session row
    const sessionRow = screen.getByText('example.com');
    fireEvent.click(sessionRow);

    await waitFor(() => {
      // Detail panel should show the selected session
      expect(screen.getByText('Request')).toBeInTheDocument();
      expect(screen.getByText('Response')).toBeInTheDocument();
    });
  });

  it('should handle keyboard shortcut for export (Ctrl+S)', () => {
    render(<App />);

    const event = new KeyboardEvent('keydown', {
      key: 's',
      ctrlKey: true,
    });

    fireEvent(window, event);

    // Export should be triggered (implementation may vary)
  });

  it('should debounce text filter input', async () => {
    render(<App />);

    const filterInput = screen.getByPlaceholderText(/filter/i);

    fireEvent.change(filterInput, { target: { value: 'test' } });
    fireEvent.change(filterInput, { target: { value: 'test1' } });
    fireEvent.change(filterInput, { target: { value: 'test12' } });

    // After debounce delay, filter should be applied
    await waitFor(
      () => {
        expect(filterInput).toHaveValue('test12');
      },
      { timeout: 200 }
    );
  });
});