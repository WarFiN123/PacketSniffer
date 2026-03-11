import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useTheme } from './useTheme';

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {};

  return {
    getItem: (key: string) => store[key] || null,
    setItem: (key: string, value: string) => {
      store[key] = value;
    },
    removeItem: (key: string) => {
      delete store[key];
    },
    clear: () => {
      store = {};
    },
  };
})();

describe('useTheme', () => {
  beforeEach(() => {
    Object.defineProperty(window, 'localStorage', {
      value: localStorageMock,
      writable: true,
    });
    localStorageMock.clear();
    document.documentElement.className = '';
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should return default theme as "system"', () => {
    const { result } = renderHook(() => useTheme());
    expect(result.current.theme).toBe('system');
  });

  it('should apply dark class when theme is "dark"', () => {
    const { result } = renderHook(() => useTheme());

    act(() => {
      result.current.setTheme('dark');
    });

    expect(document.documentElement.classList.contains('dark')).toBe(true);
    expect(result.current.theme).toBe('dark');
  });

  it('should remove dark class when theme is "light"', () => {
    document.documentElement.classList.add('dark');
    const { result } = renderHook(() => useTheme());

    act(() => {
      result.current.setTheme('light');
    });

    expect(document.documentElement.classList.contains('dark')).toBe(false);
    expect(result.current.theme).toBe('light');
  });

  it('should save theme to localStorage', () => {
    const { result } = renderHook(() => useTheme());

    act(() => {
      result.current.setTheme('dark');
    });

    expect(localStorage.getItem('packetsniffer-theme')).toBe('dark');
  });

  it('should load theme from localStorage on mount', () => {
    localStorage.setItem('packetsniffer-theme', 'light');
    const { result } = renderHook(() => useTheme());

    expect(result.current.theme).toBe('light');
  });

  it('should handle "system" theme based on media query', () => {
    const mediaQueryList = {
      matches: true,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    };

    vi.spyOn(window, 'matchMedia').mockReturnValue(mediaQueryList as any);

    const { result } = renderHook(() => useTheme());

    act(() => {
      result.current.setTheme('system');
    });

    // When system prefers dark
    expect(document.documentElement.classList.contains('dark')).toBe(true);
  });

  it('should handle system theme when prefers light', () => {
    const mediaQueryList = {
      matches: false,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    };

    vi.spyOn(window, 'matchMedia').mockReturnValue(mediaQueryList as any);

    const { result } = renderHook(() => useTheme());

    act(() => {
      result.current.setTheme('system');
    });

    // When system prefers light
    expect(document.documentElement.classList.contains('dark')).toBe(false);
  });

  it('should return correct isDark value for dark theme', () => {
    const { result } = renderHook(() => useTheme());

    act(() => {
      result.current.setTheme('dark');
    });

    expect(result.current.isDark).toBe(true);
  });

  it('should return correct isDark value for light theme', () => {
    const { result } = renderHook(() => useTheme());

    act(() => {
      result.current.setTheme('light');
    });

    expect(result.current.isDark).toBe(false);
  });

  it('should listen for system theme changes when set to system', () => {
    const addEventListener = vi.fn();
    const removeEventListener = vi.fn();
    const mediaQueryList = {
      matches: false,
      addEventListener,
      removeEventListener,
    };

    vi.spyOn(window, 'matchMedia').mockReturnValue(mediaQueryList as any);

    const { unmount } = renderHook(() => useTheme());

    expect(addEventListener).toHaveBeenCalledWith('change', expect.any(Function));

    unmount();

    expect(removeEventListener).toHaveBeenCalledWith('change', expect.any(Function));
  });

  it('should handle localStorage errors gracefully', () => {
    const mockSetItem = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('QuotaExceededError');
    });

    const { result } = renderHook(() => useTheme());

    act(() => {
      result.current.setTheme('dark');
    });

    // Should not throw error
    expect(result.current.theme).toBe('dark');

    mockSetItem.mockRestore();
  });

  it('should handle invalid localStorage values', () => {
    localStorage.setItem('packetsniffer-theme', 'invalid-theme');
    const { result } = renderHook(() => useTheme());

    // Should fall back to default "system"
    expect(result.current.theme).toBe('system');
  });

  it('should switch between all theme values correctly', () => {
    const { result } = renderHook(() => useTheme());

    act(() => {
      result.current.setTheme('light');
    });
    expect(result.current.theme).toBe('light');

    act(() => {
      result.current.setTheme('dark');
    });
    expect(result.current.theme).toBe('dark');

    act(() => {
      result.current.setTheme('system');
    });
    expect(result.current.theme).toBe('system');
  });

  it('should persist theme changes across hook re-renders', () => {
    const { result, rerender } = renderHook(() => useTheme());

    act(() => {
      result.current.setTheme('dark');
    });

    rerender();

    expect(result.current.theme).toBe('dark');
    expect(localStorage.getItem('packetsniffer-theme')).toBe('dark');
  });
});