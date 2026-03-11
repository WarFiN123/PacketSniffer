# Testing Documentation

This document describes the test setup and how to run tests for the PacketSniffer project.

## Overview

The project includes comprehensive test coverage for both the Rust backend and TypeScript frontend:

- **Rust Tests**: Unit tests for certificate management, system proxy configuration, and CA generation
- **TypeScript Tests**: Unit tests for React hooks and components

## Test Files

### Rust Tests

Tests are located inline with the source code using Rust's `#[cfg(test)]` attribute:

- `src-tauri/src/cert_store.rs` - Certificate store integration tests
- `src-tauri/src/system_proxy.rs` - System proxy configuration tests
- `src-tauri/src/proxy/ca.rs` - Certificate authority tests
- `src-tauri/src/lib.rs` - Tauri command and event tests

### TypeScript Tests

Test files are located alongside their source files with `.test.ts` or `.test.tsx` extension:

- `src/hooks/useTheme.test.ts` - Theme hook tests
- `src/hooks/useTauriEvents.test.ts` - Tauri event hooks tests
- `src/App.test.tsx` - Main application component tests
- `src/components/BodyViewer.test.tsx` - Body viewer component tests

## Prerequisites

### For Rust Tests

- Rust toolchain (rustc + cargo)
- All dependencies from `Cargo.toml`

### For TypeScript Tests

You need to add the following dependencies to `package.json`:

```json
{
  "devDependencies": {
    "vitest": "^2.0.0",
    "@testing-library/react": "^16.0.0",
    "@testing-library/user-event": "^14.5.0",
    "@vitest/ui": "^2.0.0",
    "jsdom": "^25.0.0"
  }
}
```

Install them with:

```bash
bun add -D vitest @testing-library/react @testing-library/user-event @vitest/ui jsdom
```

Then add a `vitest.config.ts` file:

```typescript
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
});
```

Create a test setup file at `src/test/setup.ts`:

```typescript
import '@testing-library/jest-dom';

// Mock matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => true,
  }),
});
```

Add test scripts to `package.json`:

```json
{
  "scripts": {
    "test": "vitest",
    "test:ui": "vitest --ui",
    "test:coverage": "vitest --coverage"
  }
}
```

## Running Tests

### Rust Tests

To run all Rust tests:

```bash
cd src-tauri
cargo test
```

To run tests for a specific module:

```bash
cargo test --lib cert_store
cargo test --lib system_proxy
cargo test --lib ca
```

To run tests with output:

```bash
cargo test -- --nocapture
```

### TypeScript Tests

To run all TypeScript tests:

```bash
bun test
```

To run tests in watch mode:

```bash
bun test --watch
```

To run tests with UI:

```bash
bun test:ui
```

To run tests with coverage:

```bash
bun test:coverage
```

To run a specific test file:

```bash
bun test src/hooks/useTheme.test.ts
```

## Test Coverage

### Rust Backend

The Rust tests cover:

- **cert_store.rs**:
  - Dependency checking (platform-specific)
  - Package installation
  - CA trust verification
  - Error handling and edge cases

- **system_proxy.rs**:
  - Proxy enable/disable functionality
  - Registry operations (Windows)
  - Network service configuration (macOS)
  - gsettings operations (Linux)
  - State management

- **ca.rs**:
  - CA initialization and generation
  - Certificate caching
  - Version checking and regeneration
  - Server config generation for different hosts
  - ALPN protocol configuration

- **lib.rs**:
  - Event serialization
  - State management
  - Data structures

### TypeScript Frontend

The TypeScript tests cover:

- **useTheme hook**:
  - Theme switching (light/dark/system)
  - localStorage persistence
  - System theme detection
  - Media query listening
  - Error handling

- **useTauriEvents hook**:
  - Event batching
  - Session management
  - WebSocket message handling
  - State clearing

- **App component**:
  - Component rendering
  - Session filtering
  - CA trust checking
  - Dependency checking
  - User interactions

- **BodyViewer component**:
  - Text rendering
  - Code syntax highlighting
  - Base64 image/video/audio display
  - Hex dump formatting
  - Copy functionality

## Writing New Tests

### Rust Test Example

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_name() {
        // Arrange
        let input = "test";

        // Act
        let result = my_function(input);

        // Assert
        assert_eq!(result, expected_value);
    }

    #[tokio::test]
    async fn test_async_function() {
        // For async tests
        let result = async_function().await;
        assert!(result.is_ok());
    }
}
```

### TypeScript Test Example

```typescript
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import MyComponent from './MyComponent';

describe('MyComponent', () => {
  it('should render correctly', () => {
    render(<MyComponent />);
    expect(screen.getByText('Hello')).toBeInTheDocument();
  });

  it('should handle click events', () => {
    render(<MyComponent />);
    const button = screen.getByRole('button');
    fireEvent.click(button);
    expect(screen.getByText('Clicked')).toBeInTheDocument();
  });
});
```

## Continuous Integration

To run tests in CI, add these commands to your GitHub Actions workflow:

```yaml
- name: Run Rust tests
  run: |
    cd src-tauri
    cargo test

- name: Run TypeScript tests
  run: |
    bun install
    bun test --run
```

## Troubleshooting

### Rust Tests

- If tests fail due to missing system dependencies, install the required packages for your platform
- Platform-specific tests may only run on their target OS
- Some tests require elevated privileges and may be skipped in CI

### TypeScript Tests

- Ensure all dev dependencies are installed: `bun install`
- If tests fail with import errors, check the path aliases in `vitest.config.ts`
- Mock Tauri APIs are required for component tests
- Some tests may require specific browser APIs to be mocked

## Best Practices

1. **Rust Tests**:
   - Use `#[cfg(test)]` for test modules
   - Use `#[tokio::test]` for async tests
   - Clean up resources (files, directories) after tests
   - Use platform-specific attributes (`#[cfg(target_os = "...")]`) when needed

2. **TypeScript Tests**:
   - Follow AAA pattern (Arrange, Act, Assert)
   - Use `describe` blocks to group related tests
   - Mock external dependencies (Tauri APIs, browser APIs)
   - Test user interactions, not implementation details
   - Use `waitFor` for async assertions

3. **General**:
   - Write tests for new features
   - Update tests when modifying existing code
   - Aim for high coverage but prioritize critical paths
   - Test edge cases and error conditions
   - Keep tests focused and independent