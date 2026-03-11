import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import BodyViewer from './BodyViewer';

// Mock CodeViewer component
vi.mock('./CodeViewer', () => ({
  default: ({ content, contentType }: { content: string; contentType: string }) => (
    <div data-testid="code-viewer">
      <div>Content: {content}</div>
      <div>Type: {contentType}</div>
    </div>
  ),
}));

describe('BodyViewer', () => {
  it('should render plain text body', () => {
    render(<BodyViewer body="Hello World" isJson={false} contentType="text/plain" />);

    expect(screen.getByText('Hello World')).toBeInTheDocument();
  });

  it('should render JSON content with CodeViewer', () => {
    const jsonBody = '{"key": "value"}';
    render(<BodyViewer body={jsonBody} isJson={true} contentType="application/json" />);

    expect(screen.getByTestId('code-viewer')).toBeInTheDocument();
    expect(screen.getByText(/Content:/)).toBeInTheDocument();
  });

  it('should render HTML content with CodeViewer', () => {
    const htmlBody = '<html><body>Test</body></html>';
    render(<BodyViewer body={htmlBody} isJson={false} contentType="text/html" />);

    expect(screen.getByTestId('code-viewer')).toBeInTheDocument();
  });

  it('should render base64 image', () => {
    const base64Body = '__BASE64__:image/png:iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
    render(<BodyViewer body={base64Body} isJson={false} contentType="image/png" />);

    const img = screen.getByRole('img');
    expect(img).toBeInTheDocument();
    expect(img).toHaveAttribute('src', expect.stringContaining('data:image/png;base64,'));
  });

  it('should display image dimensions when image loads', () => {
    const base64Body = '__BASE64__:image/jpeg:base64data';
    render(<BodyViewer body={base64Body} isJson={false} contentType="image/jpeg" />);

    const img = screen.getByRole('img');

    // Simulate image load
    fireEvent.load(img);

    // After load, dimensions should be displayed (mocked dimensions)
  });

  it('should render video element for video content', () => {
    const base64Body = '__BASE64__:video/mp4:mockbase64videodata';
    render(<BodyViewer body={base64Body} isJson={false} contentType="video/mp4" />);

    const video = screen.getByRole('video');
    expect(video).toBeInTheDocument();
    expect(video).toHaveAttribute('controls');
  });

  it('should render audio element for audio content', () => {
    const base64Body = '__BASE64__:audio/mp3:mockbase64audiodata';
    render(<BodyViewer body={base64Body} isJson={false} contentType="audio/mp3" />);

    const audio = document.querySelector('audio');
    expect(audio).toBeInTheDocument();
    expect(audio).toHaveAttribute('controls');
  });

  it('should render hex dump for binary content', () => {
    const hexBody = '__HEX__:1024:48656c6c6f576f726c64';
    render(<BodyViewer body={hexBody} isJson={false} contentType="application/octet-stream" />);

    expect(screen.getByText('Binary Preview')).toBeInTheDocument();
    expect(screen.getByText('1024')).toBeInTheDocument();
  });

  it('should display formatted bytes size', () => {
    const base64Body = '__BASE64__:image/png:' + 'A'.repeat(1000);
    render(<BodyViewer body={base64Body} isJson={false} contentType="image/png" />);

    // Should display size in appropriate format (Bytes, KiB, etc.)
    expect(screen.getByText(/Bytes|KiB|MB/)).toBeInTheDocument();
  });

  it('should render copy button for plain text', () => {
    render(<BodyViewer body="Test content" isJson={false} contentType="text/plain" />);

    const copyButton = screen.getByRole('button', { name: /copy body/i });
    expect(copyButton).toBeInTheDocument();
  });

  it('should copy text to clipboard when copy button is clicked', async () => {
    const writeTextMock = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, {
      clipboard: {
        writeText: writeTextMock,
      },
    });

    render(<BodyViewer body="Test content" isJson={false} contentType="text/plain" />);

    const copyButton = screen.getByRole('button', { name: /copy body/i });
    fireEvent.click(copyButton);

    expect(writeTextMock).toHaveBeenCalledWith('Test content');
  });

  it('should render JavaScript content with CodeViewer', () => {
    const jsBody = 'function test() { return true; }';
    render(<BodyViewer body={jsBody} isJson={false} contentType="text/javascript" />);

    expect(screen.getByTestId('code-viewer')).toBeInTheDocument();
  });

  it('should render XML content with CodeViewer', () => {
    const xmlBody = '<?xml version="1.0"?><root></root>';
    render(<BodyViewer body={xmlBody} isJson={false} contentType="application/xml" />);

    expect(screen.getByTestId('code-viewer')).toBeInTheDocument();
  });

  it('should handle empty body gracefully', () => {
    render(<BodyViewer body="" isJson={false} contentType="" />);

    expect(screen.getByText('')).toBeInTheDocument();
  });

  it('should handle malformed base64 data', () => {
    const malformedBody = '__BASE64__:malformed';
    render(<BodyViewer body={malformedBody} isJson={false} contentType="" />);

    // Should render without crashing
    expect(screen.getByRole('button', { name: /copy body/i })).toBeInTheDocument();
  });

  it('should handle malformed hex data', () => {
    const malformedBody = '__HEX__:malformed';
    render(<BodyViewer body={malformedBody} isJson={false} contentType="" />);

    // Should render without crashing
    expect(screen.getByRole('button', { name: /copy body/i })).toBeInTheDocument();
  });

  it('should show hex dump with proper formatting', () => {
    // Create a hex string representing "Hello World"
    const hexBody = '__HEX__:11:48656c6c6f20576f726c64';
    render(<BodyViewer body={hexBody} isJson={false} contentType="" />);

    expect(screen.getByText('Binary Preview')).toBeInTheDocument();
    // Should display hex values and ASCII representation
    expect(screen.getByText(/48 65 6c 6c 6f/)).toBeInTheDocument();
  });

  it('should truncate large hex dumps', () => {
    // Create a large hex string (>10KB)
    const largeHex = 'FF'.repeat(6000);
    const hexBody = `__HEX__:12000:${largeHex}`;
    render(<BodyViewer body={hexBody} isJson={false} contentType="" />);

    expect(screen.getByText(/Preview truncated at 10KB/i)).toBeInTheDocument();
  });

  it('should render context menu for plain text body', () => {
    render(<BodyViewer body="Test" isJson={false} contentType="text/plain" />);

    const bodyElement = screen.getByText('Test');
    fireEvent.contextMenu(bodyElement);

    expect(screen.getByText(/Copy Full Body/i)).toBeInTheDocument();
  });

  it('should format bytes correctly', () => {
    const base64Body = '__BASE64__:image/png:' + 'A'.repeat(2048);
    render(<BodyViewer body={base64Body} isJson={false} contentType="image/png" />);

    // Should show size in KiB for ~1.5 KB
    const sizeText = screen.getByText(/KiB/);
    expect(sizeText).toBeInTheDocument();
  });

  it('should use CodeViewer for JSON even when isJson is false but contentType includes json', () => {
    const jsonBody = '{"test": true}';
    render(<BodyViewer body={jsonBody} isJson={false} contentType="application/json" />);

    expect(screen.getByTestId('code-viewer')).toBeInTheDocument();
  });

  it('should handle various base64 image formats', () => {
    const formats = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];

    formats.forEach((format) => {
      const { unmount } = render(
        <BodyViewer body={`__BASE64__:${format}:data`} isJson={false} contentType={format} />
      );

      expect(screen.getByRole('img')).toBeInTheDocument();
      unmount();
    });
  });

  it('should handle various video formats', () => {
    const formats = ['video/mp4', 'video/webm', 'video/ogg'];

    formats.forEach((format) => {
      const { unmount } = render(
        <BodyViewer body={`__BASE64__:${format}:data`} isJson={false} contentType={format} />
      );

      expect(screen.getByRole('video')).toBeInTheDocument();
      unmount();
    });
  });

  it('should handle various audio formats', () => {
    const formats = ['audio/mp3', 'audio/wav', 'audio/ogg'];

    formats.forEach((format) => {
      const { unmount } = render(
        <BodyViewer body={`__BASE64__:${format}:data`} isJson={false} contentType={format} />
      );

      const audio = document.querySelector('audio');
      expect(audio).toBeInTheDocument();
      unmount();
    });
  });
});