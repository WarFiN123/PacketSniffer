import { Component, type ReactNode } from "react";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}
interface State {
  error: Error | null;
}

/** Contains render crashes (e.g. body viewers) so one panel failing doesn't
 *  blank the whole window. Reset by changing the `key` prop. */
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: unknown) {
    console.error("ErrorBoundary caught:", error, info);
  }

  render() {
    if (this.state.error) {
      return (
        this.props.fallback ?? (
          <div className="h-full w-full flex flex-col items-center justify-center gap-1 bg-background text-xs text-muted-foreground p-4 text-center">
            <span className="text-destructive font-medium">
              Failed to render this view.
            </span>
            <span className="font-mono text-[10px] break-all">
              {this.state.error.message}
            </span>
          </div>
        )
      );
    }
    return this.props.children;
  }
}
