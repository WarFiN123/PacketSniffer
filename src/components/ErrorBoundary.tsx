import { Component, type ReactNode } from "react";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
  /** When this value changes, any caught error is cleared and the children
   *  re-render. Prefer this over a `key` remount when the children hold state
   *  worth keeping across the reset (e.g. the detail panel's active tab). */
  resetKey?: unknown;
}
interface State {
  error: Error | null;
  prevResetKey: unknown;
}

/** Contains render crashes (e.g. body viewers) so one panel failing doesn't
 *  blank the whole window. Recovers when `resetKey` changes. */
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, prevResetKey: this.props.resetKey };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  static getDerivedStateFromProps(
    props: Props,
    state: State,
  ): Partial<State> | null {
    // A new selection clears a prior crash without unmounting the subtree,
    // so the children keep their state.
    if (props.resetKey !== state.prevResetKey) {
      return { error: null, prevResetKey: props.resetKey };
    }
    return null;
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
