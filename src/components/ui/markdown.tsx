import type { ReactNode } from "react";

// Tiny, dependency-free Markdown renderer for the common release-note subset:
// headings, bullet/ordered lists, paragraphs, horizontal rules, and inline
// bold / italic / code / links. It builds React nodes (never raw HTML), so
// untrusted note text can't inject markup. Anything it doesn't recognize falls
// back to its literal text — no crash, no escape hatch.

/** Allow only http(s) links; everything else renders as literal text. */
function safeHref(url: string): string | null {
  const u = url.trim();
  return /^https?:\/\//i.test(u) ? u : null;
}

const INLINE_SRC =
  "(`[^`]+`)|(\\*\\*.+?\\*\\*|__.+?__)|(\\*.+?\\*|_.+?_)|\\[([^\\]]+)\\]\\(([^)]+)\\)";

/** Render inline spans (bold/italic/code/links) within a run of text. `inline`
 *  recurses into bold/italic bodies, so each call gets its OWN regex — a shared
 *  one's `lastIndex` would be clobbered by the nested scan. */
function inline(text: string, key: string): ReactNode[] {
  const re = new RegExp(INLINE_SRC, "g");
  const out: ReactNode[] = [];
  let last = 0;
  let n = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const k = `${key}-${n++}`;
    if (m[1]) {
      out.push(
        <code
          key={k}
          className="rounded bg-bg-2 px-1 py-0.5 font-mono text-[10px] text-text-0"
        >
          {m[1].slice(1, -1)}
        </code>,
      );
    } else if (m[2]) {
      out.push(
        <strong key={k} className="font-semibold text-text-0">
          {inline(m[2].slice(2, -2), k)}
        </strong>,
      );
    } else if (m[3]) {
      out.push(
        <em key={k} className="italic">
          {inline(m[3].slice(1, -1), k)}
        </em>,
      );
    } else if (m[4] !== undefined) {
      const href = safeHref(m[5]);
      out.push(
        href ? (
          <a
            key={k}
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            className="underline underline-offset-2 hover:text-text-0"
          >
            {m[4]}
          </a>
        ) : (
          `[${m[4]}](${m[5]})`
        ),
      );
    }
    last = re.lastIndex;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

const LIST_ITEM = /^([-*+]\s+|\d+\.\s+)/;

export default function Markdown({ source }: { source: string }) {
  const lines = source.replace(/\r\n/g, "\n").split("\n");
  const blocks: ReactNode[] = [];
  let para: string[] = [];

  const flushPara = () => {
    if (para.length) {
      const key = `b${blocks.length}`;
      blocks.push(
        <p key={key} className="text-[11px] leading-relaxed text-text-1">
          {inline(para.join(" "), key)}
        </p>,
      );
      para = [];
    }
  };

  let i = 0;
  while (i < lines.length) {
    const t = lines[i].trim();

    if (t === "") {
      flushPara();
      i++;
      continue;
    }

    // Horizontal rule
    if (/^(-{3,}|\*{3,}|_{3,})$/.test(t)) {
      flushPara();
      blocks.push(<hr key={`b${blocks.length}`} className="border-border/60" />);
      i++;
      continue;
    }

    // Heading
    const h = /^(#{1,6})\s+(.*)$/.exec(t);
    if (h) {
      flushPara();
      const key = `b${blocks.length}`;
      const big = h[1].length <= 2;
      blocks.push(
        <p
          key={key}
          className={
            big
              ? "text-[13px] font-semibold text-text-0"
              : "text-[12px] font-semibold text-text-1"
          }
        >
          {inline(h[2], key)}
        </p>,
      );
      i++;
      continue;
    }

    // List — gather consecutive item lines; wrapper type from the first item.
    if (LIST_ITEM.test(t)) {
      flushPara();
      const ordered = /^\d+\.\s+/.test(t);
      const items: string[] = [];
      while (i < lines.length && LIST_ITEM.test(lines[i].trim())) {
        items.push(lines[i].trim().replace(LIST_ITEM, ""));
        i++;
      }
      const key = `b${blocks.length}`;
      const cls =
        "space-y-0.5 pl-4 text-[11px] leading-relaxed text-text-1 " +
        (ordered ? "list-decimal" : "list-disc");
      blocks.push(
        ordered ? (
          <ol key={key} className={cls}>
            {items.map((it, j) => (
              <li key={j} className="marker:text-muted-foreground">
                {inline(it, `${key}-${j}`)}
              </li>
            ))}
          </ol>
        ) : (
          <ul key={key} className={cls}>
            {items.map((it, j) => (
              <li key={j} className="marker:text-muted-foreground">
                {inline(it, `${key}-${j}`)}
              </li>
            ))}
          </ul>
        ),
      );
      continue;
    }

    // Plain paragraph line
    para.push(t);
    i++;
  }
  flushPara();

  return <div className="space-y-2">{blocks}</div>;
}
