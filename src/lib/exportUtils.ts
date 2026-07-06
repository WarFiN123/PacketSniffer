import { invoke } from "@tauri-apps/api/core";
import { save, message } from "@tauri-apps/plugin-dialog";
import { writeTextFile } from "@tauri-apps/plugin-fs";
import type { HttpSession } from "@/types";

export function parseQueryParams(path: string): [string, string][] {
  const qIdx = path.indexOf("?");
  if (qIdx === -1) return [];
  try {
    const params = new URLSearchParams(path.slice(qIdx + 1));
    return [...params.entries()];
  } catch {
    return [];
  }
}

export function getFullUrl(session: HttpSession): string {
  return session.url.startsWith("http") || session.url.startsWith("ws")
    ? session.url
    : `${session.scheme}://${session.host}${session.path}`;
}

/** Escape a value for a single-quoted bash-style cURL argument. */
function shQuote(s: string): string {
  return s.replace(/'/g, "'\\''");
}

/**
 * Build a cURL command equivalent to the captured request. Postman parses
 * cURL on paste (into a request's URL bar), which is the only mechanism that
 * reliably loads a request into current Postman — its deep-link import no
 * longer accepts local files or arbitrary collection URLs.
 */
export function buildCurl(session: HttpSession): string {
  const url = getFullUrl(session);
  const method = (session.method || "GET").toUpperCase();

  let head = "curl --location";
  if (method !== "GET") head += ` --request ${method}`;
  head += ` '${shQuote(url)}'`;

  const parts = [head];
  for (const h of session.requestHeaders) {
    // Drop HTTP/2 pseudo-headers and headers cURL/Postman recompute themselves.
    const lname = h.name.toLowerCase();
    if (h.name.startsWith(":") || lname === "content-length" || lname === "host") continue;
    parts.push(`--header '${shQuote(h.name)}: ${shQuote(h.value)}'`);
  }
  if (session.requestBody) {
    parts.push(`--data-raw '${shQuote(session.requestBody)}'`);
  }
  return parts.join(" \\\n  ");
}

export async function exportToPostman(session: HttpSession) {
  const curl = buildCurl(session);
  try {
    await navigator.clipboard.writeText(curl);
    await invoke("open_in_postman");
    const paste = navigator.userAgent.includes("Mac") ? "⌘V" : "Ctrl+V";
    await message(
      `Request copied as cURL.\n\nIn Postman, click a new request's URL bar and press ${paste} — it expands into the full request (method, headers, body).`,
      { title: "Open in Postman", kind: "info" },
    );
  } catch (e) {
    console.error("Failed to open in Postman", e);
  }
}

export function getRawRequest(session: HttpSession): string {
  const lines = [`${session.method} ${session.path} ${session.httpVersion}`, `Host: ${session.host}`];
  session.requestHeaders.forEach(h => lines.push(`${h.name}: ${h.value}`));
  if (session.requestBody) {
    lines.push("");
    lines.push(session.requestBody);
  }
  return lines.join("\n");
}

export function getRawResponse(session: HttpSession): string {
  const lines = [`${session.httpVersion} ${session.status} ${session.statusText}`];
  session.responseHeaders.forEach(h => lines.push(`${h.name}: ${h.value}`));
  if (session.responseBody) {
    lines.push("");
    lines.push(session.responseBody);
  }
  return lines.join("\n");
}

export async function exportResponse(session: HttpSession) {
  try {
    const path = await save({
      defaultPath: `response_${session.host.replace(/[^a-z0-9]/gi, "_")}.txt`,
      filters: [{ name: "Text", extensions: ["txt"] }, { name: "All Files", extensions: ["*"] }],
    });
    if (path) {
      await writeTextFile(path, getRawResponse(session));
    }
  } catch (e) {
    console.error("Failed to export response", e);
  }
}

export async function exportRequest(session: HttpSession) {
  try {
    const path = await save({
      defaultPath: `request_${session.host.replace(/[^a-z0-9]/gi, "_")}.txt`,
      filters: [{ name: "Text", extensions: ["txt"] }, { name: "All Files", extensions: ["*"] }],
    });
    if (path) {
      await writeTextFile(path, getRawRequest(session));
    }
  } catch (e) {
    console.error("Failed to export request", e);
  }
}
