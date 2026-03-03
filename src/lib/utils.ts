import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatSize(bytes: number): string {
  if (bytes === 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatTime(ms: number): string {
  if (ms === 0) return "0 ms";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

export function formatWsTime(epochMs: number): string {
  const d = new Date(epochMs);
  const h = d.getHours().toString().padStart(2, "0");
  const m = d.getMinutes().toString().padStart(2, "0");
  const s = d.getSeconds().toString().padStart(2, "0");
  const ms = d.getMilliseconds().toString().padStart(3, "0");
  return `${h}:${m}:${s}.${ms}`;
}

export function shortType(contentType: string): string {
  if (!contentType) return "";
  const base = contentType.split(";")[0].trim();
  if (base === "application/json") return "json";
  if (base === "text/html") return "html";
  if (base === "text/css") return "css";
  if (base === "text/javascript" || base === "application/javascript")
    return "js";
  if (base === "application/xml" || base === "text/xml") return "xml";
  if (base === "text/plain") return "text";
  if (base === "application/x-www-form-urlencoded") return "form";
  if (base === "multipart/form-data") return "multipart";
  if (base === "application/octet-stream") return "binary";
  if (base === "application/grpc") return "grpc";
  if (base === "application/protobuf" || base === "application/x-protobuf")
    return "protobuf";
  if (base.startsWith("image/")) return base.replace("image/", "img/");
  if (base.startsWith("font/")) return base.replace("font/", "font/");
  if (base.startsWith("video/")) return "video";
  if (base.startsWith("audio/")) return "audio";
  return base.replace("application/", "");
}

