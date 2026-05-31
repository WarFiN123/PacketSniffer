import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
    // CodeMirror requires a SINGLE instance of these singleton packages;
    // duplicate copies break instanceof checks ("Unrecognized extension value").
    dedupe: [
      "@codemirror/state",
      "@codemirror/view",
      "@codemirror/language",
    ],
  },
  clearScreen: false, // tauri logs remain visible

  build: {
    rollupOptions: {
      output: {
        // rolldown-vite (Vite 8) requires manualChunks as a function.
        manualChunks(id) {
          if (
            id.includes("@uiw/react-codemirror") ||
            id.includes("@codemirror/") ||
            id.includes("@lezer/")
          ) {
            return "codemirror";
          }
        },
      },
    },
    chunkSizeWarningLimit: 600,
  },

  server: {
    port: 5173,
    strictPort: true,
    host: host || false,
    hmr: host ? { protocol: "ws", host, port: 5174 } : undefined,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
});
