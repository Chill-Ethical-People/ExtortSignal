import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.indexOf("node_modules/@phosphor-icons") >= 0) return "icons";
          if (id.indexOf("node_modules/framer-motion") >= 0) return "motion";
          if (id.indexOf("node_modules/react") >= 0) return "react";
        }
      }
    }
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8765",
      "/health": "http://127.0.0.1:8765"
    }
  }
});
