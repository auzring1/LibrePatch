import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { PRODUCT_NAME } from "./src/brand.generated";

// The production bundle is embedded into the Go server (internal/server/webui/dist).
export default defineConfig({
  // The product name comes from internal/shared/brand (go generate writes src/brand.generated.ts).
  plugins: [react(), {
      // Production builds keep <!--BRAND_HEAD-->; the Go server fills it per request from the
      // deployment's branding. The dev server has no such server, so use the product defaults.
      name: "brand-head",
      transformIndexHtml: (html, ctx) =>
        ctx.server
          ? html.replace("<!--BRAND_HEAD-->", `<title>${PRODUCT_NAME}</title><link rel="icon" href="/favicon.svg" />`)
          : html,
    },
    {
      // A blocking script, placed after the stylesheet so it can read the themes: it applies the saved theme before
      // the first paint (see public/theme-init.js). The CSP allows it as a same-origin script.
      name: "theme-init",
      transformIndexHtml: { order: "post", handler: (html: string) => html.replace("</head>", '  <script src="/theme-init.js"></script>\n  </head>') },
    }],
  build: {
    outDir: "../internal/server/webui/dist",
    emptyOutDir: true,
    sourcemap: false,
    // Keep everything as external files: the CSP forbids inline scripts.
    assetsInlineLimit: 0,
    // Internal admin console: one bundle is fine.
    chunkSizeWarningLimit: 1000,
  },
  server: {
    port: 5173,
    // Dev: run the server with LIBREPATCH_PUBLIC_URL=http://localhost:5173 so Origin checks pass.
    proxy: { "/api": { target: "http://localhost:8080", changeOrigin: false } },
  },
  // Unit tests only; the Playwright browser test in e2e/ runs via scripts/gui-e2e.sh.
  // The theme registry reads the theme CSS files as raw text, so vitest must not blank them.
  test: { environment: "node", include: ["src/**/*.test.ts", "src/**/*.test.tsx"], css: { include: [/src\/design\/themes\/.*\.css/] } },
});
