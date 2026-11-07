import "@mantine/core/styles.css";
import "@mantine/notifications/styles.css";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { Notifications } from "@mantine/notifications";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import { setNonce } from "get-nonce";
import { App } from "./App";
import { ApiError } from "./api/client";
import { SessionProvider } from "./api/session";
import { BrandingProvider } from "./branding/BrandingProvider";
import "./design/themes-entry";
import { AppearanceProvider } from "./design/AppearanceProvider";
import { ConfirmProvider } from "./ui";

// Per-request CSP nonce injected by the server (see internal/server/webui).
const nonce = document.querySelector<HTMLMetaElement>('meta[name="csp-nonce"]')?.content ?? "";
// Modals/drawers lock scrolling via react-remove-scroll, which injects a
// <style> element; give it the nonce too so the strict CSP holds.
setNonce(nonce);

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (n, e) => !(e instanceof ApiError && e.status < 500) && n < 2,
      refetchOnWindowFocus: true,
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrandingProvider>
        <BrowserRouter>
          <SessionProvider>
            <AppearanceProvider nonce={nonce}>
              <Notifications position="top-right" />
              <ConfirmProvider>
                <App />
              </ConfirmProvider>
            </AppearanceProvider>
          </SessionProvider>
        </BrowserRouter>
      </BrandingProvider>
    </QueryClientProvider>
  </StrictMode>,
);
