import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { RouterProvider } from "react-router";
import { QueryClientProvider } from "@tanstack/react-query";
import { LinkProvider, Toasty, TooltipProvider } from "@cloudflare/kumo";
import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import "./styles.css";
import { queryClient } from "./lib/queries";
import { toastManager } from "./lib/toast";
import { router } from "./router";
import { AppLink } from "./components/AppLink";
import { onUnauthorized } from "./lib/api";

onUnauthorized(() => {
  queryClient.removeQueries({ queryKey: ["me"] });
  const here = window.location.pathname + window.location.search;
  if (!window.location.pathname.startsWith("/login")) {
    router.navigate(`/login?next=${encodeURIComponent(here)}`, { replace: true });
  }
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <LinkProvider component={AppLink}>
        <TooltipProvider>
          <Toasty toastManager={toastManager}>
            <RouterProvider router={router} />
          </Toasty>
        </TooltipProvider>
      </LinkProvider>
    </QueryClientProvider>
  </StrictMode>,
);
