import { createKumoToastManager } from "@cloudflare/kumo";
import { errorMessage } from "./api";

export const toastManager = createKumoToastManager();

export const toast = {
  success(title: string, description?: string) {
    toastManager.add({ title, description, variant: "success" });
  },
  info(title: string, description?: string) {
    toastManager.add({ title, description, variant: "info" });
  },
  error(err: unknown, title = "Something went wrong") {
    toastManager.add({ title, description: errorMessage(err), variant: "error" });
  },
};
