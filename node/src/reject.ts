import type { RejectReason } from "./core.js";

/** JSON body for a 401 rejection; identical across adapters and languages. */
export function rejectionBody(reason: RejectReason): string {
  return `{"error":"invalid_assay_signature","reason":"${reason}"}`;
}
