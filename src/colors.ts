import type { AuditResult } from "./types.js";

export const AUDIT_COLORS: Readonly<Record<AuditResult, string>> = {
    FAILURE: "#ff626d",
    SUCCESS: "#5dc98b",
    NONE: "#87909e",
};
