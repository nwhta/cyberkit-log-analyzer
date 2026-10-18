import type { Severity } from "./types.js";

export const SEVERITY_COLORS: Readonly<Record<Severity, string>> = {
    CRITICAL: "#ff3d4f",
    ERROR: "#ff626d",
    WARNING: "#e5b44b",
    INFO: "#619aff",
    DEBUG: "#87909e",
    UNKNOWN: "#6b7380",
};

export const SEVERITY_ORDER: string[] = ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "UNKNOWN"];

export function severityColor(value: string): string {
    return SEVERITY_COLORS[value as Severity] ?? SEVERITY_COLORS.UNKNOWN;
}

export function isSeriousSeverity(severity: Severity): boolean {
    return severity === "CRITICAL" || severity === "ERROR";
}

export function severityFromText(text: string | null | undefined): Severity {
    if (!text) {
        return "UNKNOWN";
    }

    const value = text.trim().toLowerCase();

    if (/^(emerg|emergency|alert|crit|critical|fatal|panic|severe)/.test(value)) {
        return "CRITICAL";
    }

    if (/^(err|error|failure|fail)/.test(value)) {
        return "ERROR";
    }

    if (/^(warn|warning)/.test(value)) {
        return "WARNING";
    }

    if (/^(notice|info|information|informational|ok|success)/.test(value)) {
        return "INFO";
    }

    if (/^(debug|trace|verbose|fine)/.test(value)) {
        return "DEBUG";
    }

    return "UNKNOWN";
}
