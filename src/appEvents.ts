import type { Severity } from "./types.js";
import type { EventField, FacetDefinition, ParsedEvent, SourcePanelDefinition } from "./parserTypes.js";
import { cleanIp, formatUtc, shorten } from "./parseHelpers.js";
import { SEVERITY_COLORS, SEVERITY_ORDER, isSeriousSeverity, severityColor } from "./severity.js";

export const AUTH_FAILED = "Login failed";

export interface AppRecord {
    lineNumber: number;
    raw: string;
    timeMs: number;
    timeText: string;
    severity: Severity;
    category: string;
    title: string;
    badge: string;
    summary?: string;
    ip?: string | null;
    user?: string | null;
    host?: string | null;
    emphasis?: boolean;
    noise?: boolean;
    fields: EventField[];
}

const CATEGORY_COLORS: Readonly<Record<string, string>> = {
    [AUTH_FAILED]: SEVERITY_COLORS.ERROR,
    "Login OK": "#5dc98b",
    Connected: "#5dc98b",
    Disconnected: "#87909e",
    "Suspicious command": SEVERITY_COLORS.CRITICAL,
};

export function buildAppEvent(record: AppRecord): ParsedEvent {
    const ip = cleanIp(record.ip ?? null);
    const metadata = [formatUtc(record.timeMs)];

    if (record.host) {
        metadata.push(record.host);
    }

    if (record.user) {
        metadata.push(`user: ${record.user}`);
    }

    if (ip !== null) {
        metadata.push(`IP: ${ip}`);
    }

    return {
        lineNumber: record.lineNumber,
        raw: record.raw,
        timeMs: record.timeMs,
        timeText: record.timeText,
        severity: record.severity,
        title: shorten(record.title, 180),
        badge: record.badge,
        summary: shorten(record.summary ?? ""),
        metadata,
        accent: CATEGORY_COLORS[record.category] ?? SEVERITY_COLORS[record.severity],
        emphasis: record.emphasis ?? isSeriousSeverity(record.severity),
        noise: record.noise ?? false,
        ip,
        facets: {
            category: record.category,
            severity: record.severity,
            user: record.user ?? "(none)",
        },
        details: () => ({ fields: record.fields }),
    };
}

export function appFacets(categoryOrder: string[]): FacetDefinition[] {
    return [
        { key: "category", title: "Category", order: categoryOrder, color: value => CATEGORY_COLORS[value] ?? "#619aff" },
        { key: "severity", title: "Severity", order: SEVERITY_ORDER, color: severityColor },
        { key: "user", title: "User" },
    ];
}

export const AUTH_SOURCE_PANEL: SourcePanelDefinition = {
    title: "Failed logins by IP",
    emptyText: "No failed logins with a client IP",
    subjectWord: ["user", "users"],
    select: event => event.ip === null || event.facets.category !== AUTH_FAILED ? null : {
        ip: event.ip,
        subject: event.facets.user === "(none)" ? null : event.facets.user,
        tag: null,
    },
    suspicion: stats => {
        if (stats.subjects.size >= 3) {
            return "tries many user names (password spray)";
        }

        return stats.count >= 5 ? "possible password guessing" : null;
    },
};
