import type { Severity } from "./types.js";
import type { FacetDefinition, ParserCoverage, SourcePanelDefinition } from "./parserTypes.js";
import { SEVERITY_COLORS, severityColor, SEVERITY_ORDER } from "./severity.js";
import { listAttackPatterns, NO_ATTACK } from "./webAttackPatterns.js";
import { listKnownScanners } from "./userAgents.js";

const STATUS_MEANINGS: Readonly<Record<string, string>> = {
    "200": "OK — request succeeded",
    "201": "Created",
    "204": "No content",
    "206": "Partial content (download in parts)",
    "301": "Moved permanently (redirect)",
    "302": "Found (temporary redirect)",
    "304": "Not modified (browser cache used)",
    "400": "Bad request — malformed request, common with scanners",
    "401": "Unauthorized — login required or wrong credentials",
    "403": "Forbidden — access denied",
    "404": "Not found — many 404s from one IP usually means scanning",
    "405": "Method not allowed",
    "408": "Request timeout",
    "413": "Request body too large",
    "429": "Too many requests — rate limit triggered",
    "444": "Nginx closed the connection without response (often used to drop bad bots)",
    "499": "Client closed the connection before Nginx answered",
    "500": "Internal server error — the application crashed or failed",
    "502": "Bad gateway — the backend app is down or returned garbage",
    "503": "Service unavailable — overloaded or in maintenance",
    "504": "Gateway timeout — the backend app answered too slowly",
};

export function statusMeaning(status: string): string | null {
    return STATUS_MEANINGS[status] ?? null;
}

export function statusClass(status: string): string {
    return /^[1-5]\d\d$/.test(status) ? `${status[0]}xx` : "Other";
}

export function statusSeverity(status: string): Severity {
    if (status.startsWith("5")) {
        return "ERROR";
    }

    if (status.startsWith("4")) {
        return "WARNING";
    }

    if (/^[123]/.test(status)) {
        return "INFO";
    }

    return "UNKNOWN";
}

const STATUS_COLORS: Readonly<Record<string, string>> = {
    "2xx": "#5dc98b",
    "3xx": "#619aff",
    "4xx": "#e5b44b",
    "5xx": "#ff626d",
};

export const WEB_FACETS: FacetDefinition[] = [
    { key: "status", title: "Status", order: ["5xx", "4xx", "3xx", "2xx", "1xx", "Other"], color: value => STATUS_COLORS[value] ?? "#87909e" },
    { key: "attack", title: "Suspicious pattern", color: value => value === NO_ATTACK ? "#87909e" : SEVERITY_COLORS.ERROR },
    { key: "client", title: "Client type", color: value => value === "Security scanner" ? SEVERITY_COLORS.ERROR : "#619aff" },
    { key: "method", title: "Method" },
    { key: "severity", title: "Severity", order: SEVERITY_ORDER, color: severityColor },
];

const ATTACK_THRESHOLD = 3;
const LOGIN_FAILURE_THRESHOLD = 5;
export const LOGIN_FAILURE_TAG = "login failed (401)";
const NOT_FOUND_PATHS_THRESHOLD = 20;

export const WEB_SOURCE_PANEL: SourcePanelDefinition = {
    title: "Suspicious requests by IP",
    emptyText: "No errors or attack patterns with a client IP",
    subjectWord: ["path", "paths"],
    select: event => {
        const isProblem = event.facets.attack !== NO_ATTACK ||
            event.facets.status === "4xx" ||
            event.facets.status === "5xx" ||
            event.facets.client === "Security scanner";

        if (!isProblem || event.ip === null) {
            return null;
        }

        return {
            ip: event.ip,
            subject: event.facets.path ?? null,
            tag: event.facets.attack !== NO_ATTACK ? event.facets.attack : event.facets.code === "401" ? LOGIN_FAILURE_TAG : null,
        };
    },
    suspicion: stats => {
        const attackTags = [...stats.tags].filter(tag => tag !== LOGIN_FAILURE_TAG);

        if (attackTags.length > 0 && stats.count >= ATTACK_THRESHOLD) {
            return "possible attack / vulnerability scan";
        }

        if (stats.tags.has(LOGIN_FAILURE_TAG) && stats.count >= LOGIN_FAILURE_THRESHOLD) {
            return "possible password guessing";
        }

        if (stats.subjects.size >= NOT_FOUND_PATHS_THRESHOLD) {
            return "possible directory brute-force";
        }

        if (attackTags.length > 0) {
            return "attack pattern seen";
        }

        return null;
    },
};

export function webCoverage(): ParserCoverage {
    return {
        summary: "Every request is shown. These patterns are flagged as suspicious; the matched text is shown in Details.",
        groups: [
            { title: "Suspicious patterns", items: listAttackPatterns() },
            { title: "Security scanners recognized by user agent", items: [listKnownScanners().join(", ")] },
            { title: "Status codes with an explanation", items: Object.entries(STATUS_MEANINGS).map(([code, text]) => `${code} — ${text}`) },
        ],
    };
}
