import { cleanIp, flattenObject, formatUtc, shorten } from "./parseHelpers.js";
import { SEVERITY_COLORS, SEVERITY_ORDER, severityColor } from "./severity.js";
export const NO_RISK = "None detected";
const RESULT_COLORS = {
    Success: "#5dc98b",
    Failure: SEVERITY_COLORS.ERROR,
    Interrupted: "#619aff",
    Unknown: "#87909e",
};
export function buildCloudEvent(record) {
    const ip = cleanIp(record.ip);
    const severity = record.severity ?? record.risk?.severity ?? (record.risk !== null ? "WARNING" : record.result === "Failure" ? "WARNING" : "INFO");
    const summary = [
        record.risk !== null ? `${record.risk.name}: ${record.risk.reason}` : "",
        record.summary ?? "",
        record.actor ? `by ${record.actor}` : "",
        ip !== null ? `from ${ip}` : "",
    ].filter(Boolean).join(" · ");
    const metadata = [formatUtc(record.timeMs), record.service];
    if (record.resource) {
        metadata.push(shorten(record.resource, 80));
    }
    if (ip !== null) {
        metadata.push(`IP: ${ip}`);
    }
    return {
        lineNumber: record.lineNumber,
        raw: record.raw,
        timeMs: record.timeMs,
        timeText: record.timeText,
        severity,
        title: shorten(record.title ?? record.operation, 180),
        badge: record.risk !== null ? `⚠ ${record.risk.name}` : (record.resultText ?? record.result).toUpperCase(),
        summary: shorten(summary),
        metadata,
        accent: record.risk !== null ? SEVERITY_COLORS[record.risk.severity ?? "ERROR"] : RESULT_COLORS[record.result],
        emphasis: record.risk !== null || severity === "ERROR" || severity === "CRITICAL",
        noise: record.noise ?? false,
        ip,
        facets: {
            result: record.result,
            risk: record.risk?.name ?? NO_RISK,
            service: record.service || "(not set)",
            actor: record.actor ?? "(unknown)",
            operation: record.operation,
            severity,
            ...record.extraFacets,
        },
        details: () => {
            const fields = [...(record.fields ?? [])];
            if (record.risk !== null) {
                fields.unshift({ name: "Why it is flagged", value: record.risk.name, meaning: record.risk.reason, risky: true });
            }
            if (record.source !== undefined) {
                for (const [name, value] of flattenObject(record.source)) {
                    fields.push({ name, value });
                }
            }
            return { fields };
        },
    };
}
export function cloudFacets(extra = []) {
    return [
        { key: "risk", title: "Risky activity", color: value => value === NO_RISK ? "#87909e" : SEVERITY_COLORS.ERROR },
        { key: "result", title: "Result", order: ["Failure", "Interrupted", "Success", "Unknown"], color: value => RESULT_COLORS[value] ?? "#87909e" },
        ...extra,
        { key: "service", title: "Service" },
        { key: "severity", title: "Severity", order: SEVERITY_ORDER, color: severityColor },
    ];
}
export const CLOUD_SOURCE_PANEL = {
    title: "Failures and risky actions by IP",
    emptyText: "No failed or risky actions with an IP",
    subjectWord: ["account", "accounts"],
    select: event => {
        if (event.ip === null || (event.facets.result !== "Failure" && event.facets.risk === NO_RISK)) {
            return null;
        }
        return {
            ip: event.ip,
            subject: event.facets.actor === "(unknown)" ? null : event.facets.actor,
            tag: event.facets.risk !== NO_RISK ? event.facets.risk : event.facets.result === "Failure" ? "failure" : null,
        };
    },
    suspicion: stats => {
        const risks = [...stats.tags].filter(tag => tag !== "failure");
        if (stats.tags.has("failure") && stats.subjects.size >= 3) {
            return `failures on ${stats.subjects.size} accounts (password spray?)`;
        }
        if (risks.length > 0) {
            return risks.length === 1 ? risks[0] : `${risks.length} kinds of risky activity`;
        }
        return stats.count >= 5 ? "many failures" : null;
    },
};
