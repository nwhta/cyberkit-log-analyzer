import type { Severity } from "./types.js";
import type { LogParser, ParsedEvent } from "./parserTypes.js";
import { cleanIp, formatUtc, parseLineByLine, sampleLines, shareOf, shorten } from "./parseHelpers.js";
import { SEVERITY_COLORS, SEVERITY_ORDER, severityColor } from "./severity.js";
import { serviceLabel } from "./netEvents.js";

const FAST_LINE = /^(\d{2})\/(\d{2})(?:\/(\d{2,4}))?-(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s+(?:\[(\w+)\]\s+)?\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+(.*?)\s+\[\*\*\]\s*(?:\[Classification:\s*([^\]]*)\]\s*)?(?:\[Priority:\s*(\d+)\]\s*)?\{(\w+)\}\s+(\S+?)(?::(\d+))?\s+->\s+(\S+?)(?::(\d+))?\s*$/;

const PRIORITY_SEVERITY: Readonly<Record<string, Severity>> = { "1": "ERROR", "2": "WARNING", "3": "INFO", "4": "DEBUG" };
const PRIORITY_MEANING: Readonly<Record<string, string>> = {
    "1": "High: likely a real attack or compromise",
    "2": "Medium: suspicious, worth checking",
    "3": "Low: informational or policy",
    "4": "Very low",
};

function splitAddress(address: string, port: string | undefined): [string | null, string | null] {
    if (port !== undefined) {
        return [cleanIp(address), port];
    }

    const ipv4 = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$/.exec(address);
    return ipv4 ? [ipv4[1], ipv4[2]] : [cleanIp(address), null];
}

function parseFastLine(line: string, lineNumber: number, year: number): ParsedEvent | null {
    const match = FAST_LINE.exec(line.trim());

    if (!match) {
        return null;
    }

    const [, month, day, yearText, hour, minute, second, fraction, action, gid, sid, rev, message, classification, priorityText, protocol, srcAddr, srcPortText, dstAddr, dstPortText] = match;
    const fullYear = yearText === undefined ? year : yearText.length === 2 ? 2000 + Number(yearText) : Number(yearText);
    const timeMs = Date.UTC(fullYear, +month - 1, +day, +hour, +minute, +second, Math.floor(Number(`0.${fraction ?? "0"}`) * 1000));
    const priority = priorityText ?? "3";
    const severity = PRIORITY_SEVERITY[priority] ?? "INFO";
    const [srcIp, srcPort] = splitAddress(srcAddr, srcPortText);
    const [dstIp, dstPort] = splitAddress(dstAddr, dstPortText);

    return {
        lineNumber,
        raw: line,
        timeMs,
        timeText: line.slice(0, line.indexOf(" ")),
        severity,
        title: shorten(message, 180),
        badge: action ? `P${priority} · ${action.toUpperCase()}` : `PRIORITY ${priority}`,
        summary: [classification, `${protocol} ${srcAddr}${srcPortText ? ":" + srcPortText : ""} → ${dstAddr}${dstPortText ? ":" + dstPortText : ""}`, dstPort !== null ? serviceLabel(dstPort) : ""].filter(Boolean).join(" · "),
        metadata: [formatUtc(timeMs), `rule ${gid}:${sid}:${rev}`, ...(srcIp !== null ? [`IP: ${srcIp}`] : [])],
        accent: SEVERITY_COLORS[severity],
        emphasis: priority === "1",
        noise: false,
        ip: srcIp,
        facets: {
            priority: `Priority ${priority}`,
            classification: classification ?? "(none)",
            protocol,
            severity,
            signature: message,
            action: action ?? "(not set)",
        },
        details: () => ({
            fields: [
                { name: "Signature", value: message },
                { name: "Rule ID (gid:sid:rev)", value: `${gid}:${sid}:${rev}`, meaning: "sid = rule number; search it on the vendor site to read the rule" },
                { name: "Classification", value: classification ?? "" },
                { name: "Priority", value: priority, meaning: PRIORITY_MEANING[priority] ?? null, risky: priority === "1" },
                { name: "Action", value: action ?? "", meaning: action ? "Inline IPS action (drop = blocked)" : null },
                { name: "Protocol", value: protocol },
                { name: "Source", value: `${srcAddr}${srcPortText ? ":" + srcPortText : ""}` },
                { name: "Destination", value: `${dstAddr}${dstPortText ? ":" + dstPortText : ""}`, meaning: dstPort !== null ? serviceLabel(dstPort) : null },
            ],
        }),
    };
}

export const snortFastParser: LogParser = {
    id: "snort-fast",
    name: "Snort / Suricata fast.log",
    description: "IDS alerts in the one-line \"fast\" format (alert_fast / fast.log).",
    demoFile: "/static/demo/snort-fast.log",
    rawLabel: "Raw line",
    searchHint: "Signature, IP, sid…",
    timeNote: "fast.log has no time zone (and often no year). Shown as written; the year is guessed.",
    detect: sample => {
        const share = shareOf(sampleLines(sample), line => FAST_LINE.test(line));
        return share >= 0.5 ? 0.97 : share * 0.9;
    },
    parse: content => {
        const year = new Date().getUTCFullYear();
        return parseLineByLine(content, (line, lineNumber) => parseFastLine(line, lineNumber, year), {
            reason: "This line does not look like a Snort/Suricata fast alert ([**] [gid:sid:rev] message [**] … {PROTO} src -> dst).",
            isContinuation: () => false,
        });
    },
    facets: [
        { key: "priority", title: "Priority", order: ["Priority 1", "Priority 2", "Priority 3", "Priority 4"], color: value => SEVERITY_COLORS[PRIORITY_SEVERITY[value.slice(-1)] ?? "INFO"] },
        { key: "classification", title: "Classification" },
        { key: "action", title: "IPS action" },
        { key: "protocol", title: "Protocol" },
        { key: "severity", title: "Severity", order: SEVERITY_ORDER, color: severityColor },
    ],
    sourcePanel: {
        title: "Medium / high alerts by source IP",
        emptyText: "No priority 1–2 alerts with a source IP",
        subjectWord: ["signature", "signatures"],
        select: event => event.ip === null || !["Priority 1", "Priority 2"].includes(event.facets.priority) ? null : { ip: event.ip, subject: event.facets.signature, tag: event.facets.priority === "Priority 1" ? "high priority" : null },
        suspicion: stats => {
            if (stats.tags.size > 0) {
                return "high-priority alerts";
            }

            if (stats.subjects.size >= 3) {
                return "several attack types";
            }

            return stats.count >= 10 ? "many alerts" : null;
        },
    },
    coverage: () => ({
        summary: "Every alert is shown. Priority is turned into severity; rule IDs and classifications are kept.",
        groups: [{ title: "Priority", items: Object.entries(PRIORITY_MEANING).map(([key, text]) => `${key} — ${text}`) }],
    }),
};
