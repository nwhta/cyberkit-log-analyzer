import type { Severity } from "./types.js";
import type { EventField, LogParser, ParsedEvent } from "./parserTypes.js";
import { cleanIp, formatUtc, parseEpochOrDate, parseLineByLine, sampleLines, shareOf, shorten } from "./parseHelpers.js";
import { SEVERITY_COLORS, SEVERITY_ORDER, isSeriousSeverity, severityColor } from "./severity.js";
import { serviceLabel } from "./netEvents.js";

const LEEF_MARKER = /LEEF:[12]\.0\|/;

const KEY_LABELS: Readonly<Record<string, string>> = {
    devTime: "Device time", devTimeFormat: "Time format", src: "Source IP", dst: "Destination IP",
    srcPort: "Source port", dstPort: "Destination port", proto: "Protocol", usrName: "User", sev: "Severity",
    cat: "Category", identSrc: "Identity source IP", identHostName: "Identity host", url: "URL",
    srcBytes: "Bytes sent", dstBytes: "Bytes received", policy: "Policy", action: "Action", reason: "Reason",
};

function delimiterOf(version: string, field: string | undefined): string {
    if (version !== "2.0" || field === undefined || field === "") {
        return "\t";
    }

    if (/^(0x|x)[0-9a-f]{2}$/i.test(field)) {
        return String.fromCharCode(parseInt(field.replace(/^0?x/i, ""), 16));
    }

    return field[0];
}

function parseAttributes(text: string, delimiter: string): Map<string, string> {
    const result = new Map<string, string>();

    for (const part of text.split(delimiter)) {
        const index = part.indexOf("=");

        if (index > 0) {
            result.set(part.slice(0, index).trim(), part.slice(index + 1));
        }
    }

    return result;
}

function severityOf(value: string | undefined): Severity {
    const number = Number(value);

    if (value === undefined || Number.isNaN(number)) {
        return "INFO";
    }

    return number >= 9 ? "CRITICAL" : number >= 7 ? "ERROR" : number >= 4 ? "WARNING" : "INFO";
}

function parseTime(attributes: Map<string, string>): number {
    const raw = attributes.get("devTime");

    if (raw === undefined) {
        return Number.NaN;
    }

    const value = parseEpochOrDate(raw);

    if (!Number.isNaN(value)) {
        return /[zZ]|[+-]\d{2}:?\d{2}$/.test(raw) || /^\d+$/.test(raw) ? value : Date.parse(raw + " UTC");
    }

    return Number.NaN;
}

function parseLeefLine(line: string, lineNumber: number): ParsedEvent | null {
    const start = line.search(LEEF_MARKER);

    if (start < 0) {
        return null;
    }

    const prefix = line.slice(0, start).trim();
    const parts = line.slice(start).split("|");
    const version = parts[0].slice(5);
    const headerCount = version === "2.0" ? 6 : 5;

    if (parts.length < headerCount + 1) {
        return null;
    }

    const [, vendor, product, productVersion, eventId] = parts;
    const delimiter = delimiterOf(version, version === "2.0" ? parts[5] : undefined);
    const attributes = parseAttributes(parts.slice(headerCount).join("|"), delimiter);
    const severity = severityOf(attributes.get("sev"));
    const ip = cleanIp(attributes.get("src"));
    const timeMs = parseTime(attributes);
    const user = attributes.get("usrName");
    const dstPort = attributes.get("dstPort") ?? null;
    const action = attributes.get("action") ?? attributes.get("act");

    const summary = [
        attributes.get("cat"),
        action,
        user ? `user: ${user}` : "",
        attributes.get("dst") ? `→ ${attributes.get("dst")}${dstPort ? ` (${serviceLabel(dstPort)})` : ""}` : "",
    ].filter(Boolean).join(" · ");

    return {
        lineNumber,
        raw: line,
        timeMs,
        timeText: attributes.get("devTime") ?? "",
        severity,
        title: shorten(attributes.get("cat") && attributes.get("cat") !== eventId ? `${attributes.get("cat")} · ${eventId}` : eventId, 160),
        badge: attributes.has("sev") ? `SEV ${attributes.get("sev")}` : `LEEF ${version}`,
        summary: shorten(summary),
        metadata: [formatUtc(timeMs), `${vendor} ${product}`.trim(), ...(ip !== null ? [`IP: ${ip}`] : [])],
        accent: SEVERITY_COLORS[severity],
        emphasis: isSeriousSeverity(severity),
        noise: false,
        ip,
        facets: {
            severity,
            device: `${vendor} ${product}`.trim() || "(not set)",
            category: attributes.get("cat") ?? "(not set)",
            action: action ?? "(not set)",
            name: eventId,
        },
        details: () => {
            const fields: EventField[] = [
                { name: "LEEF version", value: version },
                { name: "Vendor", value: vendor },
                { name: "Product", value: product },
                { name: "Product version", value: productVersion },
                { name: "Event ID", value: eventId, meaning: "Vendor's name or number of the event type." },
            ];

            if (prefix !== "") {
                fields.unshift({ name: "Syslog header", value: prefix, meaning: "Text before \"LEEF:\" added by the syslog transport." });
            }

            for (const [key, value] of attributes) {
                fields.push({
                    name: KEY_LABELS[key] ? `${KEY_LABELS[key]} (${key})` : key,
                    value,
                    meaning: key === "sev" ? "LEEF scale 1–10: 1–3 low, 4–6 medium, 7–8 high, 9–10 very high." : key === "dstPort" ? serviceLabel(value) : null,
                    risky: key === "sev" && isSeriousSeverity(severity),
                });
            }

            return { fields };
        },
    };
}

export const leefParser: LogParser = {
    id: "leef",
    name: "LEEF (IBM QRadar format)",
    description: "Log Event Extended Format used by IBM QRadar and many security products.",
    demoFile: "/static/demo/leef.log",
    rawLabel: "Raw line",
    searchHint: "Event ID, IP, user, vendor…",
    timeNote: "Taken from devTime. Times without a zone are treated as UTC.",
    detect: sample => {
        const share = shareOf(sampleLines(sample), line => LEEF_MARKER.test(line));
        return share >= 0.5 ? 0.96 : share * 0.9;
    },
    parse: content => parseLineByLine(content, parseLeefLine, {
        reason: "This line has no valid \"LEEF:Version|Vendor|Product|Version|EventID|\" header.",
        isContinuation: () => false,
    }),
    facets: [
        { key: "severity", title: "Severity", order: SEVERITY_ORDER, color: severityColor },
        { key: "device", title: "Device" },
        { key: "category", title: "Category" },
        { key: "action", title: "Action" },
    ],
    sourcePanel: {
        title: "Medium / high events by source",
        emptyText: "No medium or higher events with a source",
        subjectWord: ["event", "events"],
        select: event => event.ip === null || !["CRITICAL", "ERROR", "WARNING"].includes(event.severity) ? null : {
            ip: event.ip,
            subject: event.facets.name || null,
            tag: isSeriousSeverity(event.severity) ? "high" : null,
        },
        suspicion: stats => stats.tags.size > 0 ? "high-severity events" : stats.count >= 10 ? "many events from one source" : null,
    },
};
