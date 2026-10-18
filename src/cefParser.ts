import type { Severity } from "./types.js";
import type { EventField, LogParser, ParsedEvent } from "./parserTypes.js";
import { cleanIp, formatUtc, parseLineByLine, sampleLines, shareOf, shorten } from "./parseHelpers.js";
import { SEVERITY_COLORS, SEVERITY_ORDER, isSeriousSeverity, severityColor } from "./severity.js";

const CEF_MARKER = /CEF:\d+\|/;

const KEY_LABELS: Readonly<Record<string, string>> = {
    act: "Action",
    app: "Application protocol",
    cat: "Category",
    cnt: "Count",
    dhost: "Destination host",
    dmac: "Destination MAC",
    dpt: "Destination port",
    dst: "Destination IP",
    duser: "Destination user",
    dvc: "Device IP",
    dvchost: "Device host",
    end: "End time",
    fname: "File name",
    filePath: "File path",
    msg: "Message",
    outcome: "Outcome",
    proto: "Transport protocol",
    reason: "Reason",
    request: "URL",
    requestMethod: "HTTP method",
    requestClientApplication: "User agent",
    rt: "Receipt time",
    shost: "Source host",
    smac: "Source MAC",
    spt: "Source port",
    src: "Source IP",
    start: "Start time",
    suser: "Source user",
    deviceDirection: "Direction",
    deviceExternalId: "Device ID",
    externalId: "External ID",
};

function splitHeader(text: string): string[] | null {
    const parts: string[] = [];
    let current = "";

    for (let i = 0; i < text.length; i++) {
        const char = text[i];

        if (char === "\\" && i + 1 < text.length) {
            current += text[i + 1];
            i++;
            continue;
        }

        if (char === "|" && parts.length < 7) {
            parts.push(current);
            current = "";
            continue;
        }

        current += char;
    }

    parts.push(current);
    return parts.length === 8 ? parts : null;
}

function unescapeValue(value: string): string {
    return value.replace(/\\([=\\n r])/g, (_, char: string) => char === "n" ? "\n" : char === "r" ? "\r" : char);
}

function parseExtension(text: string): Map<string, string> {
    const result = new Map<string, string>();
    const keyPattern = /(?:^|\s)([A-Za-z0-9_.\-[\]]+)=/g;
    const keys: { key: string; valueStart: number; matchStart: number }[] = [];

    let match: RegExpExecArray | null;

    while ((match = keyPattern.exec(text)) !== null) {
        keys.push({ key: match[1], valueStart: match.index + match[0].length, matchStart: match.index });
    }

    for (let i = 0; i < keys.length; i++) {
        const end = i + 1 < keys.length ? keys[i + 1].matchStart : text.length;
        result.set(keys[i].key, unescapeValue(text.slice(keys[i].valueStart, end).trim()));
    }

    return result;
}

function cefSeverity(value: string): Severity {
    const number = Number(value);

    if (!Number.isNaN(number) && value.trim() !== "") {
        if (number >= 9) return "CRITICAL";
        if (number >= 7) return "ERROR";
        if (number >= 4) return "WARNING";
        return "INFO";
    }

    switch (value.trim().toLowerCase()) {
        case "very-high":
            return "CRITICAL";
        case "high":
            return "ERROR";
        case "medium":
            return "WARNING";
        case "low":
            return "INFO";
        default:
            return "UNKNOWN";
    }
}

function parseCefTime(value: string | undefined): number {
    if (value === undefined || value === "") {
        return Number.NaN;
    }

    if (/^\d{10,13}$/.test(value)) {
        const number = Number(value);
        return number > 1e12 ? number : number * 1000;
    }

    const hasZone = /(?:Z|UTC|GMT|[+-]\d{2}:?\d{2}|\b[A-Z]{3,4})$/.test(value.trim());
    return Date.parse(hasZone ? value : `${value} UTC`);
}

function parsePrefixTime(prefix: string): number {
    const iso = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?/.exec(prefix);
    return iso ? Date.parse(iso[0].replace(/(\.\d{3})\d+/, "$1")) : Number.NaN;
}

function customLabel(key: string, extension: Map<string, string>): string | null {
    const match = /^(cs|cn|cfp|flexString|flexNumber|flexDate|c6a|deviceCustomDate)(\d)$/.exec(key);

    if (!match) {
        return null;
    }

    return extension.get(`${key}Label`) ?? null;
}

function parseCefLine(line: string, lineNumber: number): ParsedEvent | null {
    const markerIndex = line.search(CEF_MARKER);

    if (markerIndex < 0) {
        return null;
    }

    const prefix = line.slice(0, markerIndex).trim();
    const header = splitHeader(line.slice(markerIndex));

    if (header === null) {
        return null;
    }

    const [version, vendor, product, deviceVersion, signatureId, name, severityText, extensionText] = header;
    const extension = parseExtension(extensionText);
    const severity = cefSeverity(severityText);

    let timeMs = parseCefTime(extension.get("rt") ?? extension.get("end") ?? extension.get("start"));
    let timeSource = extension.has("rt") ? "rt" : extension.has("end") ? "end" : extension.has("start") ? "start" : "";

    if (Number.isNaN(timeMs)) {
        timeMs = parsePrefixTime(prefix);
        timeSource = Number.isNaN(timeMs) ? "" : "syslog header";
    }

    const ip = cleanIp(extension.get("src") ?? extension.get("shost"));
    const destination = extension.get("dst") ?? extension.get("dhost") ?? null;
    const action = extension.get("act") ?? extension.get("outcome") ?? null;

    const metadata = [formatUtc(timeMs), `${vendor} ${product}`.trim()];

    if (ip !== null || destination !== null) {
        metadata.push(`${ip ?? "?"}${extension.has("spt") ? ":" + extension.get("spt") : ""} → ${destination ?? "?"}${extension.has("dpt") ? ":" + extension.get("dpt") : ""}`);
    }

    const summaryParts: string[] = [];

    if (action !== null) {
        summaryParts.push(`action: ${action}`);
    }

    if (extension.has("suser") || extension.has("duser")) {
        summaryParts.push(`user: ${extension.get("suser") ?? extension.get("duser")}`);
    }

    if (extension.has("msg")) {
        summaryParts.push(extension.get("msg") as string);
    }

    return {
        lineNumber,
        raw: line,
        timeMs,
        timeText: timeSource === "syslog header" ? prefix : timeSource === "" ? "" : extension.get(timeSource) ?? "",
        severity,
        title: shorten(name || `Signature ${signatureId}`, 160),
        badge: `SEV ${severityText}`,
        summary: shorten(summaryParts.join(" · ") || `Signature ID ${signatureId}`),
        metadata,
        accent: SEVERITY_COLORS[severity],
        emphasis: isSeriousSeverity(severity),
        noise: false,
        ip,
        facets: {
            severity,
            device: `${vendor} ${product}`.trim() || "(not set)",
            action: action ?? "(not set)",
            category: extension.get("cat") ?? "(not set)",
            name,
        },
        details: () => {
            const fields: EventField[] = [
                { name: "CEF version", value: version },
                { name: "Device vendor", value: vendor },
                { name: "Device product", value: product },
                { name: "Device version", value: deviceVersion },
                { name: "Signature ID", value: signatureId, meaning: "Vendor's ID of the rule or event type." },
                { name: "Name", value: name },
                { name: "Severity", value: severityText, meaning: "CEF scale 0–10: 0–3 low, 4–6 medium, 7–8 high, 9–10 very high.", risky: isSeriousSeverity(severity) },
            ];

            if (prefix !== "") {
                fields.unshift({ name: "Syslog header", value: prefix, meaning: "Text before \"CEF:\" added by the syslog transport." });
            }

            if (timeSource === "") {
                fields.push({ name: "Time", value: "not found", meaning: "No rt/start/end field and no ISO time in the syslog header." });
            }

            for (const [key, value] of extension) {
                if (key.endsWith("Label") && customLabel(key.slice(0, -5), extension) !== null) {
                    continue;
                }

                const label = customLabel(key, extension);
                fields.push({
                    name: label !== null ? `${label} (${key})` : KEY_LABELS[key] ? `${KEY_LABELS[key]} (${key})` : key,
                    value,
                });
            }

            return { fields };
        },
    };
}

export const cefParser: LogParser = {
    id: "cef",
    name: "CEF (Common Event Format)",
    description: "Common Event Format from firewalls, IDS and SIEMs (Fortinet, Check Point, Palo Alto…).",
    demoFile: "/static/demo/cef.log",
    rawLabel: "Raw line",
    searchHint: "Name, IP, user, vendor…",
    timeNote: "Taken from rt/start/end (or the syslog header). Times without a zone are treated as UTC.",
    detect: sample => {
        const share = shareOf(sampleLines(sample), line => CEF_MARKER.test(line));
        return share >= 0.5 ? 0.95 : share * 0.9;
    },
    parse: content => parseLineByLine(content, parseCefLine, {
        reason: "This line has no valid \"CEF:Version|Vendor|Product|Version|ID|Name|Severity|\" header.",
        isContinuation: () => false,
    }),
    facets: [
        { key: "severity", title: "Severity", order: SEVERITY_ORDER, color: severityColor },
        { key: "device", title: "Device" },
        { key: "action", title: "Action" },
        { key: "category", title: "Category" },
    ],
    sourcePanel: {
        title: "High / medium events by source",
        emptyText: "No medium or higher events with a source",
        subjectWord: ["event name", "event names"],
        select: event => event.ip === null || !["CRITICAL", "ERROR", "WARNING"].includes(event.severity) ? null : {
            ip: event.ip,
            subject: event.facets.name || null,
            tag: isSeriousSeverity(event.severity) ? "high" : null,
        },
        suspicion: stats => {
            if (stats.tags.size > 0) {
                return "high-severity events";
            }

            return stats.count >= 10 ? "many events from one source" : null;
        },
    },
};
