import type { Severity } from "./types.js";
import type { EventField, LogParser, ParsedEvent } from "./parserTypes.js";
import { cleanIp, flattenObject, formatUtc, getPath, parseEpochOrDate, shorten } from "./parseHelpers.js";
import { SEVERITY_COLORS, SEVERITY_ORDER, isSeriousSeverity, severityColor, severityFromText } from "./severity.js";
import { firstValue, jsonLineShare, readJsonLines, type JsonItem, type JsonRecord } from "./jsonRecords.js";

const TIME_KEYS = ["@timestamp", "timestamp", "time", "ts", "date", "datetime", "eventTime", "Timestamp", "TimeGenerated", "t"];
const LEVEL_KEYS = ["level", "log.level", "severity", "lvl", "loglevel", "levelname", "Level", "severity_text", "SeverityText"];
const MESSAGE_KEYS = ["message", "msg", "log", "MESSAGE", "short_message", "Message", "text", "event", "error"];
const SOURCE_KEYS = ["service", "service.name", "logger", "logger_name", "logger.name", "app", "application", "component", "container_name", "name", "source", "module"];
const IP_KEYS = ["client_ip", "clientIp", "client.ip", "source.ip", "src_ip", "remote_addr", "remote_ip", "ip", "ip_address", "client"];
const STACK_KEYS = ["stack", "stack_trace", "stacktrace", "error.stack", "err.stack", "exception", "exc_info"];

const PINO_LEVELS: Readonly<Record<number, Severity>> = {
    10: "DEBUG",
    20: "DEBUG",
    30: "INFO",
    40: "WARNING",
    50: "ERROR",
    60: "CRITICAL",
};

function levelToSeverity(value: unknown): Severity {
    if (typeof value === "number") {
        if (PINO_LEVELS[value] !== undefined) {
            return PINO_LEVELS[value];
        }

        if (value >= 0 && value <= 7) {
            return value <= 2 ? "CRITICAL" : value === 3 ? "ERROR" : value === 4 ? "WARNING" : value === 7 ? "DEBUG" : "INFO";
        }

        return "UNKNOWN";
    }

    return typeof value === "string" ? severityFromText(value) : "UNKNOWN";
}

function asText(value: unknown): string {
    if (value === undefined || value === null) {
        return "";
    }

    return typeof value === "string" ? value : JSON.stringify(value);
}

const KNOWN_KEYS = new Set([...TIME_KEYS, ...LEVEL_KEYS, ...MESSAGE_KEYS, ...SOURCE_KEYS, ...STACK_KEYS]);
const MAX_SUMMARY_FIELDS = 4;

function extraFieldsSummary(record: JsonRecord): string {
    const parts: string[] = [];

    for (const [key, item] of Object.entries(record)) {
        if (KNOWN_KEYS.has(key) || item === null || typeof item === "object") {
            continue;
        }

        parts.push(`${key}=${String(item)}`);

        if (parts.length === MAX_SUMMARY_FIELDS) {
            break;
        }
    }

    return parts.join(" · ");
}

function toEvent({ record, raw, lineNumber }: JsonItem): ParsedEvent {
    const timeValue = firstValue(record, TIME_KEYS, getPath);
    const levelValue = firstValue(record, LEVEL_KEYS, getPath);
    const messageValue = firstValue(record, MESSAGE_KEYS, getPath);
    const sourceValue = firstValue(record, SOURCE_KEYS, getPath);
    const ipValue = firstValue(record, IP_KEYS, getPath);
    const stackValue = firstValue(record, STACK_KEYS, getPath);

    const timeMs = parseEpochOrDate(timeValue);
    let severity = levelToSeverity(levelValue);

    if (severity === "UNKNOWN" && record.stream === "stderr") {
        severity = "WARNING";
    }

    const message = asText(messageValue).trim();
    const source = asText(sourceValue);
    const ip = typeof ipValue === "string" ? cleanIp(ipValue) : null;

    const metadata = [formatUtc(timeMs)];

    if (source !== "") {
        metadata.push(source);
    }

    if (ip !== null) {
        metadata.push(`IP: ${ip}`);
    }

    return {
        lineNumber,
        raw,
        timeMs,
        timeText: asText(timeValue),
        severity,
        title: shorten(message.split("\n")[0] || "(no message field)", 160),
        badge: levelValue === undefined ? "NO LEVEL" : asText(levelValue).toUpperCase(),
        summary: shorten(message.includes("\n") ? message.split("\n").slice(1).join(" ") : extraFieldsSummary(record)),
        metadata,
        accent: SEVERITY_COLORS[severity],
        emphasis: isSeriousSeverity(severity),
        noise: false,
        ip,
        facets: {
            severity,
            source: source === "" ? "(not set)" : source,
        },
        details: () => {
            const fields: EventField[] = flattenObject(record).map(([name, value]) => ({ name, value }));
            const sections = stackValue === undefined ? [] : [{ title: "Stack trace / exception", text: asText(stackValue) }];

            return { fields, sections };
        },
    };
}

export const jsonLogParser: LogParser = {
    id: "json-lines",
    name: "JSON log (one object per line)",
    description: "Any app log with one JSON object per line: Docker, Node.js, Python, Go…",
    demoFile: "/static/demo/app.jsonl",
    rawLabel: "Raw JSON",
    searchHint: "Any value: message, service, IP…",
    timeNote: "Read from @timestamp / time / ts. Times without a zone are treated as UTC.",
    detect: sample => jsonLineShare(sample) * 0.6,
    parse: content => readJsonLines(content, toEvent, "This line is not a valid JSON object."),
    facets: [
        { key: "severity", title: "Level", order: SEVERITY_ORDER, color: severityColor },
        { key: "source", title: "Source / service" },
    ],
    sourcePanel: {
        title: "Errors and warnings by IP",
        emptyText: "No errors or warnings with an IP field",
        subjectWord: ["message", "messages"],
        select: event => event.ip === null || !["CRITICAL", "ERROR", "WARNING"].includes(event.severity) ? null : {
            ip: event.ip,
            subject: event.title,
            tag: null,
        },
        suspicion: stats => stats.count >= 20 ? "many errors from one IP" : null,
    },
};
