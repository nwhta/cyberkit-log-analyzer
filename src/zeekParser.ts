import type { Severity } from "./types.js";
import type { EventField, LogParser, ParsedEvent } from "./parserTypes.js";
import { cleanIp, formatUtc, makeUnparsedEvent, parseEpochOrDate, shorten, splitLines, tryParseJsonObject } from "./parseHelpers.js";
import { SEVERITY_COLORS, SEVERITY_ORDER, isSeriousSeverity, severityColor } from "./severity.js";
import { sampleJsonRecords } from "./jsonRecords.js";

const CONN_STATES: Readonly<Record<string, string>> = {
    S0: "Connection attempt seen, no reply. Typical for port scans or a host that is down.",
    S1: "Connection established, not terminated.",
    SF: "Normal connection: established and closed properly.",
    REJ: "Connection attempt rejected (port closed).",
    S2: "Established, originator tried to close, no reply from responder.",
    S3: "Established, responder tried to close, no reply from originator.",
    RSTO: "Established, originator aborted (sent RST).",
    RSTR: "Responder sent RST.",
    RSTOS0: "Originator sent SYN then RST, no SYN-ACK seen. Common for stealth scans.",
    RSTRH: "Responder sent SYN-ACK then RST, no SYN from originator seen.",
    SH: "Originator sent SYN then FIN, no SYN-ACK. Unusual — can be a scan.",
    SHR: "Responder sent SYN-ACK then FIN, no SYN from originator seen.",
    OTH: "No SYN seen, just midstream traffic (connection started before capture).",
};

const NO_REPLY_STATES: ReadonlySet<string> = new Set(["S0", "REJ", "RSTOS0", "SH"]);

const FIELD_MEANINGS: Readonly<Record<string, string>> = {
    "ts": "Time (Unix seconds, UTC)",
    "uid": "Connection ID. Use it to find the same connection in other Zeek logs.",
    "id.orig_h": "Who started the connection (originator IP)",
    "id.orig_p": "Originator port",
    "id.resp_h": "Who answered (responder IP)",
    "id.resp_p": "Responder port",
    "history": "Packet flags history. Upper case = originator, lower case = responder (S syn, h syn-ack, A ack, D data, F fin, R rst).",
    "orig_bytes": "Bytes sent by the originator",
    "resp_bytes": "Bytes sent by the responder",
    "missed_bytes": "Bytes lost in capture",
};

type ZeekRecord = Map<string, string>;

function value(record: ZeekRecord, key: string): string {
    return record.get(key) ?? "";
}

function inferPath(record: ZeekRecord): string {
    if (record.has("conn_state")) return "conn";
    if (record.has("query") && record.has("qtype_name")) return "dns";
    if (record.has("method") && record.has("uri")) return "http";
    if (record.has("server_name") || record.has("cipher")) return "ssl";
    if (record.has("note")) return "notice";
    if (record.has("fuid") && record.has("mime_type")) return "files";
    if (record.has("name") && record.has("addl")) return "weird";
    return "zeek";
}

function describe(path: string, record: ZeekRecord): { title: string; summary: string; severity: Severity } {
    const from = `${value(record, "id.orig_h")}:${value(record, "id.orig_p")}`;
    const to = `${value(record, "id.resp_h")}:${value(record, "id.resp_p")}`;

    switch (path) {
        case "conn": {
            const state = value(record, "conn_state");
            return {
                title: `${value(record, "proto").toUpperCase()} ${from} → ${to}${record.has("service") && value(record, "service") !== "" ? " · " + value(record, "service") : ""}`,
                summary: CONN_STATES[state] ?? `Connection state ${state}`,
                severity: "INFO",
            };
        }
        case "dns":
            return {
                title: `DNS ${value(record, "qtype_name")} ${value(record, "query")}`,
                summary: `${value(record, "rcode_name") || "no answer"}${value(record, "answers") ? " · " + value(record, "answers") : ""}`,
                severity: "INFO",
            };
        case "http": {
            const status = value(record, "status_code");
            return {
                title: `${value(record, "method")} ${value(record, "host")}${value(record, "uri")}`,
                summary: `${status || "no status"} · ${value(record, "user_agent") || "no user agent"}`,
                severity: status.startsWith("5") ? "ERROR" : status.startsWith("4") ? "WARNING" : "INFO",
            };
        }
        case "ssl":
            return {
                title: `TLS ${value(record, "server_name") || to}`,
                summary: `${value(record, "version")} · ${value(record, "established") === "T" ? "established" : "not established"}${value(record, "validation_status") ? " · cert: " + value(record, "validation_status") : ""}`,
                severity: value(record, "version").match(/SSLv|TLSv10\b|TLSv1$/) ? "WARNING" : "INFO",
            };
        case "notice":
            return {
                title: value(record, "note") || "Zeek notice",
                summary: value(record, "msg"),
                severity: /Scan|Attack|Brute|Exploit|Malware/i.test(value(record, "note")) ? "ERROR" : "WARNING",
            };
        case "weird":
            return {
                title: `Weird: ${value(record, "name")}`,
                summary: "Protocol violation or unusual traffic noticed by Zeek.",
                severity: "WARNING",
            };
        case "files":
            return {
                title: `File ${value(record, "filename") || value(record, "fuid")}`,
                summary: `${value(record, "mime_type")} · ${value(record, "total_bytes") || value(record, "seen_bytes")} bytes`,
                severity: "INFO",
            };
        default:
            return { title: `Zeek ${path} record`, summary: "", severity: "INFO" };
    }
}

function toEvent(record: ZeekRecord, path: string, raw: string, lineNumber: number): ParsedEvent {
    const timeMs = parseEpochOrDate(value(record, "ts"));
    const { title, summary, severity } = describe(path, record);
    const ip = cleanIp(value(record, "id.orig_h") || value(record, "src"));
    const state = value(record, "conn_state");

    const facets: Record<string, string> = { logType: path, severity };

    for (const [facet, key] of [["proto", "proto"], ["service", "service"], ["connState", "conn_state"], ["qtype", "qtype_name"], ["rcode", "rcode_name"], ["httpStatus", "status_code"], ["note", "note"]] as const) {
        if (record.has(key)) {
            facets[facet] = value(record, key) || "(not set)";
        }
    }

    facets.target = `${value(record, "id.resp_h")}:${value(record, "id.resp_p")}`;
    facets.port = value(record, "id.resp_p");

    return {
        lineNumber,
        raw,
        timeMs,
        timeText: value(record, "ts"),
        severity,
        title: shorten(title, 160),
        badge: path.toUpperCase(),
        summary: shorten(summary),
        metadata: [formatUtc(timeMs), value(record, "uid")].filter(part => part !== ""),
        accent: SEVERITY_COLORS[severity],
        emphasis: isSeriousSeverity(severity) || path === "notice",
        noise: false,
        ip,
        facets,
        details: () => {
            const fields: EventField[] = [];

            for (const [key, fieldValue] of record) {
                let meaning: string | null = FIELD_MEANINGS[key] ?? null;
                let risky = false;

                if (key === "conn_state") {
                    meaning = CONN_STATES[fieldValue] ?? null;
                    risky = NO_REPLY_STATES.has(fieldValue);
                }

                fields.push({ name: key, value: fieldValue, meaning, risky });
            }

            if (path === "conn" && state === "") {
                fields.push({ name: "Note", value: "", meaning: "No conn_state in this record." });
            }

            return { fields };
        },
    };
}

function unescapeZeek(text: string): string {
    return text.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)));
}

function parseTsv(content: string): ParsedEvent[] {
    const events: ParsedEvent[] = [];
    const lines = splitLines(content);
    let separator = "\t";
    let fields: string[] = [];
    let path = "zeek";
    let unset = "-";
    let empty = "(empty)";

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        if (line.trim() === "") {
            continue;
        }

        if (line.startsWith("#")) {
            const directive = /^#(\w+)\s(.*)$/.exec(line);

            if (directive === null) {
                continue;
            }

            const [, name, rest] = directive;

            if (name === "separator") {
                separator = unescapeZeek(rest.trim());
            } else if (name === "fields") {
                fields = rest.split(separator);
            } else if (name === "path") {
                path = rest.trim();
            } else if (name === "unset_field") {
                unset = rest.trim();
            } else if (name === "empty_field") {
                empty = rest.trim();
            }

            continue;
        }

        const values = line.split(separator);

        if (fields.length === 0 || values.length !== fields.length) {
            events.push(makeUnparsedEvent(line, i + 1, "Row does not match the #fields header of this Zeek log."));
            continue;
        }

        const record: ZeekRecord = new Map();

        fields.forEach((field, index) => {
            const raw = values[index];
            record.set(field, raw === unset ? "" : raw === empty ? "" : unescapeZeek(raw));
        });

        events.push(toEvent(record, path, line, i + 1));
    }

    return events;
}

function parseJson(content: string): ParsedEvent[] {
    const events: ParsedEvent[] = [];
    const lines = splitLines(content);

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        if (line.trim() === "") {
            continue;
        }

        const object = tryParseJsonObject(line);

        if (object === null) {
            events.push(makeUnparsedEvent(line, i + 1, "This line is not a valid JSON object."));
            continue;
        }

        const record: ZeekRecord = new Map();

        for (const [key, item] of Object.entries(object)) {
            record.set(key, Array.isArray(item) ? item.join(", ") : item === null ? "" : String(item));
        }

        const path = typeof object._path === "string" ? object._path : inferPath(record);
        events.push(toEvent(record, path, line, i + 1));
    }

    return events;
}

export const zeekParser: LogParser = {
    id: "zeek",
    name: "Zeek (Bro) network log",
    description: "Zeek network logs (conn, dns, http, ssl, notice, weird…) in TSV or JSON.",
    demoFile: "/static/demo/zeek.log",
    rawLabel: "Raw line",
    searchHint: "IP, domain, uid, port…",
    timeNote: "Zeek writes Unix timestamps, shown in UTC.",
    detect: sample => {
        if (/^#separator /m.test(sample) && /^#fields\t/m.test(sample)) {
            return 0.99;
        }

        const records = sampleJsonRecords(sample);

        if (records.length === 0) {
            return 0;
        }

        const zeekLike = records.filter(record => "id.orig_h" in record && "ts" in record).length;
        return zeekLike / records.length >= 0.6 ? 0.93 : 0;
    },
    parse: content => content.trimStart().startsWith("#") ? parseTsv(content) : parseJson(content),
    facets: [
        { key: "logType", title: "Zeek log", color: value => value === "notice" || value === "weird" ? SEVERITY_COLORS.WARNING : "#619aff" },
        { key: "severity", title: "Severity", order: SEVERITY_ORDER, color: severityColor },
        { key: "connState", title: "Connection state", color: value => NO_REPLY_STATES.has(value) ? SEVERITY_COLORS.WARNING : "#619aff" },
        { key: "proto", title: "Transport" },
        { key: "service", title: "Service" },
        { key: "qtype", title: "DNS query type" },
        { key: "rcode", title: "DNS response" },
        { key: "httpStatus", title: "HTTP status" },
        { key: "note", title: "Notice", color: () => SEVERITY_COLORS.ERROR },
    ],
    sourcePanel: {
        title: "Unanswered connections by source",
        emptyText: "No rejected or unanswered connections",
        subjectWord: ["target", "targets"],
        select: event => event.ip === null || !NO_REPLY_STATES.has(event.facets.connState ?? "") ? null : {
            ip: event.ip,
            subject: event.facets.target,
            tag: event.facets.port || null,
        },
        suspicion: stats => {
            if (stats.tags.size >= 15) {
                return "possible port scan";
            }

            return stats.subjects.size >= 30 ? "possible network sweep" : null;
        },
    },
};
