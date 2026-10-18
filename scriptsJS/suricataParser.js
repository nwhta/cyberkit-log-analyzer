import { cleanIp, flattenObject, formatUtc, getPath, parseEpochOrDate, shorten } from "./parseHelpers.js";
import { SEVERITY_COLORS, SEVERITY_ORDER, isSeriousSeverity, severityColor } from "./severity.js";
import { readJsonLines, sampleJsonRecords } from "./jsonRecords.js";
const EVENT_TYPE_MEANINGS = {
    alert: "A detection rule (signature) matched this traffic.",
    anomaly: "Traffic that breaks protocol rules. Can be a broken client or an evasion attempt.",
    drop: "Packet dropped by Suricata in IPS mode.",
    flow: "Summary of a finished network connection.",
    netflow: "One direction of a network connection.",
    dns: "DNS query or answer.",
    http: "HTTP request seen on the network.",
    tls: "TLS handshake (server name, certificate).",
    ssh: "SSH handshake (client and server versions).",
    fileinfo: "File transferred over the network.",
    smb: "Windows file sharing (SMB) activity.",
    stats: "Suricata's own performance counters.",
};
const ALERT_SEVERITY = {
    1: "CRITICAL",
    2: "ERROR",
    3: "WARNING",
};
function text(record, path) {
    const value = getPath(record, path);
    return value === undefined || value === null ? "" : String(value);
}
function dnsQueryName(record) {
    const queries = getPath(record, "dns.queries");
    if (!Array.isArray(queries) || queries.length === 0) {
        return "";
    }
    const first = queries[0];
    return first && typeof first.rrname === "string" ? first.rrname : "";
}
function describe(record, eventType) {
    switch (eventType) {
        case "alert":
            return text(record, "alert.signature") || "Alert";
        case "dns":
            return `DNS ${text(record, "dns.type")} ${text(record, "dns.rrname") || dnsQueryName(record)}`.trim();
        case "http":
            return `${text(record, "http.http_method")} ${text(record, "http.hostname")}${text(record, "http.url")}`.trim();
        case "tls":
            return `TLS ${text(record, "tls.sni") || text(record, "tls.subject")}`.trim();
        case "fileinfo":
            return `File ${text(record, "fileinfo.filename")}`;
        case "anomaly":
            return `Anomaly: ${text(record, "anomaly.event") || text(record, "anomaly.type")}`;
        case "flow":
            return `Flow ${text(record, "app_proto") || text(record, "proto")} · ${text(record, "flow.state")}`;
        default:
            return eventType === "" ? "Suricata event" : `${eventType} event`;
    }
}
function toEvent({ record, raw, lineNumber }) {
    const eventType = text(record, "event_type");
    const timeMs = parseEpochOrDate(getPath(record, "timestamp"));
    const srcIp = cleanIp(text(record, "src_ip"));
    const destIp = cleanIp(text(record, "dest_ip"));
    const alertSeverity = Number(getPath(record, "alert.severity"));
    const action = text(record, "alert.action");
    let severity = "INFO";
    if (eventType === "alert") {
        severity = ALERT_SEVERITY[alertSeverity] ?? "WARNING";
    }
    else if (eventType === "anomaly" || eventType === "drop") {
        severity = "WARNING";
    }
    else if (eventType === "stats") {
        severity = "DEBUG";
    }
    const connection = `${srcIp ?? "?"}:${text(record, "src_port")} → ${destIp ?? "?"}:${text(record, "dest_port")} ${text(record, "proto")}`;
    const metadata = [formatUtc(timeMs), connection];
    if (text(record, "app_proto") !== "") {
        metadata.push(text(record, "app_proto"));
    }
    return {
        lineNumber,
        raw,
        timeMs,
        timeText: text(record, "timestamp"),
        severity,
        title: shorten(describe(record, eventType), 160),
        badge: eventType === "alert" ? `ALERT · ${action || "allowed"}` : eventType.toUpperCase(),
        summary: eventType === "alert" ? `${text(record, "alert.category")} · rule ${text(record, "alert.signature_id")}` : EVENT_TYPE_MEANINGS[eventType] ?? "",
        metadata,
        accent: SEVERITY_COLORS[severity],
        emphasis: isSeriousSeverity(severity),
        noise: false,
        ip: srcIp,
        facets: {
            eventType: eventType || "(not set)",
            severity,
            category: text(record, "alert.category") || "(no alert)",
            proto: text(record, "app_proto") || text(record, "proto") || "(not set)",
            signature: text(record, "alert.signature"),
        },
        details: () => {
            const fields = flattenObject(record).map(([name, value]) => {
                if (name === "event_type") {
                    return { name, value, meaning: EVENT_TYPE_MEANINGS[value] ?? null };
                }
                if (name === "alert.severity") {
                    return { name, value, meaning: "Suricata severity: 1 = high, 2 = medium, 3 = low.", risky: value === "1" };
                }
                if (name === "alert.action") {
                    return { name, value, meaning: value === "blocked" ? "Traffic was blocked (IPS mode)." : "Traffic was only logged, not blocked." };
                }
                return { name, value };
            });
            const payload = text(record, "payload_printable");
            const sections = payload === "" ? [] : [{ title: "Payload (printable)", text: payload }];
            return { fields, sections };
        },
    };
}
export const suricataParser = {
    id: "suricata-eve",
    name: "Suricata IDS (eve.json)",
    description: "eve.json from the Suricata IDS / IPS: alerts, DNS, HTTP, TLS, files, flows.",
    demoFile: "/static/demo/suricata-eve.json",
    rawLabel: "Raw JSON",
    searchHint: "Signature, IP, domain, SID…",
    timeNote: "Converted to UTC using the offset in each timestamp.",
    detect: sample => {
        const records = sampleJsonRecords(sample);
        if (records.length === 0) {
            return 0;
        }
        const matching = records.filter(record => ("event_type" in record && "src_ip" in record) || record.event_type === "stats");
        return matching.length / records.length >= 0.6 ? 0.95 : 0;
    },
    parse: content => readJsonLines(content, toEvent, "This line is not a valid JSON object."),
    facets: [
        { key: "eventType", title: "Event type", color: value => value === "alert" ? SEVERITY_COLORS.ERROR : "#619aff" },
        { key: "severity", title: "Severity", order: SEVERITY_ORDER, color: severityColor },
        { key: "category", title: "Alert category", color: value => value === "(no alert)" ? "#87909e" : SEVERITY_COLORS.WARNING },
        { key: "proto", title: "Protocol" },
    ],
    sourcePanel: {
        title: "Alerts by source IP",
        emptyText: "No alerts with a source IP",
        subjectWord: ["signature", "signatures"],
        select: event => event.facets.eventType !== "alert" || event.ip === null ? null : {
            ip: event.ip,
            subject: event.facets.signature || null,
            tag: event.severity === "CRITICAL" ? "high" : null,
        },
        suspicion: stats => {
            if (stats.tags.size > 0) {
                return "high-severity alert";
            }
            return stats.subjects.size >= 3 || stats.count >= 10 ? "repeated alerts" : null;
        },
    },
};
