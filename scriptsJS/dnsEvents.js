import { cleanIp, formatUtc, shorten } from "./parseHelpers.js";
import { SEVERITY_COLORS, SEVERITY_ORDER, severityColor } from "./severity.js";
export const NOT_SUSPICIOUS = "None detected";
const LONG_LABEL = 40;
const LONG_NAME = 100;
const ENTROPY_LIMIT = 3.8;
const QTYPE_MEANINGS = {
    A: "IPv4 address", AAAA: "IPv6 address", CNAME: "Alias", MX: "Mail server", TXT: "Text record (also used for DNS tunneling)",
    NS: "Name server", PTR: "Reverse lookup (IP → name)", SRV: "Service location (e.g. Active Directory)", SOA: "Zone info",
    ANY: "Everything (often used in DNS amplification attacks)", AXFR: "Zone transfer (leaks the whole zone if allowed)", HTTPS: "HTTPS service info",
    NULL: "NULL record (rare; used by tunneling tools like iodine)",
};
const RESPONSE_MEANINGS = {
    NOERROR: "Answered normally",
    NXDOMAIN: "Name does not exist — many of these from one device can mean malware (DGA)",
    SERVFAIL: "Server failed to answer",
    REFUSED: "Server refused to answer",
    FORMERR: "Malformed query",
    Blocked: "Blocked by the DNS filter (ad, tracker or malware list)",
};
function entropy(text) {
    const counts = new Map();
    for (const char of text) {
        counts.set(char, (counts.get(char) ?? 0) + 1);
    }
    let result = 0;
    for (const count of counts.values()) {
        const share = count / text.length;
        result -= share * Math.log2(share);
    }
    return result;
}
export function suspiciousName(name, qtype) {
    const labels = name.toLowerCase().replace(/\.$/, "").split(".");
    const sub = labels.slice(0, -2).join("");
    const longest = labels.reduce((max, label) => label.length > max.length ? label : max, "");
    if (["AXFR", "IXFR"].includes(qtype)) {
        return "Zone transfer request";
    }
    if (longest.length >= LONG_LABEL || name.length >= LONG_NAME) {
        return "Very long name (possible DNS tunneling)";
    }
    if (sub.length >= 16 && entropy(sub) >= ENTROPY_LIMIT) {
        return "Random-looking name (possible tunneling or DGA)";
    }
    if (qtype === "NULL") {
        return "NULL record (tunneling tools)";
    }
    return null;
}
export function baseDomain(name) {
    const labels = name.toLowerCase().replace(/\.$/, "").split(".");
    return labels.length <= 2 ? labels.join(".") : labels.slice(-2).join(".");
}
export function buildDnsEvent(record) {
    const client = cleanIp(record.client);
    const suspicious = record.kind === "Other" ? null : suspiciousName(record.query, record.qtype);
    const response = record.kind === "Blocked" ? "Blocked" : record.response ?? null;
    let severity = "INFO";
    if (suspicious !== null) {
        severity = "WARNING";
    }
    else if (record.kind === "Blocked" || response === "NXDOMAIN" || response === "SERVFAIL" || response === "REFUSED") {
        severity = "WARNING";
    }
    if (record.noise) {
        severity = "DEBUG";
    }
    const verb = record.kind === "Query" ? "Query" : record.kind === "Blocked" ? "Blocked" : record.kind;
    const title = record.kind === "Other" ? record.query : `${verb} ${record.qtype ? record.qtype + " " : ""}${record.query}`;
    const summary = [
        suspicious,
        response !== null ? RESPONSE_MEANINGS[response] ?? response : "",
        record.answer ? `answer: ${shorten(record.answer, 80)}` : "",
        client !== null ? `from ${client}` : "",
    ].filter(Boolean).join(" · ");
    const metadata = [formatUtc(record.timeMs)];
    if (record.server) {
        metadata.push(record.server);
    }
    if (client !== null) {
        metadata.push(`IP: ${client}`);
    }
    return {
        lineNumber: record.lineNumber,
        raw: record.raw,
        timeMs: record.timeMs,
        timeText: record.timeText,
        severity,
        title: shorten(title, 180),
        badge: (response ?? record.kind).toUpperCase(),
        summary: shorten(summary),
        metadata,
        accent: suspicious !== null ? SEVERITY_COLORS.ERROR : record.kind === "Blocked" ? "#f08262" : SEVERITY_COLORS[severity],
        emphasis: suspicious !== null,
        noise: record.noise ?? false,
        ip: client,
        facets: {
            kind: record.kind,
            qtype: record.qtype || "(none)",
            response: response ?? "(none)",
            suspicious: suspicious ?? NOT_SUSPICIOUS,
            severity,
            domain: baseDomain(record.query),
        },
        details: () => ({
            fields: [
                { name: "Name", value: record.query, meaning: suspicious, risky: suspicious !== null },
                { name: "Record type", value: record.qtype, meaning: QTYPE_MEANINGS[record.qtype] ?? null },
                { name: "Client", value: record.client ?? "" },
                ...(response !== null ? [{ name: "Response", value: response, meaning: RESPONSE_MEANINGS[response] ?? null }] : []),
                ...(record.answer ? [{ name: "Answer", value: record.answer }] : []),
                ...record.fields,
            ],
        }),
    };
}
export const DNS_FACETS = [
    { key: "suspicious", title: "Suspicious name", color: value => value === NOT_SUSPICIOUS ? "#87909e" : SEVERITY_COLORS.ERROR },
    { key: "response", title: "Response", color: value => value === "NOERROR" ? "#5dc98b" : value === "(none)" ? "#87909e" : SEVERITY_COLORS.WARNING },
    { key: "qtype", title: "Record type" },
    { key: "kind", title: "Line type" },
    { key: "severity", title: "Severity", order: SEVERITY_ORDER, color: severityColor },
];
export const DNS_NOISE = {
    label: "Forwarded / reply / cached lines",
    hint: "dnsmasq writes several lines for one lookup. Shown: the query and blocked lines. Click to show the rest.",
};
export const DNS_SOURCE_PANEL = {
    title: "DNS clients worth a look",
    emptyText: "No suspicious, blocked or failed lookups with a client IP",
    subjectWord: ["domain", "domains"],
    select: event => {
        const interesting = event.facets.suspicious !== NOT_SUSPICIOUS || ["NXDOMAIN", "Blocked", "SERVFAIL", "REFUSED"].includes(event.facets.response);
        if (event.ip === null || !interesting) {
            return null;
        }
        return {
            ip: event.ip,
            subject: event.facets.domain,
            tag: event.facets.suspicious !== NOT_SUSPICIOUS ? event.facets.suspicious : event.facets.response,
        };
    },
    suspicion: stats => {
        if ([...stats.tags].some(tag => tag.includes("tunneling") || tag.includes("DGA") || tag.includes("Zone transfer"))) {
            return "possible DNS tunneling / malware";
        }
        if (stats.tags.has("NXDOMAIN") && stats.subjects.size >= 10) {
            return "many names that do not exist (possible DGA)";
        }
        return stats.tags.has("Blocked") && stats.count >= 20 ? "many blocked lookups" : null;
    },
};
export function dnsCoverage(intro) {
    return {
        summary: `${intro} Names are checked for signs of DNS tunneling and malware: very long labels, random-looking names, zone transfers.`,
        groups: [
            { title: "Record types", items: Object.entries(QTYPE_MEANINGS).map(([key, text]) => `${key} — ${text}`) },
            { title: "Responses", items: Object.entries(RESPONSE_MEANINGS).map(([key, text]) => `${key} — ${text}`) },
        ],
    };
}
