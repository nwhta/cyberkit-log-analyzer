import { parseLineByLine, sampleLines, shareOf, shorten } from "./parseHelpers.js";
import { SEVERITY_COLORS, isSeriousSeverity } from "./severity.js";
import { buildNetEvent, LOGIN_FAILED_FLAG, NET_FACETS, NET_SOURCE_PANEL, netCoverage, normalizeAction, SIGNATURE_FLAG } from "./netEvents.js";
import { parseCsv } from "./structured.js";
const PAN_START = /(?:^|\s)\d*,(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),[^,]*,(TRAFFIC|THREAT|SYSTEM|CONFIG|GLOBALPROTECT|AUTH|USERID|HIPMATCH|DECRYPTION|URL|WILDFIRE),/;
const COMMON = ["Future use", "Receive time", "Serial number", "Type", "Subtype", "Future use", "Generated time"];
const NET_NAMES = [
    "Source address", "Destination address", "NAT source IP", "NAT destination IP", "Rule", "Source user", "Destination user",
    "Application", "Virtual system", "Source zone", "Destination zone", "Inbound interface", "Outbound interface", "Log action",
    "Future use", "Session ID", "Repeat count", "Source port", "Destination port", "NAT source port", "NAT destination port",
    "Flags", "Protocol", "Action",
];
const TRAFFIC_NAMES = [...COMMON, ...NET_NAMES, "Bytes", "Bytes sent", "Bytes received", "Packets", "Start time", "Elapsed (s)", "Category"];
const THREAT_NAMES = [...COMMON, ...NET_NAMES, "URL / file name", "Threat / content name", "Category", "Severity", "Direction"];
const SYSTEM_NAMES = [...COMMON, "Virtual system", "Event ID", "Object", "Future use", "Future use", "Module", "Severity", "Description"];
const CONFIG_NAMES = [...COMMON, "Host", "Virtual system", "Command", "Admin", "Client", "Result", "Configuration path"];
const SUBTYPE_MEANINGS = {
    start: "Session started", end: "Session ended", drop: "Dropped before a session was created", deny: "Denied by a security rule",
    vulnerability: "Exploit attempt matched a vulnerability signature", virus: "Malware detected", spyware: "Spyware / command-and-control traffic",
    url: "URL filtering", wildfire: "WildFire sandbox verdict", file: "File transfer blocked or logged", flood: "Flood (DoS) protection",
    scan: "Port / host scan detected", "wildfire-virus": "WildFire found malware",
};
const THREAT_SEVERITY = { critical: "CRITICAL", high: "ERROR", medium: "WARNING", low: "INFO", informational: "INFO" };
function panTime(text) {
    return Date.parse(text.replace(/\//g, "-").replace(" ", "T") + "Z");
}
function fieldsOf(values, names) {
    return values.map((value, index) => ({ name: names[index] ?? `Field ${index + 1}`, value })).filter(field => field.value !== "" && field.name !== "Future use");
}
function parsePanLine(line, lineNumber) {
    const match = PAN_START.exec(line);
    if (!match) {
        return null;
    }
    const start = match.index + (/^\s/.test(match[0]) ? 1 : 0);
    const values = parseCsv(line.slice(start).trim())[0] ?? [];
    const type = values[3] ?? "";
    const subtype = values[4] ?? "";
    const generated = values[6] ?? values[1] ?? "";
    const timeMs = panTime(generated);
    const host = line.slice(0, start).trim().split(/\s+/).pop() ?? "";
    if (type === "TRAFFIC" || type === "THREAT") {
        const isThreat = type === "THREAT";
        const threatName = isThreat ? values[32] ?? "" : "";
        const threatSeverity = isThreat ? THREAT_SEVERITY[(values[34] ?? "").toLowerCase()] ?? "WARNING" : undefined;
        const actionText = values[30] ?? subtype;
        const user = values[12] ?? "";
        return buildNetEvent({
            lineNumber,
            raw: line,
            timeMs,
            timeText: generated,
            action: subtype === "deny" || subtype === "drop" ? "Block" : normalizeAction(actionText),
            actionText,
            protocol: values[29] ?? "",
            srcIp: values[7] ?? null,
            srcPort: values[24] ?? null,
            dstIp: values[8] ?? null,
            dstPort: values[25] ?? null,
            direction: values[16] && values[17] ? `${values[16]} → ${values[17]}` : null,
            device: host || values[2] || null,
            rule: values[11] || null,
            severity: threatSeverity,
            title: isThreat ? shorten(threatName.replace(/\(\d+\)$/, "").trim() || `Threat (${subtype})`, 160) : undefined,
            badge: isThreat ? `${subtype.toUpperCase()} · ${actionText.toUpperCase()}` : actionText.toUpperCase(),
            flag: isThreat && subtype !== "url" ? SIGNATURE_FLAG : null,
            note: [SUBTYPE_MEANINGS[subtype], values[14] ? `app: ${values[14]}` : "", user ? `user: ${user}` : "", isThreat && values[31] ? shorten(values[31], 100) : ""].filter(Boolean).join(" · ") || null,
            fields: fieldsOf(values, isThreat ? THREAT_NAMES : TRAFFIC_NAMES).filter(field => !["Source address", "Destination address", "Source port", "Destination port", "Protocol", "Action"].includes(field.name)),
        });
    }
    const names = type === "SYSTEM" ? SYSTEM_NAMES : type === "CONFIG" ? CONFIG_NAMES : COMMON;
    const severity = type === "SYSTEM" ? THREAT_SEVERITY[(values[13] ?? "").toLowerCase()] ?? "INFO" : type === "CONFIG" ? "WARNING" : "INFO";
    const failedLogin = /fail(?:ed)? auth|authentication fail|login fail/i.test(values.join(" "));
    const fromIp = /From:\s*(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]*:[0-9a-f:]+)/i.exec(values[14] ?? "")?.[1] ?? null;
    const title = type === "SYSTEM" ? values[14] ?? "" : type === "CONFIG" ? `${values[10] ?? "admin"} ran "${values[9] ?? ""}" on ${values[13] ?? ""}` : [...values].sort((a, b) => b.length - a.length)[0] ?? type;
    return {
        lineNumber,
        raw: line,
        timeMs,
        timeText: generated,
        severity,
        title: shorten(title || `${type} ${subtype}`, 180),
        badge: `${type} · ${subtype}`.toUpperCase(),
        summary: type === "CONFIG" ? `Configuration change by ${values[10] ?? "?"} from ${values[11] ?? "?"} · result: ${values[12] ?? "?"}` : `${type} log`,
        metadata: [new Date(timeMs).toISOString().replace("T", " ").slice(0, 19) + " UTC", host || values[2] || ""].filter(Boolean),
        accent: SEVERITY_COLORS[severity],
        emphasis: isSeriousSeverity(severity),
        noise: false,
        ip: fromIp,
        facets: { action: failedLogin ? "Block" : "Other", protocol: "-", service: "(no port)", direction: `${type}`, severity, dstPort: "", dstIp: "", flag: failedLogin ? LOGIN_FAILED_FLAG : "" },
        details: () => ({ fields: fieldsOf(values, names) }),
    };
}
export const paloAltoParser = {
    id: "paloalto",
    name: "Palo Alto Networks (PAN-OS)",
    description: "PAN-OS syslog CSV: TRAFFIC, THREAT, SYSTEM and CONFIG logs from Palo Alto firewalls.",
    demoFile: "/static/demo/paloalto.log",
    rawLabel: "Raw line",
    searchHint: "IP, rule, app, threat, user…",
    timeNote: "PAN-OS writes the firewall's local time without a zone. Shown as written.",
    detect: sample => {
        const share = shareOf(sampleLines(sample), line => PAN_START.test(line));
        return share >= 0.5 ? 0.97 : share * 0.9;
    },
    parse: content => parseLineByLine(content, parsePanLine, {
        reason: "This line is not a PAN-OS CSV log (…,receive time,serial,TYPE,subtype,…).",
        isContinuation: () => false,
    }),
    facets: NET_FACETS,
    sourcePanel: NET_SOURCE_PANEL,
    coverage: () => {
        const base = netCoverage("Every line is shown. TRAFFIC and THREAT logs are read field by field; SYSTEM and CONFIG get a short summary.");
        base.groups.unshift({ title: "Subtypes", items: Object.entries(SUBTYPE_MEANINGS).map(([key, text]) => `${key} — ${text}`) });
        return base;
    },
};
