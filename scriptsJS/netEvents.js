import { cleanIp, formatUtc, shorten } from "./parseHelpers.js";
import { SEVERITY_COLORS, SEVERITY_ORDER, severityColor } from "./severity.js";
export const LOGIN_FAILED_FLAG = "failed login";
export const SIGNATURE_FLAG = "attack signature";
const SERVICES = {
    "20": "FTP data", "21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP", "53": "DNS", "67": "DHCP", "68": "DHCP",
    "69": "TFTP", "80": "HTTP", "88": "Kerberos", "110": "POP3", "123": "NTP", "135": "Windows RPC", "137": "NetBIOS",
    "138": "NetBIOS", "139": "NetBIOS/SMB", "143": "IMAP", "161": "SNMP", "389": "LDAP", "443": "HTTPS", "445": "SMB",
    "465": "SMTPS", "500": "IPsec IKE", "514": "Syslog", "587": "SMTP submission", "636": "LDAPS", "993": "IMAPS",
    "995": "POP3S", "1194": "OpenVPN", "1433": "MS SQL", "1521": "Oracle DB", "1723": "PPTP VPN", "1900": "SSDP",
    "2049": "NFS", "2375": "Docker API", "3128": "Proxy", "3306": "MySQL", "3389": "RDP", "4444": "Metasploit default",
    "4500": "IPsec NAT-T", "5060": "SIP", "5353": "mDNS", "5432": "PostgreSQL", "5900": "VNC", "5985": "WinRM",
    "5986": "WinRM HTTPS", "6379": "Redis", "6443": "Kubernetes API", "8080": "HTTP alt", "8443": "HTTPS alt",
    "9200": "Elasticsearch", "11211": "Memcached", "27017": "MongoDB", "51820": "WireGuard",
};
const RISKY_PORTS = new Set(["23", "135", "139", "445", "1433", "2375", "3306", "3389", "4444", "5432", "5900", "5985", "5986", "6379", "9200", "11211", "27017"]);
const ACTION_COLORS = {
    Allow: "#5dc98b",
    Block: "#f08262",
    Other: "#87909e",
};
const PORT_SCAN_PORTS = 10;
const SWEEP_HOSTS = 10;
const MANY_BLOCKS = 20;
const REPEATED_BLOCKS = 8;
export function serviceName(port) {
    return port === null ? null : SERVICES[port] ?? null;
}
export function serviceLabel(port) {
    if (port === null || port === "") {
        return "(no port)";
    }
    const name = serviceName(port);
    return name === null ? `port ${port}` : `${name} (${port})`;
}
export function isRiskyPort(port) {
    return port !== null && RISKY_PORTS.has(port);
}
export function isPrivateIp(ip) {
    if (ip === null) {
        return false;
    }
    return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|fe80:|fc|fd|::1$)/i.test(ip);
}
export function normalizeAction(text) {
    const value = (text ?? "").trim().toLowerCase();
    if (/^(allow|allowed|accept|accepted|permit|permitted|pass|built|teardown|close|start|ok|server-rst|client-rst|timeout)/.test(value)) {
        return "Allow";
    }
    if (/^(deny|denied|drop|dropped|block|blocked|reject|rejected|reset|reset-both|reset-client|reset-server|discard|blackhole)/.test(value)) {
        return "Block";
    }
    return "Other";
}
function endpoint(ip, port) {
    if (ip === null) {
        return "?";
    }
    const host = ip.includes(":") ? `[${ip}]` : ip;
    return port === null || port === "" ? host : `${host}:${port}`;
}
export function buildNetEvent(record) {
    const srcIp = cleanIp(record.srcIp);
    const dstIp = cleanIp(record.dstIp);
    const service = serviceName(record.dstPort);
    const risky = isRiskyPort(record.dstPort);
    const inboundFromInternet = srcIp !== null && !isPrivateIp(srcIp) && isPrivateIp(dstIp);
    const exposed = record.action === "Allow" && risky && inboundFromInternet;
    let severity = record.severity ?? (record.action === "Block" ? "WARNING" : "INFO");
    if (exposed && severity === "INFO") {
        severity = "WARNING";
    }
    const verb = record.action === "Block" ? "Blocked" : record.action === "Allow" ? "Allowed" : record.actionText || "Connection";
    const protocol = record.protocol.toUpperCase() || "IP";
    const title = record.title ?? `${verb} ${protocol} ${endpoint(srcIp, record.srcPort)} → ${endpoint(dstIp, record.dstPort)}${service !== null ? ` · ${service}` : ""}`;
    const summaryParts = [];
    if (record.note) {
        summaryParts.push(record.note);
    }
    if (exposed) {
        summaryParts.push(`${service ?? "Sensitive service"} reachable from the internet`);
    }
    else if (risky && record.action === "Block") {
        summaryParts.push(`Attempt to reach ${service ?? `port ${record.dstPort}`}, a service often attacked`);
    }
    if (record.rule) {
        summaryParts.push(`rule: ${record.rule}`);
    }
    const metadata = [formatUtc(record.timeMs)];
    if (record.device) {
        metadata.push(record.device);
    }
    if (record.direction) {
        metadata.push(record.direction);
    }
    if (srcIp !== null) {
        metadata.push(`IP: ${srcIp}`);
    }
    return {
        lineNumber: record.lineNumber,
        raw: record.raw,
        timeMs: record.timeMs,
        timeText: record.timeText,
        severity,
        title: shorten(title, 180),
        badge: record.badge ?? (record.actionText.toUpperCase() || record.action.toUpperCase()),
        summary: shorten(summaryParts.join(" · ")),
        metadata,
        accent: severity === "ERROR" || severity === "CRITICAL" ? SEVERITY_COLORS[severity] : ACTION_COLORS[record.action],
        emphasis: exposed || severity === "ERROR" || severity === "CRITICAL",
        noise: false,
        ip: srcIp,
        facets: {
            action: record.action,
            protocol,
            service: record.dstPort === null ? "(no port)" : service ?? "Other ports",
            direction: record.direction ?? "(not set)",
            severity,
            dstPort: record.dstPort ?? "",
            dstIp: dstIp ?? "",
            flag: record.flag ?? "",
        },
        details: () => {
            const fields = [
                { name: "Action", value: record.actionText, meaning: record.action === "Block" ? "The connection was stopped" : record.action === "Allow" ? "The connection was let through" : null, risky: exposed },
                { name: "Protocol", value: protocol },
                { name: "Source", value: endpoint(srcIp, record.srcPort), meaning: srcIp === null ? null : isPrivateIp(srcIp) ? "Private (internal) address" : "Public (internet) address" },
                { name: "Destination", value: endpoint(dstIp, record.dstPort), meaning: record.dstPort === null ? null : `${serviceLabel(record.dstPort)}${risky ? " — often targeted by attackers" : ""}`, risky },
            ];
            return { fields: [...fields, ...record.fields] };
        },
    };
}
export const NET_FACETS = [
    { key: "action", title: "Action", order: ["Block", "Allow", "Other"], color: value => ACTION_COLORS[value] ?? "#87909e" },
    { key: "service", title: "Service", color: value => [...RISKY_PORTS].some(port => SERVICES[port] === value) ? SEVERITY_COLORS.WARNING : "#619aff" },
    { key: "protocol", title: "Protocol" },
    { key: "direction", title: "Direction" },
    { key: "severity", title: "Severity", order: SEVERITY_ORDER, color: severityColor },
];
export const NET_SOURCE_PANEL = {
    title: "Blocked connections by source IP",
    emptyText: "No blocked connections with a source IP",
    subjectWord: ["port", "ports"],
    select: event => event.ip === null || (event.facets.action !== "Block" && !event.facets.flag) ? null : {
        ip: event.ip,
        subject: event.facets.dstPort === "" ? null : event.facets.dstPort,
        tag: event.facets.flag || (event.facets.dstIp === "" ? null : event.facets.dstIp),
    },
    suspicion: stats => {
        if (stats.tags.has(SIGNATURE_FLAG)) {
            return "attack signatures matched";
        }
        if (stats.tags.has(LOGIN_FAILED_FLAG) && stats.count >= 5) {
            return "repeated failed logins";
        }
        if (stats.subjects.size >= PORT_SCAN_PORTS) {
            return "possible port scan";
        }
        if ([...stats.tags].filter(tag => tag !== LOGIN_FAILED_FLAG).length >= SWEEP_HOSTS) {
            return "possible network sweep";
        }
        if (stats.subjects.size === 1 && stats.count >= REPEATED_BLOCKS) {
            return `repeated attempts on ${serviceLabel([...stats.subjects][0])}`;
        }
        return stats.count >= MANY_BLOCKS ? "many blocked attempts" : null;
    },
};
export function netCoverage(intro) {
    return {
        summary: `${intro} Blocked connections are grouped by source IP: many ports from one IP means a port scan, many hosts means a network sweep.`,
        groups: [
            { title: "Services recognized by port", items: Object.entries(SERVICES).map(([port, name]) => `${port} — ${name}${RISKY_PORTS.has(port) ? " (often attacked)" : ""}`) },
        ],
    };
}
export function kvPairs(text) {
    const result = new Map();
    const pattern = /([\w.-]+)=("(?:[^"\\]|\\.)*"|\S*)/g;
    for (const match of text.matchAll(pattern)) {
        const value = match[2].startsWith("\"") ? match[2].slice(1, -1).replace(/\\"/g, "\"") : match[2];
        result.set(match[1], value);
    }
    return result;
}
