import { parseLineByLine, sampleLines, shareOf } from "./parseHelpers.js";
import { appFacets, AUTH_FAILED, AUTH_SOURCE_PANEL, buildAppEvent } from "./appEvents.js";
import { readSyslogHeader } from "./syslogTime.js";
const ISO_TIME = /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})\s+(.*)$/;
const CTIME = /^(?:[A-Z][a-z]{2}) ([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}:\d{2}:\d{2}) (\d{4}) (.*)$/;
const SYSLOG_TAG = /\b(?:openvpn|ovpn-[\w-]+)(?:\[\d+\])?: (.*)$/;
const PEER = /^(?:([^/\s]+)\/)?(\[AF_INET6?\])?([\d.]+|[0-9a-f:]+):(\d+) (.*)$/i;
const OPENVPN_HINT = /(OpenVPN|TLS|Peer Connection|MULTI|VERIFY|Initialization Sequence|SIGTERM|SIGUSR1|PUSH|AUTH|link remote|UDPv4|TCPv4|data channel)/;
const RULES = [
    { pattern: /Auth Username\/Password verification failed|AUTH_FAILED|failed to authenticate|auth-user-pass-verify.*fail/i, category: AUTH_FAILED, severity: "WARNING", title: "VPN login failed", meaning: "Wrong user name or password" },
    { pattern: /TLS Error: TLS key negotiation failed|TLS handshake failed/i, category: "TLS error", severity: "WARNING", title: "TLS handshake failed", meaning: "Client could not finish the encrypted handshake (wrong key, firewall, or a scanner probing the port)" },
    { pattern: /TLS Error: (?:cannot locate HMAC|incoming packet authentication failed)|tls-crypt unwrap error|HMAC authentication failed/i, category: "TLS error", severity: "WARNING", title: "Packet with wrong tls-auth / tls-crypt key", meaning: "Usually a port scanner or a client with the wrong key" },
    { pattern: /VERIFY ERROR|certificate verify failed|certificate has expired|certificate is not yet valid|CRL/i, category: "Certificate error", severity: "ERROR", title: "Client certificate rejected", meaning: "Certificate is expired, revoked or from another CA" },
    { pattern: /Peer Connection Initiated/i, category: "Connected", severity: "INFO", title: "Client connected", meaning: "Handshake finished, the VPN tunnel is up" },
    { pattern: /MULTI_sva: pool returned|MULTI: Learn: |PUSH: Received control message/i, category: "Session", severity: "DEBUG", title: "Address assigned / route learned", meaning: "Internal VPN address handed to the client" },
    { pattern: /SIGTERM|SIGUSR1|client-instance exiting|Connection reset|Inactivity timeout|ping-restart/i, category: "Disconnected", severity: "INFO", title: "Client disconnected", meaning: "Tunnel closed (client quit, timeout or restart)" },
    { pattern: /Initialization Sequence Completed/i, category: "Server", severity: "INFO", title: "VPN server / client started", meaning: "OpenVPN finished starting" },
    { pattern: /Bad LZO|Fatal|Exiting due to fatal error|Cannot open|Options error/i, category: "Error", severity: "ERROR", title: "OpenVPN error", meaning: "OpenVPN reported a serious error" },
    { pattern: /WARNING/, category: "Warning", severity: "WARNING", title: "OpenVPN warning", meaning: "Configuration or security warning" },
];
function readTime(line) {
    const iso = ISO_TIME.exec(line);
    if (iso) {
        return [Date.parse(`${iso[1]}T${iso[2]}Z`), `${iso[1]} ${iso[2]}`, iso[3]];
    }
    const ctime = CTIME.exec(line);
    if (ctime) {
        const [, month, day, time, year, rest] = ctime;
        return [Date.parse(`${month} ${day} ${year} ${time} UTC`), `${month} ${day} ${year} ${time}`, rest];
    }
    const header = readSyslogHeader(line);
    const tag = SYSLOG_TAG.exec(line);
    return header && tag ? [header.timeMs, header.timeText, tag[1]] : null;
}
function parseOpenvpnLine(line, lineNumber) {
    const time = readTime(line);
    if (time === null || !OPENVPN_HINT.test(line)) {
        return null;
    }
    const [timeMs, timeText, message] = time;
    const peer = PEER.exec(message);
    const text = peer ? peer[5] : message;
    const rule = RULES.find(item => item.pattern.test(text));
    const userFromText = /user '([^']+)'|\[([^\]]+)\] Peer Connection|username ['"]?([^'"\s]+)/i.exec(text);
    const user = peer?.[1] ?? userFromText?.[1] ?? userFromText?.[2] ?? userFromText?.[3] ?? null;
    return buildAppEvent({
        lineNumber,
        raw: line,
        timeMs,
        timeText,
        severity: rule?.severity ?? "INFO",
        category: rule?.category ?? "Other",
        title: rule ? `${rule.title}${user ? ` · ${user}` : ""}` : text,
        badge: (rule?.category ?? "info").toUpperCase(),
        summary: rule ? `${rule.meaning} · ${text}` : "",
        ip: peer?.[3] ?? null,
        user,
        noise: rule?.severity === "DEBUG",
        fields: [
            { name: "Message", value: text, meaning: rule?.meaning ?? null, risky: rule?.category === AUTH_FAILED || rule?.category === "Certificate error" },
            ...(peer ? [{ name: "Client address", value: `${peer[3]}:${peer[4]}` }] : []),
            ...(user ? [{ name: "User / certificate name", value: user }] : []),
        ],
    });
}
export const openvpnParser = {
    id: "openvpn",
    name: "OpenVPN log",
    description: "OpenVPN server or client log: connections, failed logins, TLS and certificate errors.",
    demoFile: "/static/demo/openvpn.log",
    rawLabel: "Raw line",
    searchHint: "User, IP, TLS, AUTH…",
    timeNote: "OpenVPN writes local time without a zone. Shown as written.",
    detect: sample => {
        const lines = sampleLines(sample);
        const share = shareOf(lines, line => readTime(line) !== null && OPENVPN_HINT.test(line));
        const strong = /Peer Connection Initiated|Initialization Sequence Completed|OpenVPN \d|MULTI_sva|TLS Error/.test(sample);
        return strong && share >= 0.4 ? 0.95 : 0;
    },
    parse: content => parseLineByLine(content, parseOpenvpnLine, {
        reason: "This line does not look like an OpenVPN log message.",
        isContinuation: () => false,
    }),
    facets: appFacets([AUTH_FAILED, "Certificate error", "TLS error", "Error", "Warning", "Connected", "Disconnected", "Session", "Server", "Other"]),
    sourcePanel: {
        ...AUTH_SOURCE_PANEL,
        title: "Failed VPN logins and TLS errors by IP",
        emptyText: "No failed VPN logins with a client IP",
        select: event => event.ip === null || ![AUTH_FAILED, "TLS error", "Certificate error"].includes(event.facets.category) ? null : {
            ip: event.ip,
            subject: event.facets.user === "(none)" ? null : event.facets.user,
            tag: event.facets.category,
        },
        suspicion: stats => {
            if (stats.tags.has(AUTH_FAILED)) {
                return AUTH_SOURCE_PANEL.suspicion(stats);
            }
            return stats.tags.has("TLS error") && stats.count >= 5 ? "probing the VPN port (scanner or wrong key)" : null;
        },
    },
    noise: { label: "Address / route details", hint: "Internal session details (address pool, routes). Click to show them." },
    coverage: () => ({
        summary: "Every line is shown. These messages get a category and an explanation:",
        groups: [{ title: "Recognized messages", items: RULES.map(rule => `${rule.title} — ${rule.meaning}`) }],
    }),
};
