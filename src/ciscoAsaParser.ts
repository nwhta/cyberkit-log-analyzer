import type { Severity } from "./types.js";
import type { LogParser, ParsedEvent } from "./parserTypes.js";
import { parseLineByLine, sampleLines, shareOf, shorten } from "./parseHelpers.js";
import { buildNetEvent, LOGIN_FAILED_FLAG, NET_FACETS, NET_SOURCE_PANEL, netCoverage, SIGNATURE_FLAG, type NetAction } from "./netEvents.js";
import { bsdTime, parseIsoTime } from "./syslogTime.js";

const ASA_MARKER = /%(ASA|FTD|PIX|FWSM)-(\d)-(\d{6}):\s*(.*)$/;
const ADDRESS = /(?:([A-Za-z][\w.-]*)[:/])?(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:[0-9a-fA-F:]+)(?:\/(\d+|ssh|https|http|telnet|asdm)|\((\d+)\))?/g;
const NAMED_PORTS: Readonly<Record<string, string>> = { ssh: "22", https: "443", http: "80", telnet: "23", asdm: "443" };

const LEVELS: Readonly<Record<string, [Severity, string]>> = {
    "0": ["CRITICAL", "Emergency"], "1": ["CRITICAL", "Alert"], "2": ["CRITICAL", "Critical"], "3": ["ERROR", "Error"],
    "4": ["WARNING", "Warning"], "5": ["INFO", "Notice"], "6": ["INFO", "Informational"], "7": ["DEBUG", "Debug"],
};

interface AsaMessage {
    meaning: string;
    action: NetAction;
    severity?: Severity;
}

const MESSAGES: Readonly<Record<string, AsaMessage>> = {
    "106001": { meaning: "Inbound connection denied by an access rule", action: "Block" },
    "106006": { meaning: "Inbound UDP denied", action: "Block" },
    "106007": { meaning: "Inbound UDP DNS reply denied", action: "Block" },
    "106014": { meaning: "Inbound ICMP denied", action: "Block" },
    "106015": { meaning: "TCP packet without a connection denied (often a scan or a late packet)", action: "Block" },
    "106021": { meaning: "Reverse-path check failed: possible spoofed source address", action: "Block", severity: "WARNING" },
    "106023": { meaning: "Packet denied by an access list (ACL)", action: "Block" },
    "106100": { meaning: "Access list hit (permitted or denied)", action: "Other" },
    "302013": { meaning: "TCP connection opened", action: "Allow" },
    "302014": { meaning: "TCP connection closed", action: "Allow" },
    "302015": { meaning: "UDP connection opened", action: "Allow" },
    "302016": { meaning: "UDP connection closed", action: "Allow" },
    "302020": { meaning: "ICMP connection opened", action: "Allow" },
    "302021": { meaning: "ICMP connection closed", action: "Allow" },
    "305011": { meaning: "Address translation (NAT) created", action: "Other" },
    "305012": { meaning: "Address translation (NAT) removed", action: "Other" },
    "710003": { meaning: "Access to the firewall itself denied by ACL", action: "Block" },
    "733100": { meaning: "Threat detection: traffic rate exceeded (scanning or DoS)", action: "Other", severity: "ERROR" },
    "733101": { meaning: "Threat detection: host is attacking or being attacked", action: "Other", severity: "ERROR" },
    "419002": { meaning: "Duplicate TCP SYN (possible SYN flood or retransmit)", action: "Other" },
    "113004": { meaning: "AAA user authentication succeeded", action: "Other" },
    "113005": { meaning: "AAA user authentication rejected (wrong password?)", action: "Block", severity: "WARNING" },
    "113015": { meaning: "AAA user authentication rejected: local database", action: "Block", severity: "WARNING" },
    "605004": { meaning: "Login to the firewall denied", action: "Block", severity: "WARNING" },
    "605005": { meaning: "Login to the firewall permitted", action: "Other" },
    "611101": { meaning: "User authentication succeeded (CLI / ASDM)", action: "Other" },
    "611102": { meaning: "User authentication failed (CLI / ASDM)", action: "Block", severity: "WARNING" },
    "111008": { meaning: "Administrator ran a command", action: "Other" },
    "111010": { meaning: "Administrator ran a command (configuration change)", action: "Other" },
    "716001": { meaning: "WebVPN session started", action: "Other" },
    "716039": { meaning: "WebVPN authentication rejected", action: "Block", severity: "WARNING" },
    "722051": { meaning: "AnyConnect VPN client got an address", action: "Other" },
    "113019": { meaning: "VPN session disconnected", action: "Other" },
    "4000": { meaning: "IPS signature matched", action: "Other", severity: "WARNING" },
};

function readTime(prefix: string): [number, string] {
    const iso = /(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/.exec(prefix);

    if (iso) {
        return [parseIsoTime(iso[1]), iso[1]];
    }

    const withYear = /([A-Z][a-z]{2}) +(\d{1,2}) (\d{4}) (\d{2}):(\d{2}):(\d{2})/.exec(prefix);

    if (withYear) {
        const [text, month, day, year, hour, minute, second] = withYear;
        const ms = Date.parse(`${month} ${day} ${year} ${hour}:${minute}:${second} UTC`);
        return [ms, text];
    }

    const bsd = /([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})/.exec(prefix);

    if (bsd) {
        const [text, month, day, hour, minute, second] = bsd;
        return [bsdTime(month, day, hour, minute, second), text];
    }

    return [Number.NaN, ""];
}

function readAddresses(message: string): { iface: string | null; ip: string; port: string | null }[] {
    const result: { iface: string | null; ip: string; port: string | null }[] = [];

    for (const match of message.matchAll(ADDRESS)) {
        if (!match[2].includes(".") && (!/[a-f]|::/i.test(match[2]) || (match[2].match(/:/g) ?? []).length < 2)) {
            continue;
        }

        const portText = match[3] ?? match[4] ?? null;
        result.push({ iface: match[1] ?? null, ip: match[2], port: portText === null ? null : NAMED_PORTS[portText] ?? portText });

        if (result.length === 2) {
            break;
        }
    }

    return result;
}

function parseAsaLine(line: string, lineNumber: number): ParsedEvent | null {
    const match = ASA_MARKER.exec(line);

    if (!match) {
        return null;
    }

    const [whole, platform, level, messageId, message] = match;
    const prefix = line.slice(0, line.length - whole.length);
    const [timeMs, timeText] = readTime(prefix);
    const known = MESSAGES[messageId] ?? (messageId.startsWith("4000") ? MESSAGES["4000"] : undefined);
    const [levelSeverity, levelName] = LEVELS[level] ?? ["INFO", level];
    const protocolMatch = /\b(TCP|UDP|ICMP|tcp|udp|icmp|GRE|ESP)\b/.exec(message);
    const found = readAddresses(message.replace(/\([^)]*\/\d+\)/g, ""));
    const addresses = /^(Built|Teardown) outbound/i.test(message) ? [...found].reverse() : found;
    const deniedByAcl = messageId === "106100" && /\bdenied\b/.test(message);
    const action: NetAction = deniedByAcl ? "Block" : messageId === "106100" ? "Allow" : known?.action ?? (/\b(deny|denied|drop)\b/i.test(message) ? "Block" : "Other");
    const user = /[Uu]ser(?:name)?\s*=?\s*'?"?([^\s',"]+)/.exec(message)?.[1] ?? null;
    const acl = /access-(?:group|list) "?([\w-]+)"?/.exec(message)?.[1] ?? null;
    const isLogin = known !== undefined && /login|authentication|command/i.test(known.meaning);
    const hasConnection = addresses.length === 2 && !isLogin;

    return buildNetEvent({
        lineNumber,
        raw: line,
        timeMs,
        timeText,
        action,
        actionText: isLogin ? (action === "Block" ? "LOGIN DENIED" : "LOGIN") : action === "Block" ? "DENY" : action === "Allow" ? (message.startsWith("Teardown") ? "TEARDOWN" : "BUILT") : `${platform}-${messageId}`,
        protocol: protocolMatch?.[1] ?? "",
        srcIp: addresses[0]?.ip ?? null,
        srcPort: addresses[0]?.port ?? null,
        dstIp: addresses[1]?.ip ?? null,
        dstPort: addresses[1]?.port ?? null,
        direction: /\binbound\b/i.test(message) ? "Inbound" : /\boutbound\b/i.test(message) ? "Outbound" : addresses[0]?.iface && addresses[1]?.iface ? `${addresses[0].iface} → ${addresses[1].iface}` : null,
        rule: acl,
        severity: known?.severity ?? levelSeverity,
        title: hasConnection ? undefined : shorten(`${known?.meaning ?? message}${user !== null ? ` · ${user}` : ""}`, 160),
        badge: `${platform}-${level}-${messageId}`,
        flag: isLogin && action === "Block" ? LOGIN_FAILED_FLAG : messageId.startsWith("4000") || messageId.startsWith("7331") ? SIGNATURE_FLAG : null,
        note: [hasConnection ? known?.meaning : shorten(message, 200), user !== null ? `user: ${user}` : ""].filter(Boolean).join(" · ") || null,
        fields: [
            { name: "Message ID", value: `%${platform}-${level}-${messageId}`, meaning: known?.meaning ?? "Search the ID in Cisco's \"ASA Syslog Messages\" guide" },
            { name: "Level", value: `${level} (${levelName})` },
            { name: "Message", value: message },
            ...(user !== null ? [{ name: "User", value: user }] : []),
            ...(acl !== null ? [{ name: "Access list", value: acl }] : []),
        ],
    });
}

export const ciscoAsaParser: LogParser = {
    id: "cisco-asa",
    name: "Cisco ASA / Firepower syslog",
    description: "Cisco ASA, PIX and Firepower Threat Defense syslog messages (%ASA-6-302013…).",
    demoFile: "/static/demo/cisco-asa.log",
    rawLabel: "Raw line",
    searchHint: "IP, message ID, ACL, user…",
    timeNote: "ISO times are converted to UTC. Classic syslog times have no zone and are shown as written.",
    detect: sample => {
        const share = shareOf(sampleLines(sample), line => ASA_MARKER.test(line));
        return share >= 0.4 ? 0.97 : share * 0.95;
    },
    parse: content => parseLineByLine(content, parseAsaLine, {
        reason: "This line has no %ASA-level-number: message tag.",
        isContinuation: () => false,
    }),
    facets: NET_FACETS,
    sourcePanel: NET_SOURCE_PANEL,
    coverage: () => {
        const base = netCoverage("Every message is shown. Connections, ACL denies, logins and threat detection get an explanation.");
        base.groups.unshift({ title: "Message IDs with an explanation", items: Object.entries(MESSAGES).map(([id, item]) => `${id} — ${item.meaning}`) });
        return base;
    },
};
