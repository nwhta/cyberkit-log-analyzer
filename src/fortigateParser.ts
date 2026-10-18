import type { Severity } from "./types.js";
import type { LogParser, ParsedEvent } from "./parserTypes.js";
import { parseLineByLine, sampleLines, shareOf, shorten } from "./parseHelpers.js";
import { severityFromText } from "./severity.js";
import { buildNetEvent, kvPairs, LOGIN_FAILED_FLAG, NET_FACETS, NET_SOURCE_PANEL, netCoverage, normalizeAction, SIGNATURE_FLAG } from "./netEvents.js";

const FORTI_LINE = /\blogid="?\d{10}"?/;
const PROTOCOLS: Readonly<Record<string, string>> = { "1": "ICMP", "6": "TCP", "17": "UDP", "47": "GRE", "50": "ESP", "58": "ICMPv6" };

const KEY_LABELS: Readonly<Record<string, string>> = {
    devname: "Device name", devid: "Device serial", logid: "Log ID", type: "Log type", subtype: "Subtype", level: "Level",
    vd: "Virtual domain", srcintf: "Source interface", dstintf: "Destination interface", policyid: "Policy ID",
    policyname: "Policy name", service: "Service", sentbyte: "Bytes sent", rcvdbyte: "Bytes received", duration: "Duration (s)",
    attack: "Attack (IPS signature)", virus: "Virus name", url: "URL", hostname: "Host name", catdesc: "Web category",
    msg: "Message", logdesc: "Description", user: "User", srccountry: "Source country", dstcountry: "Destination country",
    crlevel: "Risk level", app: "Application", appcat: "Application category", reason: "Reason", ui: "Login interface",
};

const SUBTYPE_MEANINGS: Readonly<Record<string, string>> = {
    forward: "Traffic passing through the firewall",
    local: "Traffic to or from the firewall itself",
    ips: "Intrusion prevention: an attack signature matched",
    virus: "Antivirus found malware",
    webfilter: "Web filter checked a URL category",
    "app-ctrl": "Application control matched an app",
    dns: "DNS filter checked a domain",
    anomaly: "DoS / anomaly protection triggered",
    system: "System event (admin login, config change…)",
    vpn: "VPN event",
    user: "User authentication event",
};

function toTime(fields: Map<string, string>): [number, string] {
    const eventTime = fields.get("eventtime");

    if (eventTime && /^\d{10,19}$/.test(eventTime)) {
        const digits = eventTime.length;
        const ms = digits >= 18 ? Number(eventTime.slice(0, 13)) : digits >= 15 ? Number(eventTime.slice(0, 13)) : digits >= 13 ? Number(eventTime) : Number(eventTime) * 1000;
        return [ms, `${fields.get("date") ?? ""} ${fields.get("time") ?? ""}`.trim() || eventTime];
    }

    const date = fields.get("date");
    const time = fields.get("time");

    if (date && time) {
        const zone = fields.get("tz");
        const offset = zone && /^[+-]\d{4}$/.test(zone) ? `${zone.slice(0, 3)}:${zone.slice(3)}` : "Z";
        return [Date.parse(`${date}T${time}${offset}`), `${date} ${time}`];
    }

    return [Number.NaN, ""];
}

function titleFor(fields: Map<string, string>): string | undefined {
    const type = fields.get("type");
    const subtype = fields.get("subtype") ?? "";

    if (type === "traffic") {
        return undefined;
    }

    const main = fields.get("attack") ?? fields.get("virus") ?? (subtype === "webfilter" ? `${fields.get("hostname") ?? ""} · ${fields.get("catdesc") ?? ""}` : undefined)
        ?? fields.get("logdesc") ?? fields.get("msg") ?? `${type} ${subtype}`;

    return shorten(main, 160);
}

function severityFor(fields: Map<string, string>): Severity {
    const level = severityFromText(fields.get("level"));
    const risk = fields.get("crlevel");

    if (risk === "critical") {
        return "CRITICAL";
    }

    if (risk === "high" || fields.get("subtype") === "virus") {
        return "ERROR";
    }

    if (fields.get("type") === "utm" && level === "INFO") {
        return "WARNING";
    }

    return level === "UNKNOWN" ? "INFO" : level;
}

function parseFortiLine(line: string, lineNumber: number): ParsedEvent | null {
    if (!FORTI_LINE.test(line)) {
        return null;
    }

    const fields = kvPairs(line.slice(Math.max(0, line.search(/\b(date|logver|eventtime|logid)=/))));
    const [timeMs, timeText] = toTime(fields);
    const type = fields.get("type") ?? "";
    const subtype = fields.get("subtype") ?? "";
    const actionText = fields.get("action") ?? fields.get("status") ?? "";
    const protocol = PROTOCOLS[fields.get("proto") ?? ""] ?? fields.get("proto") ?? "";
    const user = fields.get("user") ?? fields.get("unauthuser");

    const notes = [
        type !== "traffic" ? SUBTYPE_MEANINGS[subtype] : "",
        fields.get("service") && type === "traffic" ? `service ${fields.get("service")}` : "",
        user ? `user: ${user}` : "",
        fields.get("srccountry") && fields.get("srccountry") !== "Reserved" ? `from ${fields.get("srccountry")}` : "",
    ].filter(Boolean);

    return buildNetEvent({
        lineNumber,
        raw: line,
        timeMs,
        timeText,
        action: /^fail/.test(fields.get("status") ?? "") ? "Block" : normalizeAction(actionText),
        actionText,
        protocol,
        srcIp: fields.get("srcip") ?? fields.get("remip") ?? null,
        srcPort: fields.get("srcport") ?? null,
        dstIp: fields.get("dstip") ?? null,
        dstPort: fields.get("dstport") ?? null,
        direction: subtype ? `${type} / ${subtype}` : type,
        device: fields.get("devname") ?? null,
        rule: fields.get("policyid") ? `policy ${fields.get("policyid")}${fields.get("policyname") ? ` (${fields.get("policyname")})` : ""}` : null,
        severity: severityFor(fields),
        title: titleFor(fields),
        badge: (actionText || subtype || type).toUpperCase(),
        flag: /^fail/.test(fields.get("status") ?? "") ? LOGIN_FAILED_FLAG : ["ips", "virus", "anomaly"].includes(subtype) ? SIGNATURE_FLAG : null,
        note: notes.join(" · ") || null,
        fields: [...fields]
            .filter(([key]) => !["srcip", "dstip", "srcport", "dstport", "proto", "action"].includes(key))
            .map(([key, value]) => ({
                name: KEY_LABELS[key] ? `${KEY_LABELS[key]} (${key})` : key,
                value,
                meaning: key === "subtype" ? SUBTYPE_MEANINGS[value] ?? null : null,
                risky: key === "attack" || key === "virus" || (key === "crlevel" && /high|critical/.test(value)),
            })),
    });
}

export const fortigateParser: LogParser = {
    id: "fortigate",
    name: "FortiGate log (key=value)",
    description: "Fortinet FortiGate native logs: traffic, IPS, antivirus, web filter, VPN and admin events.",
    demoFile: "/static/demo/fortigate.log",
    rawLabel: "Raw line",
    searchHint: "IP, policy, attack, user…",
    timeNote: "Uses eventtime (exact) or date + time + tz. Times without a zone are treated as UTC.",
    detect: sample => {
        const share = shareOf(sampleLines(sample), line => FORTI_LINE.test(line) && /\b(devname|devid|type)=/.test(line));
        return share >= 0.5 ? 0.97 : share * 0.9;
    },
    parse: content => parseLineByLine(content, parseFortiLine, {
        reason: "This line has no FortiGate logid=… field.",
        isContinuation: () => false,
    }),
    facets: NET_FACETS,
    sourcePanel: NET_SOURCE_PANEL,
    coverage: () => {
        const base = netCoverage("Every line is shown. Traffic, UTM (IPS, antivirus, web filter, app control, DNS) and event logs are read.");
        base.groups.unshift({ title: "Log subtypes", items: Object.entries(SUBTYPE_MEANINGS).map(([key, text]) => `${key} — ${text}`) });
        return base;
    },
};
