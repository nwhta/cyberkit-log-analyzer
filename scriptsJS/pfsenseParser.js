import { parseLineByLine, sampleLines, shareOf } from "./parseHelpers.js";
import { buildNetEvent, NET_FACETS, NET_SOURCE_PANEL, netCoverage, normalizeAction } from "./netEvents.js";
import { readSyslogHeader } from "./syslogTime.js";
const FILTERLOG = /\bfilterlog(?:\[\d+\]:|\s+\d+\s+-\s+(?:-|\[[^\]]*\])?)\s*(\d*,.*)$/;
const REASON_MEANINGS = {
    match: "Matched a firewall rule",
    "bad-offset": "Packet had a bad fragment offset",
    fragment: "Packet fragment",
    short: "Packet too short",
    normalize: "Dropped by packet normalization (scrub)",
    memory: "Dropped: firewall out of memory",
};
function parseFilterlog(line, lineNumber) {
    const match = FILTERLOG.exec(line);
    if (!match) {
        return null;
    }
    const header = readSyslogHeader(line);
    const csv = match[1].split(",");
    const [ruleNumber, subRule, anchor, tracker, iface, reason, actionText, direction, ipVersion] = csv;
    if (actionText === undefined || ipVersion === undefined) {
        return null;
    }
    let protocol = "";
    let srcIp = null;
    let dstIp = null;
    let rest = [];
    let ipFields = [];
    if (ipVersion === "4") {
        const [tos, ecn, ttl, id, offset, flags, protoId, protoText, length, src, dst, ...tail] = csv.slice(9);
        protocol = protoText ?? protoId ?? "";
        srcIp = src ?? null;
        dstIp = dst ?? null;
        rest = tail;
        ipFields = [
            { name: "TTL", value: ttl ?? "" }, { name: "IP ID", value: id ?? "" }, { name: "Fragment offset", value: offset ?? "" },
            { name: "IP flags", value: flags ?? "" }, { name: "TOS / ECN", value: `${tos ?? ""} ${ecn ?? ""}`.trim() }, { name: "Length", value: length ?? "" },
        ];
    }
    else if (ipVersion === "6") {
        const [klass, flowLabel, hopLimit, protoText, protoId, length, src, dst, ...tail] = csv.slice(9);
        protocol = protoText ?? protoId ?? "";
        srcIp = src ?? null;
        dstIp = dst ?? null;
        rest = tail;
        ipFields = [
            { name: "Traffic class", value: klass ?? "" }, { name: "Flow label", value: flowLabel ?? "" },
            { name: "Hop limit", value: hopLimit ?? "" }, { name: "Length", value: length ?? "" },
        ];
    }
    const hasPorts = /^(tcp|udp)$/i.test(protocol);
    const srcPort = hasPorts ? rest[0] ?? null : null;
    const dstPort = hasPorts ? rest[1] ?? null : null;
    const tcpFlags = protocol.toLowerCase() === "tcp" ? rest[3] ?? "" : "";
    return buildNetEvent({
        lineNumber,
        raw: line,
        timeMs: header?.timeMs ?? Number.NaN,
        timeText: header?.timeText ?? "",
        action: normalizeAction(actionText),
        actionText,
        protocol,
        srcIp,
        srcPort,
        dstIp,
        dstPort,
        direction: direction === "in" ? "Inbound" : direction === "out" ? "Outbound" : direction,
        device: header?.host ? `${header.host} · ${iface}` : iface,
        rule: ruleNumber !== "" ? `#${ruleNumber}${subRule ? "." + subRule : ""}` : null,
        note: tcpFlags === "S" && normalizeAction(actionText) === "Block" ? "New connection attempt was blocked" : null,
        fields: [
            { name: "Interface", value: iface },
            { name: "Reason", value: reason, meaning: REASON_MEANINGS[reason] ?? null },
            { name: "Rule number", value: ruleNumber, meaning: "Firewall → Rules: hover a rule to see its number, or search the tracker ID" },
            { name: "Tracker ID", value: tracker, meaning: "Unique rule ID; in the GUI log view it links the entry to its rule" },
            { name: "Anchor", value: anchor },
            { name: "IP version", value: ipVersion },
            ...ipFields,
            ...(tcpFlags !== "" ? [{ name: "TCP flags", value: tcpFlags, meaning: tcpFlags === "S" ? "SYN: a new connection attempt" : tcpFlags.includes("R") ? "RST: connection reset" : null }] : []),
        ],
    });
}
export const pfsenseParser = {
    id: "pfsense-filterlog",
    name: "pfSense / OPNsense firewall",
    description: "filterlog lines from pfSense and OPNsense (BSD pf firewall): passed and blocked packets.",
    demoFile: "/static/demo/pfsense-filterlog.log",
    rawLabel: "Raw line",
    searchHint: "IP, port, interface, block…",
    timeNote: "RFC 5424 times are converted to UTC. Old BSD syslog times have no zone or year and are shown as written.",
    detect: sample => {
        const share = shareOf(sampleLines(sample), line => FILTERLOG.test(line));
        return share >= 0.4 ? 0.97 : share * 0.95;
    },
    parse: content => parseLineByLine(content, parseFilterlog, {
        reason: "This line is not a pf filterlog entry (filterlog: rule,…,interface,reason,action,direction,…).",
        isContinuation: () => false,
    }),
    facets: NET_FACETS,
    sourcePanel: NET_SOURCE_PANEL,
    coverage: () => netCoverage("Every filterlog line is shown. IPv4 and IPv6, TCP/UDP ports, flags, interface and rule number are read."),
};
