import type { EventField, LogParser, ParsedEvent } from "./parserTypes.js";
import { makeUnparsedEvent, splitLines } from "./parseHelpers.js";
import { buildNetEvent, NET_FACETS, NET_SOURCE_PANEL, netCoverage, normalizeAction } from "./netEvents.js";

const DEFAULT_FIELDS = ["date", "time", "action", "protocol", "src-ip", "dst-ip", "src-port", "dst-port", "size", "tcpflags", "tcpsyn", "tcpack", "tcpwin", "icmptype", "icmpcode", "info", "path", "pid"];

const PATH_MEANINGS: Readonly<Record<string, string>> = {
    SEND: "Outbound — this computer started the connection",
    RECEIVE: "Inbound — someone connected to this computer",
    FORWARD: "Forwarded through this computer",
};

function value(fields: string[], values: string[], name: string): string | null {
    const index = fields.indexOf(name);
    const result = index >= 0 ? values[index] : undefined;
    return result === undefined || result === "-" || result === "" ? null : result;
}

function parseRow(fields: string[], values: string[], line: string, lineNumber: number): ParsedEvent {
    const get = (name: string): string | null => value(fields, values, name);
    const date = get("date") ?? "";
    const time = get("time") ?? "";
    const actionText = get("action") ?? "";
    const path = get("path");
    const flags = get("tcpflags");

    const extra: EventField[] = fields
        .map((name, index) => ({ name, value: values[index] ?? "" }))
        .filter(field => !["date", "time", "action", "protocol", "src-ip", "dst-ip", "src-port", "dst-port"].includes(field.name))
        .map(field => ({
            name: field.name,
            value: field.value,
            meaning: field.name === "path" ? PATH_MEANINGS[field.value] ?? null : field.name === "tcpflags" && field.value === "S" ? "SYN only: a new connection attempt" : null,
        }));

    return buildNetEvent({
        lineNumber,
        raw: line,
        timeMs: Date.parse(`${date}T${time}Z`),
        timeText: `${date} ${time}`,
        action: actionText === "INFO-EVENTS-LOST" ? "Other" : normalizeAction(actionText),
        actionText,
        protocol: get("protocol") ?? "",
        srcIp: get("src-ip"),
        srcPort: get("src-port"),
        dstIp: get("dst-ip"),
        dstPort: get("dst-port"),
        direction: path === "SEND" ? "Outbound" : path === "RECEIVE" ? "Inbound" : path,
        note: actionText === "INFO-EVENTS-LOST" ? "The firewall could not write some events (log was too busy)" : flags === "S" && normalizeAction(actionText) === "Block" ? "New connection attempt was dropped" : null,
        fields: extra,
    });
}

export const windowsFirewallParser: LogParser = {
    id: "windows-firewall",
    name: "Windows Firewall log",
    description: "pfirewall.log from Windows Defender Firewall: allowed and dropped connections.",
    demoFile: "/static/demo/pfirewall.log",
    rawLabel: "Raw line",
    searchHint: "IP, port, DROP, ALLOW…",
    timeNote: "Windows Firewall writes local time of the computer without a time zone. Shown as written.",
    detect: sample => {
        if (/^#Software: Microsoft Windows Firewall/m.test(sample)) {
            return 0.99;
        }

        return /^#Fields:.*\bsrc-ip\b.*\bdst-port\b/m.test(sample) ? 0.9 : 0;
    },
    parse: content => {
        const events: ParsedEvent[] = [];
        let fields = DEFAULT_FIELDS;
        const lines = splitLines(content);

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];

            if (line.trim() === "") {
                continue;
            }

            if (line.startsWith("#")) {
                if (line.startsWith("#Fields:")) {
                    fields = line.slice(8).trim().split(/\s+/);
                }
                continue;
            }

            const values = line.trim().split(/\s+/);

            if (values.length < 8 || !/^\d{4}-\d{2}-\d{2}$/.test(values[0])) {
                events.push(makeUnparsedEvent(line, i + 1, "Row does not match the #Fields header of this Windows Firewall log."));
                continue;
            }

            events.push(parseRow(fields, values, line, i + 1));
        }

        return events;
    },
    facets: NET_FACETS,
    sourcePanel: NET_SOURCE_PANEL,
    coverage: () => netCoverage("Every line is shown. ALLOW / DROP and the direction (SEND = outbound, RECEIVE = inbound) are explained."),
};
