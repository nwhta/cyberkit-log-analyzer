import type { EventField, LogParser, ParsedEvent } from "./parserTypes.js";
import { makeUnparsedEvent, splitLines } from "./parseHelpers.js";
import { buildNetEvent, NET_FACETS, NET_SOURCE_PANEL, netCoverage } from "./netEvents.js";

const DEFAULT_FIELDS = ["version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol", "packets", "bytes", "start", "end", "action", "log-status"];
const PROTOCOLS: Readonly<Record<string, string>> = { "1": "ICMP", "6": "TCP", "17": "UDP", "47": "GRE", "50": "ESP", "58": "ICMPv6" };
const DEFAULT_LINE = /^\d+ (?:\d{12}|unknown|-) (?:eni-|-)\S* \S+ \S+ \S+ \S+ \S+ \S+ \S+ \d+ \d+ (?:ACCEPT|REJECT|-) (?:OK|NODATA|SKIPDATA)\b/;

const STATUS_MEANINGS: Readonly<Record<string, string>> = {
    OK: "Data logged normally",
    NODATA: "No traffic in this time window",
    SKIPDATA: "Some records were skipped (capacity limit or error)",
};

function parseRow(fields: string[], values: string[], line: string, lineNumber: number): ParsedEvent {
    const get = (name: string): string | null => {
        const index = fields.indexOf(name);
        const value = index >= 0 ? values[index] : undefined;
        return value === undefined || value === "-" ? null : value;
    };

    const start = Number(get("start"));
    const status = get("log-status") ?? "";
    const actionText = get("action") ?? "";
    const flowDirection = get("flow-direction");

    const extra: EventField[] = fields
        .map((name, index) => ({ name, value: values[index] ?? "" }))
        .filter(field => !["srcaddr", "dstaddr", "srcport", "dstport", "protocol", "action"].includes(field.name))
        .map(field => ({
            name: field.name,
            value: field.value,
            meaning: field.name === "log-status" ? STATUS_MEANINGS[field.value] ?? null
                : (field.name === "start" || field.name === "end") && /^\d+$/.test(field.value) ? new Date(Number(field.value) * 1000).toISOString() : null,
        }));

    return buildNetEvent({
        lineNumber,
        raw: line,
        timeMs: Number.isFinite(start) ? start * 1000 : Number.NaN,
        timeText: get("start") ?? "",
        action: actionText === "ACCEPT" ? "Allow" : actionText === "REJECT" ? "Block" : "Other",
        actionText: actionText || status,
        protocol: PROTOCOLS[get("protocol") ?? ""] ?? get("protocol") ?? "",
        srcIp: get("pkt-srcaddr") ?? get("srcaddr"),
        srcPort: get("srcport"),
        dstIp: get("pkt-dstaddr") ?? get("dstaddr"),
        dstPort: get("dstport"),
        direction: flowDirection === "ingress" ? "Inbound" : flowDirection === "egress" ? "Outbound" : null,
        device: get("interface-id"),
        note: status !== "OK" && status !== "" ? STATUS_MEANINGS[status] ?? status : `${get("packets") ?? "?"} packets, ${get("bytes") ?? "?"} bytes`,
        fields: extra,
    });
}

export const awsVpcFlowParser: LogParser = {
    id: "aws-vpc-flow",
    name: "AWS VPC Flow Logs",
    description: "AWS VPC flow logs (default or custom format): accepted and rejected network traffic.",
    demoFile: "/static/demo/vpc-flow.log",
    rawLabel: "Raw line",
    searchHint: "IP, port, ENI, REJECT…",
    timeNote: "Flow start time (Unix seconds), shown in UTC.",
    detect: sample => {
        if (/^version account-id interface-id srcaddr/m.test(sample) || /^(?:\S+ )*srcaddr dstaddr srcport dstport/m.test(sample)) {
            return 0.98;
        }

        const lines = sample.split("\n").filter(line => line.trim() !== "").slice(0, 40);
        const share = lines.length === 0 ? 0 : lines.filter(line => DEFAULT_LINE.test(line)).length / lines.length;
        return share >= 0.5 ? 0.96 : 0;
    },
    parse: content => {
        const events: ParsedEvent[] = [];
        let fields = DEFAULT_FIELDS;
        const lines = splitLines(content);

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();

            if (line === "") {
                continue;
            }

            if (/\bsrcaddr\b/.test(line) && /\bdstaddr\b/.test(line)) {
                fields = line.split(/\s+/);
                continue;
            }

            const values = line.split(/\s+/);

            if (values.length !== fields.length) {
                events.push(makeUnparsedEvent(lines[i], i + 1, "The number of values does not match the flow log fields."));
                continue;
            }

            events.push(parseRow(fields, values, lines[i], i + 1));
        }

        return events;
    },
    facets: NET_FACETS,
    sourcePanel: NET_SOURCE_PANEL,
    coverage: () => netCoverage("Every record is shown. ACCEPT = allowed, REJECT = blocked by a security group or network ACL. Custom field orders are read from the header line."),
};
