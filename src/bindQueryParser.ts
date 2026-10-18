import type { LogParser, ParsedEvent } from "./parserTypes.js";
import { parseLineByLine, sampleLines, shareOf } from "./parseHelpers.js";
import { buildDnsEvent, DNS_FACETS, DNS_SOURCE_PANEL, dnsCoverage } from "./dnsEvents.js";
import { readSyslogHeader } from "./syslogTime.js";

const QUERY = /client (?:@0x[0-9a-f]+ )?([0-9a-f.:]+)#(\d+)(?: \(([^)]+)\))?: (?:view (\S+): )?query: (\S+) (\w+) (\w+) (\S*)(?: \(([^)]+)\))?/i;
const BIND_TIME = /^(\d{2})-([A-Z][a-z]{2})-(\d{4}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d{3}))?/;
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

const FLAG_MEANINGS: Readonly<Record<string, string>> = {
    "+": "recursion requested", "-": "no recursion", S: "signed (TSIG)", E: "EDNS", T: "over TCP", D: "DNSSEC OK", C: "checking disabled", V: "valid server cookie", K: "cookie sent",
};

function readTime(line: string): [number, string] {
    const bind = BIND_TIME.exec(line);

    if (bind) {
        const [text, day, month, year, hour, minute, second, millis] = bind;
        return [Date.UTC(+year, MONTHS.indexOf(month), +day, +hour, +minute, +second, +(millis ?? 0)), text];
    }

    const header = readSyslogHeader(line);
    return header ? [header.timeMs, header.timeText] : [Number.NaN, ""];
}

function parseBindLine(line: string, lineNumber: number): ParsedEvent | null {
    const match = QUERY.exec(line);

    if (!match) {
        return null;
    }

    const [, client, port, , view, name, klass, qtype, flags, server] = match;
    const [timeMs, timeText] = readTime(line);
    const flagText = flags.replace(/\(\d+\)/g, "");

    return buildDnsEvent({
        lineNumber,
        raw: line,
        timeMs,
        timeText,
        client,
        query: name,
        qtype,
        kind: "Query",
        server: server ? `server ${server}` : null,
        fields: [
            { name: "Client port", value: port },
            { name: "Class", value: klass },
            { name: "Flags", value: flags, meaning: [...flagText].map(flag => FLAG_MEANINGS[flag] ?? "").filter(Boolean).join(", ") || null },
            ...(view ? [{ name: "View", value: view }] : []),
            ...(server ? [{ name: "Server address", value: server }] : []),
        ],
    });
}

export const bindQueryParser: LogParser = {
    id: "bind-query",
    name: "BIND DNS query log",
    description: "BIND / named query log: every DNS question with client IP and flags.",
    demoFile: "/static/demo/bind-query.log",
    rawLabel: "Raw line",
    searchHint: "Domain, client IP, record type…",
    timeNote: "BIND writes local time without a zone. Shown as written.",
    detect: sample => {
        const share = shareOf(sampleLines(sample), line => QUERY.test(line));
        return share >= 0.5 ? 0.97 : share * 0.9;
    },
    parse: content => parseLineByLine(content, parseBindLine, {
        reason: "This line is not a BIND \"client … query: name IN TYPE\" entry.",
        isContinuation: () => false,
    }),
    facets: DNS_FACETS,
    sourcePanel: DNS_SOURCE_PANEL,
    coverage: () => dnsCoverage("Every query line is shown with its flags explained."),
};
