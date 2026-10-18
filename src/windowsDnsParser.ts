import type { LogParser, ParsedEvent } from "./parserTypes.js";
import { parseLineByLine, sampleLines, shareOf } from "./parseHelpers.js";
import { buildDnsEvent, DNS_FACETS, DNS_SOURCE_PANEL, dnsCoverage } from "./dnsEvents.js";

const DNS_LINE = /^(\d{1,4}[/.-]\d{1,2}[/.-]\d{1,4}) (\d{1,2}:\d{2}:\d{2})(?: ?([AP]M))? +([0-9A-F]+) PACKET +([0-9A-F]+) (UDP|TCP) (Rcv|Snd) (\S+)\s+([0-9a-f]{1,4}) ([R ]) ([A-Z?]) \[([0-9a-f]+)\s+([A-Z ]*?)\s*([A-Z]+)\]\s+(\S+)\s+(\S+)/i;

const FLAG_MEANINGS: Readonly<Record<string, string>> = {
    A: "Authoritative answer", T: "Truncated", D: "Recursion desired", R: "Recursion available",
};

function decodeName(text: string): string {
    return text.replace(/\(\d+\)/g, ".").replace(/^\.|\.$/g, "") || ".";
}

function parseDate(date: string, time: string, meridiem: string | undefined): number {
    const parts = date.split(/[/.-]/).map(Number);
    const [year, month, day] = parts[0] > 31 ? [parts[0], parts[1], parts[2]] : [parts[2], parts[0], parts[1]];
    let [hour, minute, second] = time.split(":").map(Number);

    if (meridiem?.toUpperCase() === "PM" && hour < 12) {
        hour += 12;
    } else if (meridiem?.toUpperCase() === "AM" && hour === 12) {
        hour = 0;
    }

    return Date.UTC(year, month - 1, day, hour, minute, second);
}

function parseDnsLine(line: string, lineNumber: number): ParsedEvent | null {
    const match = DNS_LINE.exec(line);

    if (!match) {
        return null;
    }

    const [, date, time, meridiem, thread, , protocol, direction, remote, xid, responseFlag, opcode, hexFlags, charFlags, rcode, qtype, name] = match;
    const isResponse = responseFlag === "R";

    return buildDnsEvent({
        lineNumber,
        raw: line,
        timeMs: parseDate(date, time, meridiem),
        timeText: `${date} ${time}${meridiem ? " " + meridiem : ""}`,
        client: direction === "Rcv" && !isResponse ? remote : direction === "Snd" && isResponse ? remote : null,
        query: decodeName(name),
        qtype,
        kind: isResponse ? "Response" : "Query",
        response: isResponse ? rcode : null,
        server: `${protocol} ${direction === "Rcv" ? "received from" : "sent to"} ${remote}`,
        noise: isResponse && rcode === "NOERROR",
        fields: [
            { name: "Direction", value: direction, meaning: direction === "Rcv" ? "Packet received by the DNS server" : "Packet sent by the DNS server" },
            { name: "Remote IP", value: remote },
            { name: "Protocol", value: protocol },
            { name: "Transaction ID", value: xid, meaning: "Same ID links a query to its response" },
            { name: "Opcode", value: opcode, meaning: opcode === "Q" ? "Standard query" : opcode === "U" ? "Dynamic update" : null },
            { name: "Flags", value: `${hexFlags} ${charFlags}`.trim(), meaning: charFlags.trim().split(" ").map(flag => FLAG_MEANINGS[flag] ?? "").filter(Boolean).join(", ") || null },
            { name: "Thread", value: thread },
        ],
    });
}

export const windowsDnsParser: LogParser = {
    id: "windows-dns",
    name: "Windows DNS Server debug log",
    description: "Windows DNS Server debug (packet) log: who asked for which name.",
    demoFile: "/static/demo/windows-dns.log",
    rawLabel: "Raw line",
    searchHint: "Domain, client IP, NXDOMAIN…",
    timeNote: "The debug log uses the server's local time without a zone. Shown as written.",
    detect: sample => {
        const share = shareOf(sampleLines(sample), line => DNS_LINE.test(line));
        return share >= 0.3 ? 0.98 : share > 0 ? 0.9 : 0;
    },
    parse: content => parseLineByLine(content, parseDnsLine, {
        reason: "Not a PACKET line of the Windows DNS debug log (header and detail lines are skipped).",
        isContinuation: () => true,
        skip: line => !/ PACKET /.test(line),
    }),
    facets: DNS_FACETS,
    sourcePanel: DNS_SOURCE_PANEL,
    noise: { label: "Normal responses (NOERROR)", hint: "Each lookup has a query line and a response line. Failed responses (NXDOMAIN, REFUSED…) are always shown. Click to show normal responses too." },
    coverage: () => dnsCoverage("Every PACKET line is shown. Names like (3)www(7)example(3)com(0) are decoded."),
};
