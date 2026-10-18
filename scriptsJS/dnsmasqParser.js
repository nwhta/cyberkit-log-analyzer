import { makeUnparsedEvent, sampleLines, shareOf, splitLines } from "./parseHelpers.js";
import { buildDnsEvent, DNS_FACETS, DNS_NOISE, DNS_SOURCE_PANEL, dnsCoverage } from "./dnsEvents.js";
import { readSyslogHeader } from "./syslogTime.js";
const DNSMASQ = /\b(dnsmasq|pihole-FTL)(?:\[\d+\])?: (.*)$/;
const QUERY = /^query\[(\w+)\] (\S+) from (\S+)/;
const BLOCKED = /^(gravity blocked|regex blacklisted|exactly blacklisted|regex denied|exactly denied|special domain|blacklisted|\/etc\/hosts) (\S+) is (\S+)/;
const OTHER = /^(forwarded|reply|cached|config|validation|dnssec-query|cached-stale) (\S+) (?:is|to) (.*)$/;
const BLOCK_MEANINGS = {
    "gravity blocked": "Blocked by a Pi-hole blocklist (ads, trackers, malware)",
    "regex blacklisted": "Blocked by a regex rule",
    "regex denied": "Blocked by a regex rule",
    "exactly blacklisted": "Blocked by a manual deny rule",
    "exactly denied": "Blocked by a manual deny rule",
    blacklisted: "Blocked by a deny list",
};
export const dnsmasqParser = {
    id: "dnsmasq",
    name: "dnsmasq / Pi-hole DNS log",
    description: "dnsmasq and Pi-hole (pihole.log): queries, blocked domains and replies.",
    demoFile: "/static/demo/pihole.log",
    rawLabel: "Raw line",
    searchHint: "Domain, client IP, blocked…",
    timeNote: "dnsmasq writes local time without a zone or year. Shown as written.",
    detect: sample => {
        const share = shareOf(sampleLines(sample), line => DNSMASQ.test(line));
        return share >= 0.5 ? 0.96 : share * 0.9;
    },
    parse: content => {
        const events = [];
        const lastClient = new Map();
        const lines = splitLines(content);
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (line.trim() === "") {
                continue;
            }
            const match = DNSMASQ.exec(line);
            const header = readSyslogHeader(line);
            if (!match) {
                events.push(makeUnparsedEvent(line, i + 1, "This line is not a dnsmasq / Pi-hole message."));
                continue;
            }
            const message = match[2];
            const base = { lineNumber: i + 1, raw: line, timeMs: header?.timeMs ?? Number.NaN, timeText: header?.timeText ?? "", server: header && !/dnsmasq|pihole/i.test(header.host) ? header.host : null };
            let record = null;
            const query = QUERY.exec(message);
            const blocked = BLOCKED.exec(message);
            const other = OTHER.exec(message);
            if (query) {
                lastClient.set(query[2].toLowerCase(), query[3]);
                record = { ...base, client: query[3], query: query[2], qtype: query[1], kind: "Query", fields: [] };
            }
            else if (blocked) {
                record = {
                    ...base, client: lastClient.get(blocked[2].toLowerCase()) ?? null, query: blocked[2], qtype: "", kind: "Blocked", answer: blocked[3],
                    fields: [{ name: "Reason", value: blocked[1], meaning: BLOCK_MEANINGS[blocked[1]] ?? null }],
                };
            }
            else if (other) {
                const answer = other[3];
                const kind = other[1] === "forwarded" ? "Forwarded" : other[1].startsWith("cached") ? "Cached" : "Response";
                record = {
                    ...base, client: lastClient.get(other[2].toLowerCase()) ?? null, query: other[2], qtype: "", kind,
                    response: answer === "NXDOMAIN" ? "NXDOMAIN" : answer === "SERVFAIL" ? "SERVFAIL" : null,
                    answer: other[1] === "forwarded" ? `forwarded to ${answer}` : answer, noise: answer !== "NXDOMAIN" && answer !== "SERVFAIL",
                    fields: [{ name: "Step", value: other[1], meaning: other[1] === "forwarded" ? "Sent to the upstream DNS server" : other[1] === "cached" ? "Answered from cache" : other[1] === "reply" ? "Answer from upstream" : null }],
                };
            }
            if (record === null) {
                events.push(buildDnsEvent({ ...base, client: null, query: message, qtype: "", kind: "Other", noise: true, fields: [] }));
                continue;
            }
            events.push(buildDnsEvent(record));
        }
        return events;
    },
    facets: DNS_FACETS,
    sourcePanel: DNS_SOURCE_PANEL,
    noise: DNS_NOISE,
    coverage: () => dnsCoverage("Every line is shown. Blocked lines are linked to the client that asked."),
};
