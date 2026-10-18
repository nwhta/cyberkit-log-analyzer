import type { LogParser, ParsedEvent } from "./parserTypes.js";
import { parseLineByLine, sampleLines, shareOf } from "./parseHelpers.js";
import { buildLinuxEvent, LINUX_FACETS, LINUX_NOISE, LINUX_SOURCE_PANEL, linuxCoverage } from "./linuxEvent.js";

const MONTHS: Readonly<Record<string, number>> = {
    Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
    Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

const PROGRAM = String.raw`(?:([^\s:\[]+)(?:\[(\d+)\])?: ?)?`;

const BSD_LINE = new RegExp(String.raw`^(?:<(\d{1,3})>)?([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\S+) ` + PROGRAM + String.raw`(.*)$`);
const ISO_LINE = new RegExp(String.raw`^(?:<(\d{1,3})>)?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) (\S+) ` + PROGRAM + String.raw`(.*)$`);
const RFC5424_LINE = /^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[(?:[^\]\\]|\\.)*\])+) ?(.*)$/;

const ALLOWED_FUTURE_MS = 2 * 24 * 60 * 60 * 1000;

function bsdTime(month: string, day: string, hour: string, minute: string, second: string, now: number): number {
    const monthIndex = MONTHS[month];

    if (monthIndex === undefined) {
        return Number.NaN;
    }

    const year = new Date(now).getUTCFullYear();
    const thisYear = Date.UTC(year, monthIndex, +day, +hour, +minute, +second);

    return thisYear > now + ALLOWED_FUTURE_MS ? Date.UTC(year - 1, monthIndex, +day, +hour, +minute, +second) : thisYear;
}

function isoTime(text: string): number {
    const normalized = text.replace(/(\.\d{3})\d+/, "$1").replace(/([+-]\d{2})(\d{2})$/, "$1:$2");
    return Date.parse(/[Z+-]\d{2}:?\d{2}$|Z$/.test(normalized) ? normalized : normalized + "Z");
}

function splitPriority(value: string | undefined): { priority: number | null; facility: number | null } {
    if (value === undefined) {
        return { priority: null, facility: null };
    }

    const number = Number(value);
    return number >= 0 && number <= 191 ? { priority: number & 7, facility: number >> 3 } : { priority: null, facility: null };
}

function parseSyslogLine(line: string, lineNumber: number, now: number): ParsedEvent | null {
    let match = RFC5424_LINE.exec(line);

    if (match) {
        const [, pri, timestamp, host, app, procId, msgId, structured, message] = match;
        return buildLinuxEvent({
            lineNumber,
            raw: line,
            timeMs: isoTime(timestamp),
            timeText: timestamp,
            host: host === "-" ? "" : host,
            program: app === "-" ? "" : app,
            pid: procId === "-" ? "" : procId,
            message: message.replace(/^\uFEFF/, ""),
            ...splitPriority(pri),
            extraFields: [
                { name: "Message ID", value: msgId === "-" ? "" : msgId },
                { name: "Structured data", value: structured === "-" ? "" : structured, meaning: structured === "-" ? null : "Extra key=value data added by the sending program (RFC 5424)" },
            ],
        });
    }

    match = ISO_LINE.exec(line);

    if (match) {
        const [, pri, timestamp, host, program, pid, message] = match;
        return buildLinuxEvent({
            lineNumber,
            raw: line,
            timeMs: isoTime(timestamp),
            timeText: timestamp,
            host,
            program: program ?? "",
            pid: pid ?? "",
            message,
            ...splitPriority(pri),
            extraFields: [],
        });
    }

    match = BSD_LINE.exec(line);

    if (match) {
        const [, pri, month, day, hour, minute, second, host, program, pid, message] = match;
        return buildLinuxEvent({
            lineNumber,
            raw: line,
            timeMs: bsdTime(month, day, hour, minute, second, now),
            timeText: `${month} ${day} ${hour}:${minute}:${second}`,
            host,
            program: program ?? "",
            pid: pid ?? "",
            message,
            ...splitPriority(pri),
            extraFields: [{ name: "Year", value: "not written in this format", meaning: "Classic syslog lines have no year and no time zone. The year is guessed so the date is not in the future; the time is shown as written." }],
        });
    }

    return null;
}

function isSyslogLine(line: string): boolean {
    return RFC5424_LINE.test(line) || ISO_LINE.test(line) || BSD_LINE.test(line);
}

export const syslogParser: LogParser = {
    id: "linux-syslog",
    name: "Linux syslog (auth, kern, mail, cron…)",
    description: "syslog, messages, auth.log, secure, kern.log, mail.log, cron and journalctl text output from Linux servers.",
    demoFile: "/static/demo/linux-auth.log",
    rawLabel: "Raw line",
    searchHint: "User, IP, program, message…",
    timeNote: "Classic syslog has no year or time zone: shown as written, year guessed. ISO and RFC 5424 times are converted to UTC.",
    detect: sample => {
        const lines = sampleLines(sample);
        return shareOf(lines, isSyslogLine) * 0.85;
    },
    parse: content => {
        const now = Date.now();
        return parseLineByLine(content, (line, lineNumber) => parseSyslogLine(line, lineNumber, now), {
            reason: "This line does not start with a syslog header (date, host, program).",
        });
    },
    facets: LINUX_FACETS,
    sourcePanel: LINUX_SOURCE_PANEL,
    noise: LINUX_NOISE,
    coverage: () => linuxCoverage("One parser for every file that rsyslog / syslog-ng writes."),
};
