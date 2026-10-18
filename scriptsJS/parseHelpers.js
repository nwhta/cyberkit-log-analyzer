import { SEVERITY_COLORS } from "./severity.js";
export const UNPARSED_VALUE = "Unparsed";
export function splitLines(content) {
    const text = content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
    const lines = text.split(/\r?\n/);
    if (lines.length > 0 && lines[lines.length - 1] === "") {
        lines.pop();
    }
    return lines;
}
export function sampleLines(sample, max = 40) {
    return splitLines(sample)
        .map(line => line.trim())
        .filter(line => line !== "")
        .slice(0, max);
}
export function shareOf(lines, test) {
    if (lines.length === 0) {
        return 0;
    }
    let matched = 0;
    for (const line of lines) {
        if (test(line)) {
            matched++;
        }
    }
    return matched / lines.length;
}
export function formatUtc(ms) {
    if (Number.isNaN(ms)) {
        return "no timestamp";
    }
    return new Date(ms).toISOString().replace("T", " ").slice(0, 19) + " UTC";
}
export function cleanIp(value) {
    if (value === null || value === undefined) {
        return null;
    }
    let ip = value.trim();
    if (ip === "" || ip === "-") {
        return null;
    }
    if (ip.toLowerCase().startsWith("::ffff:")) {
        ip = ip.slice(7);
    }
    const ipv4WithPort = /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/.exec(ip);
    if (ipv4WithPort) {
        return ipv4WithPort[1];
    }
    const bracketed = /^\[([0-9a-fA-F:.]+)\](?::\d+)?$/.exec(ip);
    if (bracketed) {
        return bracketed[1];
    }
    return ip;
}
export function cleanValue(value) {
    if (value === null || value === undefined) {
        return null;
    }
    const text = typeof value === "string" ? value.trim() : String(value);
    if (text === "" || text === "-") {
        return null;
    }
    return text;
}
export function shorten(text, max = 300) {
    return text.length > max ? text.slice(0, max) + "…" : text;
}
export function safeDecode(text) {
    try {
        return decodeURIComponent(text.replace(/\+/g, " "));
    }
    catch {
        return text;
    }
}
export function makeUnparsedEvent(line, lineNumber, reason) {
    return {
        lineNumber,
        raw: line,
        timeMs: Number.NaN,
        timeText: "no timestamp",
        severity: "UNKNOWN",
        title: `Line ${lineNumber} — not recognized`,
        badge: "UNPARSED",
        summary: shorten(line),
        metadata: [`line ${lineNumber}`],
        accent: SEVERITY_COLORS.UNKNOWN,
        emphasis: false,
        noise: false,
        ip: null,
        facets: { parse: UNPARSED_VALUE },
        details: () => ({
            fields: [
                { name: "Line number", value: String(lineNumber) },
                { name: "Why it is shown like this", value: reason },
            ],
        }),
    };
}
export function parseLineByLine(content, parseLine, options) {
    const events = [];
    const lines = splitLines(content);
    const isContinuation = options.isContinuation ?? (line => /^\s/.test(line));
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineNumber = i + 1;
        if (line.trim() === "" || options.skip?.(line)) {
            continue;
        }
        const event = parseLine(line, lineNumber);
        if (event !== null) {
            events.push(event);
            continue;
        }
        const previous = events[events.length - 1];
        if (previous !== undefined && previous.facets.parse !== UNPARSED_VALUE && isContinuation(line)) {
            previous.raw += "\n" + line;
            continue;
        }
        events.push(makeUnparsedEvent(line, lineNumber, options.reason));
    }
    return events;
}
export function flattenObject(value, prefix = "", out = []) {
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
        for (const [key, inner] of Object.entries(value)) {
            flattenObject(inner, prefix === "" ? key : `${prefix}.${key}`, out);
        }
        return out;
    }
    if (Array.isArray(value)) {
        const allPlain = value.every(item => item === null || typeof item !== "object");
        if (allPlain) {
            out.push([prefix, value.map(item => String(item)).join(", ")]);
            return out;
        }
        value.forEach((item, index) => flattenObject(item, `${prefix}[${index}]`, out));
        return out;
    }
    out.push([prefix, value === null || value === undefined ? "null" : String(value)]);
    return out;
}
export function getPath(record, path) {
    if (record === null || typeof record !== "object") {
        return undefined;
    }
    if (path in record) {
        return record[path];
    }
    let current = record;
    for (const part of path.split(".")) {
        if (current === null || typeof current !== "object") {
            return undefined;
        }
        current = current[part];
    }
    return current;
}
export function tryParseJsonObject(line) {
    const text = line.trim();
    if (!text.startsWith("{") || !text.endsWith("}")) {
        return null;
    }
    try {
        const value = JSON.parse(text);
        return value !== null && typeof value === "object" && !Array.isArray(value)
            ? value
            : null;
    }
    catch {
        return null;
    }
}
export function parseEpochOrDate(value) {
    if (typeof value === "number") {
        return value > 1e12 ? value : value * 1000;
    }
    if (typeof value !== "string" || value.trim() === "") {
        return Number.NaN;
    }
    const text = value.trim();
    if (/^\d+(\.\d+)?$/.test(text)) {
        const number = Number(text);
        return number > 1e12 ? number : number * 1000;
    }
    return Date.parse(text.replace(/(\.\d{3})\d+/, "$1"));
}
