import type { EventField, LogParser, ParsedEvent } from "./parserTypes.js";
import { cleanIp, cleanValue, formatUtc, parseLineByLine, safeDecode, sampleLines, shareOf, shorten } from "./parseHelpers.js";
import { SEVERITY_COLORS } from "./severity.js";
import { detectWebAttack, NO_ATTACK } from "./webAttackPatterns.js";
import { classifyUserAgent, explainClient } from "./userAgents.js";
import { statusClass, statusMeaning, statusSeverity, WEB_FACETS, WEB_SOURCE_PANEL, webCoverage } from "./webTraffic.js";

const QUOTED = String.raw`"((?:[^"\\]|\\.)*)"`;

const ACCESS_LINE = new RegExp(
    String.raw`^(?:(\S+:\d+) )?(\S+) (\S+) (\S+) \[([^\]]+)\] ` + QUOTED +
    String.raw` (\d{3}|-) (\d+|-)(?: ` + QUOTED + " " + QUOTED + String.raw`)?(.*)$`
);

const MONTHS: Readonly<Record<string, number>> = {
    Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
    Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

const ACCESS_TIME = /^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?: ([+-])(\d{2})(\d{2}))?$/;

function parseAccessTime(text: string): number {
    const match = ACCESS_TIME.exec(text);

    if (!match) {
        return Number.NaN;
    }

    const month = MONTHS[match[2]];

    if (month === undefined) {
        return Number.NaN;
    }

    const local = Date.UTC(+match[3], month, +match[1], +match[4], +match[5], +match[6]);

    if (match[7] === undefined) {
        return local;
    }

    const offsetMinutes = (+match[8] * 60 + +match[9]) * (match[7] === "+" ? 1 : -1);
    return local - offsetMinutes * 60_000;
}

interface RequestParts {
    method: string;
    path: string;
    query: string;
    protocol: string;
    valid: boolean;
}

function splitRequest(request: string): RequestParts {
    const match = /^([A-Z]{3,10}) (\S+)(?: (HTTP\/[\d.]+))?$/.exec(request);

    if (!match) {
        return { method: "INVALID", path: request, query: "", protocol: "", valid: false };
    }

    const queryStart = match[2].indexOf("?");
    const path = queryStart >= 0 ? match[2].slice(0, queryStart) : match[2];
    const query = queryStart >= 0 ? match[2].slice(queryStart + 1) : "";

    return { method: match[1], path, query, protocol: match[3] ?? "", valid: true };
}

function parseAccessLine(line: string, lineNumber: number): ParsedEvent | null {
    const match = ACCESS_LINE.exec(line);

    if (!match) {
        return null;
    }

    const [, vhost, rawIp, ident, user, timeText, request, status, bytes, referer, userAgent, extra] = match;

    const timeMs = parseAccessTime(timeText);
    const ip = cleanIp(rawIp);
    const parts = splitRequest(request);
    const client = classifyUserAgent(userAgent ?? null);
    const attack = detectWebAttack(request) ?? (userAgent ? detectWebAttack(userAgent) : null);
    const statusText = status === "-" ? "—" : status;

    let severity = statusSeverity(status);

    if (attack !== null || client.kind === "Security scanner") {
        severity = severity === "ERROR" ? "ERROR" : "WARNING";
    }

    const meaning = statusMeaning(status);
    const summaryParts: string[] = [];

    if (attack !== null) {
        summaryParts.push(`${attack.name} attempt`);
    }

    summaryParts.push(meaning ?? `HTTP status ${statusText}`);

    if (client.kind !== "Browser") {
        summaryParts.push(client.name === null ? client.kind : `${client.kind}: ${client.name}`);
    }

    const metadata = [formatUtc(timeMs)];

    if (ip !== null) {
        metadata.push(`IP: ${ip}`);
    }

    if (bytes !== "-") {
        metadata.push(`${bytes} bytes`);
    }

    if (vhost) {
        metadata.push(vhost);
    }

    return {
        lineNumber,
        raw: line,
        timeMs,
        timeText,
        severity,
        title: shorten(`${parts.method} ${safeDecode(parts.path)}`, 160),
        badge: statusText,
        summary: summaryParts.join(" · "),
        metadata,
        accent: attack !== null ? SEVERITY_COLORS.ERROR : SEVERITY_COLORS[severity],
        emphasis: attack !== null || severity === "ERROR",
        noise: false,
        ip,
        facets: {
            status: statusClass(status),
            attack: attack?.name ?? NO_ATTACK,
            client: client.kind,
            method: parts.method,
            severity,
            path: parts.path,
            code: status,
        },
        details: () => {
            const fields: EventField[] = [
                { name: "Client IP", value: rawIp },
                { name: "Time (as written)", value: timeText },
                { name: "Time (UTC)", value: formatUtc(timeMs) },
                { name: "Request line", value: request, meaning: parts.valid ? null : "Not a normal HTTP request. Often a scanner, TLS sent to a plain HTTP port, or garbage.", risky: !parts.valid },
                { name: "Method", value: parts.method },
                { name: "Path", value: parts.path, meaning: parts.path.includes("%") ? `Decoded: ${safeDecode(parts.path)}` : null },
                { name: "Query string", value: parts.query, meaning: parts.query.includes("%") ? `Decoded: ${safeDecode(parts.query)}` : null },
                { name: "Protocol", value: parts.protocol },
                { name: "Status", value: statusText, meaning },
                { name: "Response size (bytes)", value: bytes },
                { name: "Referer", value: referer ?? "" },
                { name: "User agent", value: userAgent ?? "", meaning: explainClient(client), risky: client.kind === "Security scanner" },
                { name: "Remote user", value: user, meaning: cleanValue(user) === null ? null : "User name from HTTP basic authentication." },
                { name: "Ident", value: ident },
            ];

            if (vhost) {
                fields.unshift({ name: "Virtual host", value: vhost });
            }

            if (attack !== null) {
                fields.push({ name: "Suspicious pattern", value: attack.matched, meaning: `${attack.name}: ${attack.explanation}`, risky: true });
            }

            if (extra.trim() !== "") {
                fields.push({ name: "Extra fields", value: extra.trim(), meaning: "Custom fields added by this server's log_format / LogFormat." });
            }

            return { fields };
        },
    };
}

export const webAccessParser: LogParser = {
    id: "web-access",
    name: "Nginx / Apache access log",
    description: "access.log from Nginx or Apache (combined / common format): every HTTP request.",
    demoFile: "/static/demo/nginx-access.log",
    rawLabel: "Raw line",
    searchHint: "IP, path, status, user agent…",
    timeNote: "Converted to UTC using the offset written in each line.",
    detect: sample => {
        const lines = sampleLines(sample);
        return shareOf(lines, line => ACCESS_LINE.test(line));
    },
    parse: content => parseLineByLine(content, parseAccessLine, {
        reason: "This line does not match the Nginx/Apache combined or common log format.",
        isContinuation: () => false,
    }),
    facets: WEB_FACETS,
    sourcePanel: WEB_SOURCE_PANEL,
    coverage: webCoverage,
};
