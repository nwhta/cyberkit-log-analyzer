import type { EventField, LogParser, ParsedEvent } from "./parserTypes.js";
import { cleanIp, formatUtc, parseLineByLine, sampleLines, shareOf, shorten } from "./parseHelpers.js";
import { SEVERITY_COLORS, SEVERITY_ORDER, severityColor, severityFromText } from "./severity.js";
import { detectWebAttack, listAttackPatterns, NO_ATTACK } from "./webAttackPatterns.js";

const ERROR_LINE = /^\[(\w{3}) (\w{3}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d+))? (\d{4})\] \[(?:([\w-]*):)?(\w+)\] (.*)$/;

const MONTHS: Readonly<Record<string, number>> = {
    Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
    Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

interface ProblemRule {
    name: string;
    pattern: RegExp;
    explanation: string;
}

const PROBLEMS: ProblemRule[] = [
    { name: "ModSecurity block", pattern: /ModSecurity:/i, explanation: "The web application firewall (ModSecurity) matched a rule. Check the rule id and msg below." },
    { name: "File not found", pattern: /File does not exist|AH00128|script .* not found/i, explanation: "A requested file does not exist. Many of these from one IP usually means scanning." },
    { name: "Access denied", pattern: /client denied by server configuration|AH01630|AH01797|Permission denied/i, explanation: "Request blocked by Require/Deny rules or file permissions." },
    { name: "Authentication", pattern: /user .* not found|password mismatch|authentication failure|AH01617|AH01618/i, explanation: "Failed HTTP basic/digest login. Many from one IP means password guessing." },
    { name: "Invalid request", pattern: /Invalid URI|AH00126|invalid method|AH00566|request failed/i, explanation: "Malformed request. Typical for scanners and exploit attempts." },
    { name: "Backend / proxy", pattern: /proxy|AH01102|AH00898|AH01114|AH00957|AH00959|attempt to connect|timeout/i, explanation: "Apache could not talk to the backend application in time." },
    { name: "PHP error", pattern: /PHP (?:Fatal|Warning|Notice|Parse|Deprecated)/i, explanation: "Error printed by PHP running inside Apache." },
    { name: "SSL / TLS", pattern: /SSL|AH02\d{3}/i, explanation: "TLS handshake or certificate problem." },
    { name: "Server lifecycle", pattern: /resuming normal operations|caught SIGTERM|AH00094|AH00489|AH00169/i, explanation: "Apache started, stopped or reloaded." },
];

function parseApacheTime(match: RegExpExecArray): number {
    const month = MONTHS[match[2]];

    if (month === undefined) {
        return Number.NaN;
    }

    const millis = match[7] ? Math.floor(+match[7].padEnd(3, "0").slice(0, 3)) : 0;
    return Date.UTC(+match[8], month, +match[3], +match[4], +match[5], +match[6], millis);
}

function splitBracketPrefixes(text: string): { tags: Map<string, string>; message: string } {
    const tags = new Map<string, string>();
    let rest = text;
    let prefix: RegExpExecArray | null;

    while ((prefix = /^\[(pid|client|remote) ([^\]]+)\] ?/.exec(rest)) !== null) {
        tags.set(prefix[1], prefix[2]);
        rest = rest.slice(prefix[0].length);
    }

    return { tags, message: rest };
}

function parseErrorLine(line: string, lineNumber: number): ParsedEvent | null {
    const match = ERROR_LINE.exec(line);

    if (!match) {
        return null;
    }

    const timeMs = parseApacheTime(match);
    const module = match[9] ?? "";
    const level = match[10];
    const severity = severityFromText(level);
    const { tags, message } = splitBracketPrefixes(match[11]);

    const ip = cleanIp(tags.get("client") ?? tags.get("remote"));
    const errorCode = /^(AH\d{5}): /.exec(message)?.[1] ?? null;
    const problem = PROBLEMS.find(rule => rule.pattern.test(message)) ?? null;
    const attack = detectWebAttack(message);
    const modSecurityMessage = /\[msg "([^"]+)"\]/.exec(message)?.[1] ?? null;
    const modSecurityRule = /\[id "(\d+)"\]/.exec(message)?.[1] ?? null;
    const path = /\[uri "([^"]+)"\]/.exec(message)?.[1] ??
        /File does not exist: (\S+)/.exec(message)?.[1] ??
        /(?:GET|POST|HEAD|PUT|DELETE|OPTIONS) (\S+)/.exec(message)?.[1] ?? "";

    const isBlocked = problem?.name === "ModSecurity block";
    const metadata = [formatUtc(timeMs)];

    if (ip !== null) {
        metadata.push(`IP: ${ip}`);
    }

    if (module !== "") {
        metadata.push(`module: ${module}`);
    }

    return {
        lineNumber,
        raw: line,
        timeMs,
        timeText: line.slice(1, line.indexOf("]")),
        severity,
        title: isBlocked && modSecurityMessage !== null ? `WAF: ${modSecurityMessage}` : problem?.name ?? `Apache ${level}`,
        badge: level.toUpperCase(),
        summary: shorten(message),
        metadata,
        accent: attack !== null || isBlocked ? SEVERITY_COLORS.ERROR : SEVERITY_COLORS[severity],
        emphasis: severity === "CRITICAL" || severity === "ERROR" || attack !== null || isBlocked,
        noise: false,
        ip,
        facets: {
            severity,
            problem: problem?.name ?? "Other",
            attack: attack?.name ?? NO_ATTACK,
            module: module === "" ? "(not written)" : module,
            path,
        },
        details: () => {
            const fields: EventField[] = [
                { name: "Time (as written)", value: line.slice(1, line.indexOf("]")), meaning: "Server local time. Apache error logs do not write the time zone." },
                { name: "Module", value: module, meaning: module === "" ? "Apache 2.2 style line (no module name)." : null },
                { name: "Level", value: level },
            ];

            for (const [name, value] of tags) {
                fields.push({ name: name === "pid" ? "Process / thread" : "Client", value });
            }

            fields.push({ name: "Message", value: message, meaning: problem?.explanation ?? null });

            if (errorCode !== null) {
                fields.push({ name: "Apache error code", value: errorCode, meaning: "Search this AH code in the Apache docs for the exact cause." });
            }

            if (modSecurityRule !== null) {
                fields.push({ name: "ModSecurity rule id", value: modSecurityRule, meaning: modSecurityMessage, risky: true });
            }

            if (attack !== null) {
                fields.push({ name: "Suspicious pattern", value: attack.matched, meaning: `${attack.name}: ${attack.explanation}`, risky: true });
            }

            return { fields };
        },
    };
}

export const apacheErrorParser: LogParser = {
    id: "apache-error",
    name: "Apache error log",
    description: "error_log from Apache 2.2 / 2.4, including ModSecurity WAF blocks.",
    demoFile: "/static/demo/apache-error.log",
    rawLabel: "Raw line",
    searchHint: "IP, AH code, message, file…",
    coverage: () => ({
        summary: "Every line is shown. Known problems get a type and an explanation; requests are checked for attack patterns.",
        groups: [
            { title: "Problem types", items: PROBLEMS.map(rule => `${rule.name} — ${rule.explanation}`) },
            { title: "Suspicious patterns", items: listAttackPatterns() },
        ],
    }),
    timeNote: "Apache error logs have no time zone. Times are shown exactly as written.",
    detect: sample => shareOf(sampleLines(sample), line => ERROR_LINE.test(line)),
    parse: content => parseLineByLine(content, parseErrorLine, {
        reason: "This line does not start like an Apache error log entry ([Day Mon DD HH:MM:SS YYYY] [level]).",
        isContinuation: line => /^\s|^(?:PHP )?Stack trace:|^#\d+ /.test(line),
    }),
    facets: [
        { key: "severity", title: "Level", order: SEVERITY_ORDER, color: severityColor },
        { key: "problem", title: "Problem type", color: value => value === "ModSecurity block" ? SEVERITY_COLORS.ERROR : "#619aff" },
        { key: "attack", title: "Suspicious pattern", color: value => value === NO_ATTACK ? "#87909e" : SEVERITY_COLORS.ERROR },
        { key: "module", title: "Module" },
    ],
    sourcePanel: {
        title: "Errors by client IP",
        emptyText: "No errors with a client IP",
        subjectWord: ["path", "paths"],
        select: event => event.ip === null ? null : {
            ip: event.ip,
            subject: event.facets.path === "" ? null : event.facets.path,
            tag: event.facets.attack !== NO_ATTACK ? event.facets.attack : event.facets.problem === "ModSecurity block" ? "WAF block" : null,
        },
        suspicion: stats => {
            if (stats.tags.size > 0) {
                return "attack pattern / WAF block seen";
            }

            return stats.subjects.size >= 20 ? "possible scanning" : null;
        },
    },
};
