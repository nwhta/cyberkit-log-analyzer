import { cleanIp, formatUtc, parseLineByLine, sampleLines, shareOf, shorten } from "./parseHelpers.js";
import { SEVERITY_COLORS, SEVERITY_ORDER, severityColor, severityFromText } from "./severity.js";
import { detectWebAttack, listAttackPatterns, NO_ATTACK } from "./webAttackPatterns.js";
const ERROR_LINE = /^(\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2}) \[(\w+)\] (\d+)#(\d+): (?:\*(\d+) )?(.*)$/;
const CONTEXT_FIELD = /,\s(client|server|request|upstream|host|referrer|subrequest|login): ("(?:[^"\\]|\\.)*"|[^,]*)/g;
const PROBLEMS = [
    { name: "Upstream timeout", pattern: /upstream timed out/i, explanation: "The backend application (PHP, Python, Node…) did not answer in time." },
    { name: "Upstream unreachable", pattern: /connect\(\) (?:to .* )?failed|no live upstreams|upstream prematurely closed/i, explanation: "Nginx could not talk to the backend application. It may be down or crashed." },
    { name: "File not found", pattern: /open\(\) ".*" failed \(2:|No such file or directory/i, explanation: "A requested file does not exist. Many of these from one IP usually means scanning." },
    { name: "Access denied", pattern: /access forbidden by rule|directory index of .* is forbidden|Permission denied/i, explanation: "Request blocked by an allow/deny rule or by file permissions." },
    { name: "Rate limit", pattern: /limiting (?:requests|connections)/i, explanation: "The client hit limit_req / limit_conn. Could be a flood or a brute-force attempt." },
    { name: "SSL / TLS", pattern: /SSL_|ssl_/i, explanation: "TLS handshake problem: old client, scanner, or certificate issue." },
    { name: "Request too large", pattern: /client intended to send too large body|too large/i, explanation: "Request body bigger than client_max_body_size." },
    { name: "Worker crash", pattern: /worker process \d+ exited|signal \d+/i, explanation: "An Nginx worker process stopped unexpectedly." },
    { name: "Configuration", pattern: /\[emerg\]|in \/etc\/nginx|unknown directive|conflicting server name/i, explanation: "Problem in the Nginx configuration." },
];
function classifyProblem(message) {
    return PROBLEMS.find(rule => rule.pattern.test(message)) ?? null;
}
function unquote(value) {
    return value.startsWith("\"") && value.endsWith("\"") ? value.slice(1, -1) : value.trim();
}
function parseErrorLine(line, lineNumber) {
    const match = ERROR_LINE.exec(line);
    if (!match) {
        return null;
    }
    const [, year, month, day, hour, minute, second, level, pid, tid, connection, rest] = match;
    const timeMs = Date.UTC(+year, +month - 1, +day, +hour, +minute, +second);
    const severity = severityFromText(level);
    const context = new Map();
    let message = rest;
    const contextStart = rest.search(/, client: /);
    if (contextStart >= 0) {
        message = rest.slice(0, contextStart);
        CONTEXT_FIELD.lastIndex = 0;
        for (const field of rest.slice(contextStart).matchAll(CONTEXT_FIELD)) {
            context.set(field[1], unquote(field[2]));
        }
    }
    const ip = cleanIp(context.get("client"));
    const request = context.get("request") ?? "";
    const problem = classifyProblem(message);
    const attack = detectWebAttack(request) ?? detectWebAttack(message);
    const path = /^\S+ (\S+)/.exec(request)?.[1] ?? null;
    const metadata = [formatUtc(timeMs)];
    if (ip !== null) {
        metadata.push(`IP: ${ip}`);
    }
    if (context.has("server")) {
        metadata.push(`server: ${context.get("server")}`);
    }
    return {
        lineNumber,
        raw: line,
        timeMs,
        timeText: `${year}/${month}/${day} ${hour}:${minute}:${second}`,
        severity,
        title: problem?.name ?? `Nginx ${level}`,
        badge: level.toUpperCase(),
        summary: shorten(message),
        metadata,
        accent: attack !== null ? SEVERITY_COLORS.ERROR : SEVERITY_COLORS[severity],
        emphasis: severity === "CRITICAL" || severity === "ERROR" || attack !== null,
        noise: false,
        ip,
        facets: {
            severity,
            problem: problem?.name ?? "Other",
            attack: attack?.name ?? NO_ATTACK,
            path: path ?? "",
        },
        details: () => {
            const fields = [
                { name: "Time (as written)", value: `${year}/${month}/${day} ${hour}:${minute}:${second}`, meaning: "Server local time. Nginx does not write the time zone." },
                { name: "Level", value: level },
                { name: "Process ID", value: pid },
                { name: "Thread ID", value: tid },
                { name: "Connection", value: connection ?? "", meaning: connection ? "Lines with the same connection number belong to the same client connection." : null },
                { name: "Message", value: message, meaning: problem?.explanation ?? null },
            ];
            for (const [name, value] of context) {
                fields.push({ name: name.charAt(0).toUpperCase() + name.slice(1), value });
            }
            if (attack !== null) {
                fields.push({ name: "Suspicious pattern", value: attack.matched, meaning: `${attack.name}: ${attack.explanation}`, risky: true });
            }
            return { fields };
        },
    };
}
export const nginxErrorParser = {
    id: "nginx-error",
    name: "Nginx error log",
    description: "error.log from Nginx: backend failures, blocked requests, rate limits, TLS errors.",
    demoFile: "/static/demo/nginx-error.log",
    rawLabel: "Raw line",
    searchHint: "IP, message, upstream, path…",
    coverage: () => ({
        summary: "Every line is shown. Known problems get a type and an explanation; requests are checked for attack patterns.",
        groups: [
            { title: "Problem types", items: PROBLEMS.map(rule => `${rule.name} — ${rule.explanation}`) },
            { title: "Suspicious patterns", items: listAttackPatterns() },
        ],
    }),
    timeNote: "Nginx error logs have no time zone. Times are shown exactly as written.",
    detect: sample => shareOf(sampleLines(sample), line => ERROR_LINE.test(line)),
    parse: content => parseLineByLine(content, parseErrorLine, {
        reason: "This line does not start like an Nginx error log entry (YYYY/MM/DD HH:MM:SS [level]).",
    }),
    facets: [
        { key: "severity", title: "Level", order: SEVERITY_ORDER, color: severityColor },
        { key: "problem", title: "Problem type", color: () => "#619aff" },
        { key: "attack", title: "Suspicious pattern", color: value => value === NO_ATTACK ? "#87909e" : SEVERITY_COLORS.ERROR },
    ],
    sourcePanel: {
        title: "Errors by client IP",
        emptyText: "No errors with a client IP",
        subjectWord: ["path", "paths"],
        select: event => event.ip === null ? null : {
            ip: event.ip,
            subject: event.facets.path === "" ? null : event.facets.path,
            tag: event.facets.attack !== NO_ATTACK ? event.facets.attack : null,
        },
        suspicion: stats => {
            if (stats.tags.size > 0) {
                return "attack pattern seen";
            }
            return stats.subjects.size >= 20 ? "possible scanning" : null;
        },
    },
};
