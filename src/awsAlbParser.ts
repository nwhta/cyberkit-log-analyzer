import type { EventField, LogParser, ParsedEvent } from "./parserTypes.js";
import { cleanIp, formatUtc, parseLineByLine, safeDecode, sampleLines, shareOf, shorten } from "./parseHelpers.js";
import { SEVERITY_COLORS } from "./severity.js";
import { detectWebAttack, NO_ATTACK } from "./webAttackPatterns.js";
import { classifyUserAgent, explainClient } from "./userAgents.js";
import { statusClass, statusMeaning, statusSeverity, WEB_FACETS, WEB_SOURCE_PANEL, webCoverage } from "./webTraffic.js";

const ALB_LINE = /^(https?|h2|grpcs?|wss?|tls|tcp|udp) (\d{4}-\d{2}-\d{2}T\S+Z) (\S+) (\S+) (\S+) /;

const NAMES = [
    "Type", "Time", "Load balancer", "Client", "Target", "Request processing time", "Target processing time",
    "Response processing time", "ELB status", "Target status", "Bytes received", "Bytes sent", "Request", "User agent",
    "SSL cipher", "SSL protocol", "Target group ARN", "Trace ID", "Domain name", "Certificate ARN", "Matched rule priority",
    "Request creation time", "Actions executed", "Redirect URL", "Error reason", "Target list", "Target status list",
    "Classification", "Classification reason", "Connection trace ID",
];

const ERROR_REASONS: Readonly<Record<string, string>> = {
    AuthInvalidCookie: "Authentication cookie is not valid",
    LambdaInvalidResponse: "Lambda target returned an invalid response",
    TargetConnectionErrorCode: "Could not connect to the target",
    TargetResponseError: "Target closed the connection or sent a bad response",
    WAFConnectionError: "Could not reach AWS WAF",
    WAFResponseReadTimeout: "AWS WAF did not answer in time",
};

function tokenize(line: string): string[] {
    const tokens: string[] = [];

    for (const match of line.matchAll(/"((?:[^"\\]|\\.)*)"|(\S+)/g)) {
        tokens.push(match[1] !== undefined ? match[1] : match[2]);
    }

    return tokens;
}

function parseAlbLine(line: string, lineNumber: number): ParsedEvent | null {
    if (!ALB_LINE.test(line)) {
        return null;
    }

    const values = tokenize(line);
    const [, time, , clientText, , , , , elbStatus, targetStatus, , sent, request, userAgent] = values;
    const timeMs = Date.parse(time.replace(/(\.\d{3})\d+/, "$1"));
    const ip = cleanIp(clientText);
    const requestMatch = /^([A-Z]+) (\S+) (\S+)$/.exec(request ?? "");
    const url = requestMatch?.[2] ?? request ?? "";
    let path = url;

    try {
        path = new URL(url).pathname;
    } catch {
        path = url.split("?")[0];
    }

    const method = requestMatch?.[1] ?? "-";
    const client = classifyUserAgent(userAgent && userAgent !== "-" ? userAgent : null);
    const attack = detectWebAttack(url) ?? (userAgent ? detectWebAttack(userAgent) : null);
    const errorReason = values[24] && values[24] !== "-" ? values[24] : null;
    let severity = statusSeverity(elbStatus);

    if (attack !== null || client.kind === "Security scanner") {
        severity = severity === "ERROR" ? "ERROR" : "WARNING";
    }

    const summary = [
        attack !== null ? `${attack.name} attempt` : "",
        statusMeaning(elbStatus) ?? `HTTP status ${elbStatus}`,
        targetStatus === "-" && elbStatus.startsWith("5") ? "the target did not answer" : "",
        errorReason !== null ? ERROR_REASONS[errorReason] ?? errorReason : "",
        client.kind !== "Browser" ? (client.name === null ? client.kind : `${client.kind}: ${client.name}`) : "",
    ].filter(Boolean).join(" · ");

    return {
        lineNumber,
        raw: line,
        timeMs,
        timeText: time,
        severity,
        title: shorten(`${method} ${safeDecode(path)}`, 160),
        badge: elbStatus,
        summary,
        metadata: [formatUtc(timeMs), ...(ip !== null ? [`IP: ${ip}`] : []), `${sent} bytes`, values[18] && values[18] !== "-" ? values[18] : values[2]],
        accent: attack !== null ? SEVERITY_COLORS.ERROR : SEVERITY_COLORS[severity],
        emphasis: attack !== null || severity === "ERROR",
        noise: false,
        ip,
        facets: {
            status: statusClass(elbStatus),
            attack: attack?.name ?? NO_ATTACK,
            client: client.kind,
            method,
            severity,
            path,
            code: elbStatus,
        },
        details: () => {
            const fields: EventField[] = values.map((value, index) => ({
                name: NAMES[index] ?? `Field ${index + 1}`,
                value,
                meaning: index === 8 ? statusMeaning(value) : index === 9 && value === "-" ? "No answer from the target" : index === 13 ? explainClient(client) : index === 24 ? ERROR_REASONS[value] ?? null : null,
                risky: index === 13 && client.kind === "Security scanner",
            }));

            if (attack !== null) {
                fields.push({ name: "Suspicious pattern", value: attack.matched, meaning: `${attack.name}: ${attack.explanation}`, risky: true });
            }

            return { fields };
        },
    };
}

export const awsAlbParser: LogParser = {
    id: "aws-alb",
    name: "AWS Application Load Balancer",
    description: "AWS ALB / ELB access logs: every HTTP request through the load balancer.",
    demoFile: "/static/demo/aws-alb.log",
    rawLabel: "Raw line",
    searchHint: "IP, path, status, user agent…",
    timeNote: "ALB writes times in UTC.",
    detect: sample => {
        const share = shareOf(sampleLines(sample), line => ALB_LINE.test(line));
        return share >= 0.5 ? 0.97 : share * 0.9;
    },
    parse: content => parseLineByLine(content, parseAlbLine, {
        reason: "This line does not look like an AWS load balancer access log entry.",
        isContinuation: () => false,
    }),
    facets: WEB_FACETS,
    sourcePanel: WEB_SOURCE_PANEL,
    coverage: webCoverage,
};
