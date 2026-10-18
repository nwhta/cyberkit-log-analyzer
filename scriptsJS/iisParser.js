import { cleanIp, cleanValue, formatUtc, makeUnparsedEvent, safeDecode, shorten, splitLines } from "./parseHelpers.js";
import { SEVERITY_COLORS } from "./severity.js";
import { detectWebAttack, NO_ATTACK } from "./webAttackPatterns.js";
import { classifyUserAgent, explainClient } from "./userAgents.js";
import { statusClass, statusMeaning, statusSeverity, WEB_FACETS, WEB_SOURCE_PANEL, webCoverage } from "./webTraffic.js";
const FIELD_LABELS = {
    "date": "Date (UTC)",
    "time": "Time (UTC)",
    "s-sitename": "Site",
    "s-computername": "Server name",
    "s-ip": "Server IP",
    "cs-method": "Method",
    "cs-uri-stem": "Path",
    "cs-uri-query": "Query string",
    "s-port": "Server port",
    "cs-username": "Authenticated user",
    "c-ip": "Client IP",
    "cs-version": "Protocol",
    "cs(User-Agent)": "User agent",
    "cs(Cookie)": "Cookie",
    "cs(Referer)": "Referer",
    "cs-host": "Host header",
    "sc-status": "Status",
    "sc-substatus": "Substatus",
    "sc-win32-status": "Win32 status",
    "sc-bytes": "Bytes sent",
    "cs-bytes": "Bytes received",
    "time-taken": "Time taken (ms)",
};
const SUBSTATUS_MEANINGS = {
    "401.1": "Logon failed — wrong user name or password",
    "401.2": "Logon failed due to server configuration (no auth method allowed)",
    "401.3": "Denied by NTFS permissions (ACL) on the resource",
    "403.4": "SSL required",
    "403.6": "Client IP address rejected",
    "403.14": "Directory listing denied",
    "404.0": "File or directory not found",
    "404.5": "Denied by request filtering: URL sequence",
    "404.7": "Denied by request filtering: file extension",
    "404.8": "Denied by request filtering: hidden segment (e.g. web.config, bin)",
    "404.11": "Denied by request filtering: double-escaped URL",
    "404.15": "Denied by request filtering: query string too long",
    "500.19": "Configuration data is invalid (web.config error)",
    "502.3": "Bad gateway: the backend (e.g. ASP.NET Core) failed",
    "503.0": "Application pool stopped or unavailable",
};
const WIN32_MEANINGS = {
    "0": "Success",
    "2": "File not found",
    "5": "Access denied",
    "64": "Client disconnected before the response finished",
    "121": "Connection timed out",
    "1236": "Connection aborted by the server",
    "1326": "Logon failure: unknown user name or bad password",
};
function readField(fields, values, name) {
    const index = fields.indexOf(name);
    return index >= 0 ? cleanValue(values[index]) : null;
}
function parseIisRow(fields, values, line, lineNumber) {
    const get = (name) => readField(fields, values, name);
    const date = get("date");
    const time = get("time");
    const timeMs = date !== null && time !== null ? Date.parse(`${date}T${time}Z`) : Number.NaN;
    const method = get("cs-method") ?? "-";
    const path = get("cs-uri-stem") ?? "";
    const query = get("cs-uri-query") ?? "";
    const status = get("sc-status") ?? "-";
    const substatus = get("sc-substatus");
    const userAgentRaw = get("cs(User-Agent)");
    const userAgent = userAgentRaw === null ? null : userAgentRaw.replace(/\+/g, " ");
    const ip = cleanIp(get("c-ip"));
    const user = get("cs-username");
    const client = classifyUserAgent(userAgent);
    const attack = detectWebAttack(`${path}?${query}`) ?? (userAgent ? detectWebAttack(userAgent) : null);
    const fullStatus = substatus !== null && substatus !== "0" ? `${status}.${substatus}` : status;
    const meaning = SUBSTATUS_MEANINGS[fullStatus] ?? statusMeaning(status);
    let severity = statusSeverity(status);
    if (attack !== null || client.kind === "Security scanner") {
        severity = severity === "ERROR" ? "ERROR" : "WARNING";
    }
    const summaryParts = [];
    if (attack !== null) {
        summaryParts.push(`${attack.name} attempt`);
    }
    summaryParts.push(meaning ?? `HTTP status ${fullStatus}`);
    if (user !== null) {
        summaryParts.push(`user: ${user}`);
    }
    if (client.kind !== "Browser") {
        summaryParts.push(client.name === null ? client.kind : `${client.kind}: ${client.name}`);
    }
    const metadata = [formatUtc(timeMs)];
    if (ip !== null) {
        metadata.push(`IP: ${ip}`);
    }
    const site = get("s-sitename");
    if (site !== null) {
        metadata.push(site);
    }
    return {
        lineNumber,
        raw: line,
        timeMs,
        timeText: `${date ?? ""} ${time ?? ""}`.trim(),
        severity,
        title: shorten(`${method} ${safeDecode(path)}`, 160),
        badge: fullStatus,
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
            method,
            severity,
            path,
            code: status,
        },
        details: () => {
            const detailFields = fields.map((name, index) => {
                const value = values[index] ?? "";
                let fieldMeaning = null;
                let risky = false;
                if (name === "sc-status") {
                    fieldMeaning = meaning;
                }
                else if (name === "sc-win32-status") {
                    fieldMeaning = WIN32_MEANINGS[value] ?? null;
                }
                else if (name === "cs(User-Agent)") {
                    fieldMeaning = explainClient(client);
                    risky = client.kind === "Security scanner";
                }
                else if ((name === "cs-uri-stem" || name === "cs-uri-query") && value.includes("%")) {
                    fieldMeaning = `Decoded: ${safeDecode(value)}`;
                }
                return { name: FIELD_LABELS[name] ?? name, value, meaning: fieldMeaning, risky };
            });
            if (values.length > fields.length) {
                detailFields.push({ name: "Extra values", value: values.slice(fields.length).join(" "), meaning: "More values than the #Fields header declares." });
            }
            if (attack !== null) {
                detailFields.push({ name: "Suspicious pattern", value: attack.matched, meaning: `${attack.name}: ${attack.explanation}`, risky: true });
            }
            return { fields: detailFields };
        },
    };
}
export const iisParser = {
    id: "iis-w3c",
    name: "IIS log (W3C extended)",
    description: "IIS web server log (W3C extended), usually in C:\\inetpub\\logs\\LogFiles.",
    demoFile: "/static/demo/iis.log",
    rawLabel: "Raw line",
    searchHint: "IP, path, status, user…",
    timeNote: "IIS writes W3C log times in UTC.",
    detect: sample => {
        if (/^#Software: Microsoft Internet Information Services/m.test(sample)) {
            return 0.99;
        }
        return /^#Fields:.*\bcs-uri-stem\b/m.test(sample) ? 0.9 : 0;
    },
    parse: content => {
        const events = [];
        let fields = [];
        const lines = splitLines(content);
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (line.trim() === "") {
                continue;
            }
            if (line.startsWith("#")) {
                if (line.startsWith("#Fields:")) {
                    fields = line.slice(8).trim().split(/\s+/);
                }
                continue;
            }
            const values = line.trim().split(" ");
            if (fields.length === 0 || values.length < fields.length) {
                events.push(makeUnparsedEvent(line, i + 1, "Row does not match the #Fields header of this IIS log."));
                continue;
            }
            events.push(parseIisRow(fields, values, line, i + 1));
        }
        return events;
    },
    facets: WEB_FACETS,
    sourcePanel: WEB_SOURCE_PANEL,
    coverage: webCoverage,
};
