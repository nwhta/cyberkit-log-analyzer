import type { Severity } from "./types.js";
import type { LogParser, ParsedEvent } from "./parserTypes.js";
import { makeUnparsedEvent, sampleLines, shareOf, splitLines } from "./parseHelpers.js";
import { appFacets, AUTH_FAILED, AUTH_SOURCE_PANEL, buildAppEvent } from "./appEvents.js";

const PG_LINE = /^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)(?: ([A-Z]{2,5}|[+-]\d{2}(?::?\d{2})?))? \[(\d+)\](?:[: ]\s*(?:\d+-\d+ )?)?(?:([\w.-]+)@([\w.-]+) )?(?:\S+ )?(DEBUG\d?|LOG|INFO|NOTICE|WARNING|ERROR|FATAL|PANIC|DETAIL|HINT|STATEMENT|CONTEXT|QUERY|LOCATION):\s+(.*)$/;
const ATTACH = new Set(["DETAIL", "HINT", "STATEMENT", "CONTEXT", "QUERY", "LOCATION"]);

const LEVELS: Readonly<Record<string, Severity>> = {
    LOG: "INFO", INFO: "INFO", NOTICE: "INFO", WARNING: "WARNING", ERROR: "ERROR", FATAL: "ERROR", PANIC: "CRITICAL",
};

interface Rule {
    pattern: RegExp;
    category: string;
    severity?: Severity;
    title: string;
    meaning: string;
}

const RULES: Rule[] = [
    { pattern: /password authentication failed for user "([^"]+)"/, category: AUTH_FAILED, severity: "WARNING", title: "Wrong password", meaning: "Login attempt with a wrong password" },
    { pattern: /no pg_hba\.conf entry for host "([^"]+)", user "([^"]+)"/, category: AUTH_FAILED, severity: "WARNING", title: "Connection not allowed by pg_hba.conf", meaning: "This IP / user / database combination is not allowed to connect" },
    { pattern: /role "([^"]+)" does not exist/, category: AUTH_FAILED, severity: "WARNING", title: "Login with a user that does not exist", meaning: "Typical for scanners guessing user names" },
    { pattern: /(?:Ident|peer|md5|scram-sha-256|certificate) authentication failed for user "([^"]+)"/, category: AUTH_FAILED, severity: "WARNING", title: "Authentication failed", meaning: "The client could not prove who it is" },
    { pattern: /connection authorized: user=(\S+)/, category: "Login OK", title: "Login succeeded", meaning: "User connected to a database" },
    { pattern: /connection received: host=(\S+)/, category: "Connection", severity: "DEBUG", title: "Connection received", meaning: "A client opened a TCP connection" },
    { pattern: /disconnection: session time/, category: "Connection", severity: "DEBUG", title: "Disconnected", meaning: "Client session ended" },
    { pattern: /COPY .* (?:FROM|TO) PROGRAM|pg_read_file|pg_ls_dir|lo_import|lo_export/i, category: "Suspicious command", severity: "CRITICAL", title: "Command that can run programs or read server files", meaning: "Often used after a break-in to run OS commands (e.g. COPY … FROM PROGRAM)" },
    { pattern: /\b(?:DROP|TRUNCATE) (?:TABLE|DATABASE|SCHEMA)\b|ALTER ROLE .* SUPERUSER|CREATE ROLE .* SUPERUSER/i, category: "Suspicious command", severity: "ERROR", title: "Destructive or privilege change command", meaning: "Data deletion or a new superuser" },
    { pattern: /sorry, too many clients already|remaining connection slots are reserved/, category: "Capacity", severity: "ERROR", title: "Too many connections", meaning: "max_connections reached; new clients are refused" },
    { pattern: /database "([^"]+)" does not exist/, category: "Client error", title: "Database does not exist", meaning: "Client asked for an unknown database" },
    { pattern: /database system is ready to accept connections|database system is shut down|starting PostgreSQL/, category: "Server", title: "Server start / stop", meaning: "PostgreSQL started or stopped" },
    { pattern: /checkpoint (?:starting|complete)|automatic (?:vacuum|analyze)/, category: "Maintenance", severity: "DEBUG", title: "Checkpoint / vacuum", meaning: "Routine background work" },
    { pattern: /syntax error|relation "[^"]+" does not exist|column "[^"]+" does not exist/, category: "Query error", title: "Query error", meaning: "A query failed (bug in the app, or SQL injection probing if from the web app)" },
];

function toTime(stamp: string, zone: string | undefined): number {
    const iso = stamp.replace(" ", "T").replace(/(\.\d{3})\d+/, "$1");

    if (zone === undefined || zone === "UTC" || zone === "GMT") {
        return Date.parse(iso + "Z");
    }

    if (/^[+-]\d{2}/.test(zone)) {
        const offset = zone.length === 3 ? `${zone}:00` : zone.includes(":") ? zone : `${zone.slice(0, 3)}:${zone.slice(3)}`;
        return Date.parse(iso + offset);
    }

    return Date.parse(iso + "Z");
}

export const postgresParser: LogParser = {
    id: "postgresql",
    name: "PostgreSQL log",
    description: "PostgreSQL server log: failed logins, pg_hba rejections, dangerous commands, errors.",
    demoFile: "/static/demo/postgresql.log",
    rawLabel: "Raw lines",
    searchHint: "User, IP, database, error…",
    timeNote: "Times with UTC or a numeric offset are converted; other zone names are shown as written.",
    detect: sample => {
        const share = shareOf(sampleLines(sample), line => PG_LINE.test(line));
        return share >= 0.5 ? 0.95 : share * 0.85;
    },
    parse: content => {
        const events: ParsedEvent[] = [];
        const hostByPid = new Map<string, string>();
        const lines = splitLines(content);

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];

            if (line.trim() === "") {
                continue;
            }

            const match = PG_LINE.exec(line);
            const previous = events[events.length - 1];

            if (!match) {
                if (previous !== undefined && /^\s/.test(line)) {
                    previous.raw += "\n" + line;
                    continue;
                }

                events.push(makeUnparsedEvent(line, i + 1, "This line does not start with a PostgreSQL log prefix (time [pid] LEVEL:)."));
                continue;
            }

            const [, stamp, zone, pid, prefixUser, database, level, message] = match;

            if (ATTACH.has(level) && previous !== undefined) {
                previous.raw += "\n" + line;
                const details = previous.details;
                previous.details = () => {
                    const result = details();
                    return { ...result, fields: [...result.fields, { name: level, value: message, meaning: level === "DETAIL" && message.includes("pg_hba.conf") ? "The pg_hba.conf rule that matched this connection" : null }] };
                };
                continue;
            }

            const received = /connection received: host=(\S+)/.exec(message);

            if (received) {
                hostByPid.set(pid, received[1]);
            }

            const rule = RULES.find(item => item.pattern.test(message));
            const ruleMatch = rule?.pattern.exec(message);
            const user = prefixUser && prefixUser !== "[unknown]" ? prefixUser
                : rule?.category === AUTH_FAILED ? ruleMatch?.[2] ?? ruleMatch?.[1] ?? null
                : /user=(\S+)/.exec(message)?.[1] ?? null;
            const ip = /host "([^"]+)"/.exec(message)?.[1] ?? hostByPid.get(pid) ?? null;
            const severity = rule?.severity ?? LEVELS[level] ?? "DEBUG";

            events.push(buildAppEvent({
                lineNumber: i + 1,
                raw: line,
                timeMs: toTime(stamp, zone),
                timeText: `${stamp}${zone ? " " + zone : ""}`,
                severity,
                category: rule?.category ?? (level === "ERROR" ? "Query error" : "Other"),
                title: rule ? `${rule.title}${user ? ` · ${user}` : ""}` : message,
                badge: level,
                summary: rule ? `${rule.meaning} · ${message}` : "",
                ip,
                user,
                host: database && database !== "[unknown]" ? `db: ${database}` : null,
                noise: severity === "DEBUG",
                emphasis: rule?.category === "Suspicious command",
                fields: [
                    { name: "Level", value: level },
                    { name: "Process ID", value: pid, meaning: "Same PID = same client session" },
                    { name: "Message", value: message, meaning: rule?.meaning ?? null, risky: rule?.category === AUTH_FAILED || rule?.category === "Suspicious command" },
                    ...(ip !== null ? [{ name: "Client IP", value: ip, meaning: received ? null : "Taken from the connection line of the same process" }] : []),
                ],
            }));
        }

        return events;
    },
    facets: appFacets([AUTH_FAILED, "Suspicious command", "Capacity", "Query error", "Client error", "Login OK", "Connection", "Server", "Maintenance", "Other"]),
    sourcePanel: AUTH_SOURCE_PANEL,
    noise: { label: "Connections and routine work", hint: "Connection / disconnection lines, checkpoints and vacuum. Click to show them." },
    coverage: () => ({
        summary: "Every line is shown. DETAIL / HINT / STATEMENT lines are attached to the message above. To see client IPs, enable log_connections.",
        groups: [{ title: "Recognized messages", items: RULES.map(rule => `${rule.title} — ${rule.meaning}`) }],
    }),
};
