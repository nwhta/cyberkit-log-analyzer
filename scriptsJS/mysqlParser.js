import { parseLineByLine, sampleLines, shareOf } from "./parseHelpers.js";
import { appFacets, AUTH_FAILED, AUTH_SOURCE_PANEL, buildAppEvent } from "./appEvents.js";
const MYSQL_LINE = /^(\d{4}-\d{2}-\d{2}[T ] ?\d{1,2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?|\d{6} {1,2}\d{1,2}:\d{2}:\d{2})\s+(?:(\d+)\s+)?\[(\w+)\]\s+(?:\[(MY-\d+)\]\s+)?(?:\[(\w+)\]\s+)?(.*)$/;
const LEVELS = { ERROR: "ERROR", Warning: "WARNING", Note: "INFO", System: "INFO", Info: "INFO" };
const RULES = [
    { pattern: /Access denied for user '([^']*)'@'([^']*)'/, category: AUTH_FAILED, severity: "WARNING", title: "Access denied", meaning: "Wrong password or the user is not allowed from this host" },
    { pattern: /Host '([^']+)' is blocked because of many connection errors/, category: "Blocked host", severity: "ERROR", title: "Host blocked after many errors", meaning: "MySQL blocked this IP (max_connect_errors). Run FLUSH HOSTS to unblock" },
    { pattern: /Aborted connection \d+ to db: '([^']*)' user: '([^']*)' host: '([^']*)'/, category: "Aborted connection", severity: "INFO", title: "Connection aborted", meaning: "Client disconnected without closing properly (timeout, crash or network)" },
    { pattern: /Got an error reading communication packets|Got timeout reading communication packets/, category: "Aborted connection", title: "Network error with a client", meaning: "Packet could not be read (network problem or a scanner)" },
    { pattern: /IP address '([^']+)' could not be resolved/, category: "DNS", severity: "DEBUG", title: "Client IP could not be resolved to a name", meaning: "Harmless; skip-name-resolve avoids it" },
    { pattern: /Too many connections/, category: "Capacity", severity: "ERROR", title: "Too many connections", meaning: "max_connections reached" },
    { pattern: /ready for connections|Shutdown complete|Starting MySQL|mysqld .* starting as process|Server socket created/i, category: "Server", title: "Server start / stop", meaning: "MySQL started or stopped" },
    { pattern: /InnoDB:.*(corrupt|crash recovery|Database page corruption)/i, category: "Storage error", severity: "ERROR", title: "InnoDB corruption or crash recovery", meaning: "Data files may be damaged; check backups" },
    { pattern: /root@localhost is created with an empty password|Insecure configuration|--secure-file-priv/i, category: "Insecure config", severity: "WARNING", title: "Insecure configuration", meaning: "A security setting is weak" },
];
function toTime(stamp) {
    const old = /^(\d{2})(\d{2})(\d{2}) {1,2}(\d{1,2}):(\d{2}):(\d{2})$/.exec(stamp);
    if (old) {
        return Date.UTC(2000 + +old[1], +old[2] - 1, +old[3], +old[4], +old[5], +old[6]);
    }
    const iso = stamp.replace(" ", "T").replace(/T ?(\d):/, "T0$1:").replace(/(\.\d{3})\d+/, "$1");
    return /(?:Z|[+-]\d{2}:\d{2})$/.test(iso) ? Date.parse(iso) : Date.parse(iso + "Z");
}
function parseMysqlLine(line, lineNumber) {
    const match = MYSQL_LINE.exec(line);
    if (!match || !(match[3] in LEVELS)) {
        return null;
    }
    const [, stamp, thread, level, code, subsystem, message] = match;
    const rule = RULES.find(item => item.pattern.test(message));
    const found = rule?.pattern.exec(message);
    let user = null;
    let ip = null;
    if (rule?.category === AUTH_FAILED) {
        user = found?.[1] ?? null;
        ip = found?.[2] ?? null;
    }
    else if (rule?.category === "Aborted connection" && found?.[3]) {
        user = found[2] || null;
        ip = found[3];
    }
    else if (rule?.category === "Blocked host" || rule?.category === "DNS") {
        ip = found?.[1] ?? null;
    }
    const severity = rule?.severity ?? LEVELS[level] ?? "INFO";
    return buildAppEvent({
        lineNumber,
        raw: line,
        timeMs: toTime(stamp),
        timeText: stamp,
        severity,
        category: rule?.category ?? (level === "ERROR" ? "Error" : "Other"),
        title: rule ? `${rule.title}${user ? ` · ${user}` : ""}` : message,
        badge: code ?? level.toUpperCase(),
        summary: rule ? `${rule.meaning} · ${message}` : "",
        ip,
        user,
        noise: severity === "DEBUG",
        fields: [
            { name: "Level", value: level },
            ...(code ? [{ name: "Error code", value: code, meaning: "Search it in the MySQL error reference" }] : []),
            ...(subsystem ? [{ name: "Subsystem", value: subsystem }] : []),
            ...(thread ? [{ name: "Thread / connection ID", value: thread }] : []),
            { name: "Message", value: message, meaning: rule?.meaning ?? null, risky: rule?.category === AUTH_FAILED || rule?.category === "Blocked host" },
        ],
    });
}
export const mysqlParser = {
    id: "mysql",
    name: "MySQL / MariaDB error log",
    description: "MySQL and MariaDB error log: access denied, blocked hosts, aborted connections, crashes.",
    demoFile: "/static/demo/mysql-error.log",
    rawLabel: "Raw line",
    searchHint: "User, IP, error code…",
    timeNote: "MySQL 5.7+ writes UTC (Z). Older formats without a zone are shown as written.",
    detect: sample => {
        const share = shareOf(sampleLines(sample), line => {
            const match = MYSQL_LINE.exec(line);
            return match !== null && match[3] in LEVELS;
        });
        return share >= 0.5 ? 0.94 : share * 0.85;
    },
    parse: content => parseLineByLine(content, parseMysqlLine, {
        reason: "This line does not start with a MySQL error log prefix (time [Level] message).",
    }),
    facets: appFacets([AUTH_FAILED, "Blocked host", "Storage error", "Capacity", "Insecure config", "Error", "Aborted connection", "Server", "DNS", "Other"]),
    sourcePanel: AUTH_SOURCE_PANEL,
    noise: { label: "Name resolution warnings", hint: "\"IP address could not be resolved\" lines. Click to show them." },
    coverage: () => ({
        summary: "Every line is shown. To log failed logins on MySQL 8, set log_error_verbosity = 3.",
        groups: [{ title: "Recognized messages", items: RULES.map(rule => `${rule.title} — ${rule.meaning}`) }],
    }),
};
