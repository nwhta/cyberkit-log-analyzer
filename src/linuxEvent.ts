import type { Severity } from "./types.js";
import type { EventField, FacetDefinition, NoiseDefinition, ParsedEvent, ParserCoverage, SourcePanelDefinition } from "./parserTypes.js";
import { formatUtc, shorten } from "./parseHelpers.js";
import { SEVERITY_COLORS, SEVERITY_ORDER, isSeriousSeverity, severityColor } from "./severity.js";
import { interpretLinuxMessage, listLinuxCoverage, type LinuxOutcome } from "./linuxMessages.js";

const FACILITIES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp",
    "ntp", "security", "console", "solaris-cron", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
];

const PRIORITY_NAMES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"];

export interface LinuxRecord {
    lineNumber: number;
    raw: string;
    timeMs: number;
    timeText: string;
    host: string;
    program: string;
    pid: string;
    message: string;
    priority: number | null;
    facility: number | null;
    extraFields: EventField[];
}

function severityFromPriority(priority: number): Severity {
    if (priority <= 2) return "CRITICAL";
    if (priority === 3) return "ERROR";
    if (priority === 4) return "WARNING";
    if (priority === 7) return "DEBUG";
    return "INFO";
}

function severityFromOutcome(outcome: LinuxOutcome): Severity {
    switch (outcome) {
        case "Error":
            return "ERROR";
        case "Failed":
        case "Blocked":
            return "WARNING";
        default:
            return "INFO";
    }
}

const OUTCOME_COLORS: Readonly<Record<string, string>> = {
    Failed: SEVERITY_COLORS.WARNING,
    Blocked: "#f08262",
    Error: SEVERITY_COLORS.ERROR,
    Success: "#5dc98b",
    Info: "#619aff",
};

export function buildLinuxEvent(record: LinuxRecord): ParsedEvent {
    const insight = interpretLinuxMessage(record.program, record.message);
    const fromPriority = record.priority === null ? null : severityFromPriority(record.priority);
    const severity = insight.severity ?? (fromPriority !== null && fromPriority !== "INFO" ? fromPriority : severityFromOutcome(insight.outcome));

    const metadata = [formatUtc(record.timeMs)];

    if (record.host !== "") {
        metadata.push(record.host);
    }

    metadata.push(record.pid !== "" ? `${record.program}[${record.pid}]` : record.program || "(no program)");

    if (insight.ip !== null) {
        metadata.push(`IP: ${insight.ip}`);
    }

    return {
        lineNumber: record.lineNumber,
        raw: record.raw,
        timeMs: record.timeMs,
        timeText: record.timeText,
        severity,
        title: shorten(insight.title, 160),
        badge: insight.outcome.toUpperCase(),
        summary: shorten(record.message),
        metadata,
        accent: isSeriousSeverity(severity) ? SEVERITY_COLORS[severity] : OUTCOME_COLORS[insight.outcome] ?? SEVERITY_COLORS[severity],
        emphasis: isSeriousSeverity(severity) || insight.outcome === "Failed" || insight.outcome === "Blocked",
        noise: insight.noise,
        ip: insight.ip,
        facets: {
            category: insight.category,
            outcome: insight.outcome,
            program: record.program || "(none)",
            severity,
            host: record.host || "(none)",
            user: insight.user ?? "",
            port: insight.port ?? "",
        },
        details: () => {
            const fields: EventField[] = [
                { name: "Time (as written)", value: record.timeText },
                { name: "Host", value: record.host },
                { name: "Program", value: record.program },
                { name: "Process ID", value: record.pid },
            ];

            if (record.priority !== null) {
                fields.push({ name: "Priority", value: String(record.priority), meaning: `${PRIORITY_NAMES[record.priority] ?? "?"} (0 = emergency … 7 = debug)` });
            }

            if (record.facility !== null) {
                fields.push({ name: "Facility", value: String(record.facility), meaning: FACILITIES[record.facility] ?? null });
            }

            if (insight.user !== null) {
                fields.push({ name: "User", value: insight.user });
            }

            if (insight.ip !== null) {
                fields.push({ name: "Remote IP", value: insight.ip });
            }

            if (insight.port !== null && insight.category !== "Firewall") {
                fields.push({ name: "Port", value: insight.port });
            }

            fields.push(...insight.fields, ...record.extraFields, { name: "Message", value: record.message });
            return { fields };
        },
    };
}

export const LINUX_FACETS: FacetDefinition[] = [
    { key: "outcome", title: "Outcome", order: ["Failed", "Blocked", "Error", "Success", "Info"], color: value => OUTCOME_COLORS[value] ?? "#87909e" },
    { key: "category", title: "Category" },
    { key: "severity", title: "Severity", order: SEVERITY_ORDER, color: severityColor },
    { key: "program", title: "Program" },
    { key: "host", title: "Host" },
];

export const LINUX_NOISE: NoiseDefinition = {
    label: "Routine system messages",
    hint: "Cron session open/close, systemd start/stop chatter, SMTP connect/disconnect, firewall AUDIT lines. Click to show them.",
};

const SSH_BRUTE_FORCE = 5;
const SPRAY_USERS = 5;
const PORT_SCAN_PORTS = 10;

export const LINUX_SOURCE_PANEL: SourcePanelDefinition = {
    title: "Failed logins and blocks by IP",
    emptyText: "No failed logins or firewall blocks with an IP",
    subjectWord: ["target", "targets"],
    select: event => {
        if (event.ip === null || (event.facets.outcome !== "Failed" && event.facets.outcome !== "Blocked")) {
            return null;
        }

        const subject = event.facets.user ? `user ${event.facets.user}` : event.facets.port ? `port ${event.facets.port}` : null;
        return { ip: event.ip, subject, tag: event.facets.category };
    },
    suspicion: stats => {
        const users = [...stats.subjects].filter(subject => subject.startsWith("user ")).length;
        const ports = [...stats.subjects].filter(subject => subject.startsWith("port ")).length;

        if (stats.tags.has("Firewall") && ports >= PORT_SCAN_PORTS) {
            return "possible port scan";
        }

        if (stats.tags.has("SSH") && users >= SPRAY_USERS) {
            return "possible SSH username guessing / spray";
        }

        if (stats.tags.has("SSH") && users >= 1 && stats.count >= SSH_BRUTE_FORCE) {
            return "possible SSH brute-force";
        }

        if (stats.tags.has("Mail") && stats.count >= SSH_BRUTE_FORCE) {
            return "possible mail password guessing";
        }

        return stats.count >= 10 ? "many failures from one IP" : null;
    },
};

export function linuxCoverage(intro: string): ParserCoverage {
    return {
        summary: `${intro} Messages from these programs get a plain-language title, an outcome and the extracted user / IP. Anything else is still shown in full.`,
        groups: listLinuxCoverage(),
    };
}
