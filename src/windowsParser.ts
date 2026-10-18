import type { AuditResult, WindowsLogEntry } from "./types.js";
import type { EventField, LogParser, ParsedEvent } from "./parserTypes.js";
import { parseWindowsXml } from "./windowsLogParser.js";
import { CATEGORY_LABELS, countCatalogedEvents, getCatalogCoverage, getLogonTypeName, getWindowsEventDescription, isFailedLogon } from "./windowsEventCatalog.js";
import { explainField, humanizeFieldName, parsePrivilegeList } from "./eventExplainer.js";
import { explainSysmonField } from "./sysmonExplainer.js";
import { SYSMON_PROVIDER } from "./sysmonCatalog.js";
import { DEFENDER_PROVIDER } from "./defenderCatalog.js";
import { getPrivilegeInfo } from "./windowsCodes.js";
import { AUDIT_COLORS } from "./colors.js";
import { SEVERITY_COLORS, SEVERITY_ORDER, severityColor } from "./severity.js";

const WINDOWS_EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event";

const AUDIT_LABELS: Readonly<Record<AuditResult, string>> = {
    FAILURE: "Audit Failure",
    SUCCESS: "Audit Success",
    NONE: "No audit flag",
};

const LABEL_TO_AUDIT = new Map<string, AuditResult>(
    Object.entries(AUDIT_LABELS).map(([result, label]) => [label, result as AuditResult])
);

const BRUTE_FORCE_THRESHOLD = 5;
const SPRAY_USER_THRESHOLD = 5;

function buildFields(entry: WindowsLogEntry): EventField[] {
    const fields: EventField[] = [];

    for (const { name, value } of entry.eventData) {
        if (name === "PrivilegeList") {
            for (const privilege of parsePrivilegeList(value)) {
                const info = getPrivilegeInfo(privilege);
                fields.push({
                    name: "Privilege",
                    value: privilege,
                    meaning: info === null ? null : `${info.name}: ${info.meaning}`,
                    risky: info?.risky ?? false,
                });
            }

            continue;
        }

        const meaning = entry.provider === SYSMON_PROVIDER
            ? explainSysmonField(name, value) ?? explainField(name, value)
            : explainField(name, value);

        fields.push({ name: humanizeFieldName(name || "Data"), value, meaning });
    }

    if (entry.alert !== null) {
        fields.unshift({ name: "Why this is flagged", value: entry.alert.name, meaning: entry.alert.reason, risky: true });
    }

    return fields;
}

function formatMetadata(entry: WindowsLogEntry): string[] {
    const parts = [`${entry.date} ${entry.time.slice(0, 8)} UTC`];

    if (entry.computer !== "") {
        parts.push(entry.computer);
    }

    if (entry.ip !== null) {
        parts.push(`IP: ${entry.ip}`);
    }

    if (entry.logonType !== null) {
        parts.push(getLogonTypeName(entry.logonType));
    }

    return parts;
}

function toParsedEvent(entry: WindowsLogEntry): ParsedEvent {
    const description = getWindowsEventDescription(entry.provider, entry.eventId);
    const catalogued = description !== "Uncatalogued Windows event";
    const firstMessageLine = entry.renderedMessage.split("\n")[0].trim();

    return {
        lineNumber: entry.lineNumber,
        raw: entry.line,
        timeMs: entry.timeMs,
        timeText: entry.timestamp,
        severity: entry.severity,
        title: entry.provider === SYSMON_PROVIDER
            ? `Sysmon ${entry.eventId} — ${description}`
            : entry.provider === DEFENDER_PROVIDER
            ? `Defender ${entry.eventId} — ${description}`
            : `${entry.eventId} — ${catalogued ? description : entry.provider || description}`,
        badge: entry.alert !== null ? `⚠ ${entry.alert.name}` : entry.provider === SYSMON_PROVIDER ? "SYSMON" : entry.provider === DEFENDER_PROVIDER ? "DEFENDER" : entry.isRoutine ? `${entry.auditResult} · routine` : entry.auditResult,
        summary: !catalogued && firstMessageLine !== "" ? firstMessageLine : entry.summary,
        metadata: formatMetadata(entry),
        accent: entry.alert !== null ? SEVERITY_COLORS.ERROR : entry.auditResult === "NONE" ? severityColor(entry.severity) : AUDIT_COLORS[entry.auditResult],
        emphasis: entry.alert !== null || entry.auditResult === "FAILURE" || entry.severity === "CRITICAL" || entry.severity === "ERROR",
        noise: entry.isRoutine,
        ip: entry.ip,
        facets: {
            audit: AUDIT_LABELS[entry.auditResult],
            category: CATEGORY_LABELS[entry.category],
            level: entry.severity,
            channel: entry.channel || "(not set)",
            failedLogon: isFailedLogon(entry.provider, entry.eventId) ? "yes" : "",
            ...(entry.provider === SYSMON_PROVIDER || entry.provider === DEFENDER_PROVIDER ? { alert: entry.alert?.name ?? "No alert" } : {}),
            user: entry.targetUser ?? "",
            logonType: entry.logonType === null ? "" : getLogonTypeName(entry.logonType),
        },
        details: () => ({
            fields: buildFields(entry),
            sections: entry.renderedMessage === "" ? [] : [{ title: "Windows message", text: entry.renderedMessage }],
        }),
    };
}

function formatXml(xml: string): string {
    const tokens = xml.match(/<[^>]+>|[^<]+/g) ?? [];
    const lines: string[] = [];
    let depth = 0;

    for (let i = 0; i < tokens.length; i++) {
        const token = tokens[i];
        const indent = "  ".repeat(depth);

        if (token.startsWith("</")) {
            depth = Math.max(depth - 1, 0);
            lines.push("  ".repeat(depth) + token);
        } else if (token.startsWith("<") && !token.endsWith("/>") && !token.startsWith("<?")) {
            const text = tokens[i + 1];
            const closing = tokens[i + 2];

            if (text !== undefined && !text.startsWith("<") && closing?.startsWith("</")) {
                lines.push(indent + token + text + closing);
                i += 2;
            } else {
                lines.push(indent + token);
                depth++;
            }
        } else if (token.trim() !== "") {
            lines.push(indent + token.trim());
        }
    }

    return lines.join("\n");
}

export const windowsParser: LogParser = {
    id: "windows-xml",
    name: "Windows Event Log (.evtx / XML)",
    description: "Event Viewer export (.evtx or XML): Security, System, Sysmon and Microsoft Defender logs.",
    demoFile: "/static/demo/windows-security.xml",
    rawLabel: "Raw XML",
    searchHint: "User, IP, event ID, text…",
    timeNote: "Windows exports times in UTC.",
    detect: sample => {
        const head = sample.trimStart();
        return head.startsWith("<") && head.includes("<Event") && head.includes(WINDOWS_EVENT_NAMESPACE) ? 1 : 0;
    },
    parse: content => parseWindowsXml(content).map(toParsedEvent),
    formatRaw: formatXml,
    coverage: () => ({
        summary: `${countCatalogedEvents()} Windows, Sysmon and Microsoft Defender event IDs get a plain-language explanation. Sysmon events are checked for suspicious behaviour (encoded PowerShell, LSASS access, code injection, persistence…); Defender detections, disabled protection and new exclusions are flagged. Any other event is still shown in full, marked "Uncatalogued Windows event".`,
        groups: getCatalogCoverage(),
    }),
    noise: {
        label: "Routine Windows activity",
        hint: "Background logons and checks by SYSTEM, service and computer accounts. Click to show them.",
    },
    facets: [
        {
            key: "audit",
            title: "Audit result",
            order: [AUDIT_LABELS.FAILURE, AUDIT_LABELS.SUCCESS, AUDIT_LABELS.NONE],
            color: value => AUDIT_COLORS[LABEL_TO_AUDIT.get(value) ?? "NONE"],
        },
        { key: "alert", title: "Sysmon / Defender alerts", color: value => value === "No alert" ? "#87909e" : SEVERITY_COLORS.ERROR },
        { key: "category", title: "Category" },
        { key: "level", title: "Level", order: SEVERITY_ORDER, color: severityColor },
        { key: "channel", title: "Channel" },
    ],
    sourcePanel: {
        title: "Failed logons by source IP",
        emptyText: "No failed logons with a source IP",
        subjectWord: ["account", "accounts"],
        select: event => event.facets.failedLogon !== "yes" || event.ip === null ? null : {
            ip: event.ip,
            subject: event.facets.user || null,
            tag: event.facets.logonType || null,
        },
        suspicion: stats => {
            if (stats.subjects.size >= SPRAY_USER_THRESHOLD) {
                return "possible password spray";
            }

            return stats.count >= BRUTE_FORCE_THRESHOLD ? "possible brute-force" : null;
        },
    },
};
