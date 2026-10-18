import { cleanIp, flattenObject, formatUtc, shorten } from "./parseHelpers.js";
import { SEVERITY_COLORS, SEVERITY_ORDER, severityColor } from "./severity.js";
import { object, prettyJson, readJsonEvents, text } from "./structured.js";
function severityOf(level) {
    return level >= 13 ? "CRITICAL" : level >= 10 ? "ERROR" : level >= 7 ? "WARNING" : level >= 3 ? "INFO" : "DEBUG";
}
function list(value) {
    return Array.isArray(value) ? value.map(String) : [];
}
function toEvent(item) {
    const record = item.record;
    const rule = object(record, "rule") ?? {};
    const level = Number(text(rule, "level") || "0");
    const severity = severityOf(level);
    const mitre = object(rule, "mitre") ?? {};
    const tactics = list(mitre.tactic);
    const techniques = list(mitre.id).map((id, index) => `${id} ${list(mitre.technique)[index] ?? ""}`.trim());
    const agent = text(record, "agent.name");
    const ip = cleanIp(text(record, "data.srcip", "data.src_ip", "data.win.eventdata.ipAddress"));
    const user = text(record, "data.srcuser", "data.dstuser", "data.win.eventdata.targetUserName");
    const time = text(record, "timestamp", "@timestamp");
    const timeMs = Date.parse(time.replace(/([+-]\d{2})(\d{2})$/, "$1:$2"));
    const groups = list(rule.groups);
    return {
        lineNumber: item.lineNumber,
        raw: item.raw,
        timeMs,
        timeText: time,
        severity,
        title: shorten(text(rule, "description") || "Wazuh alert", 180),
        badge: `LEVEL ${level}`,
        summary: shorten([techniques.length > 0 ? `MITRE ${techniques.join(", ")}` : "", user ? `user: ${user}` : "", text(record, "full_log")].filter(Boolean).join(" · ")),
        metadata: [formatUtc(timeMs), agent ? `agent ${agent}` : "", `rule ${text(rule, "id")}`, ip !== null ? `IP: ${ip}` : ""].filter(Boolean),
        accent: SEVERITY_COLORS[severity],
        emphasis: level >= 10,
        noise: level < 3,
        ip,
        facets: {
            severity,
            tactic: tactics[0] ?? "(none)",
            agent: agent || "(none)",
            group: groups.find(group => !["syslog", "ossec", "windows", "sysmon"].includes(group)) ?? groups[0] ?? "(none)",
            rule: text(rule, "description"),
        },
        details: () => ({
            fields: [
                { name: "Rule level", value: String(level), meaning: "Wazuh scale 0–15: 7+ worth a look, 10+ high, 12+ critical", risky: level >= 10 },
                { name: "MITRE ATT&CK", value: techniques.join(", "), meaning: tactics.length > 0 ? `Tactic: ${tactics.join(", ")}` : null },
                ...flattenObject(record).map(([name, value]) => ({ name, value })),
            ],
        }),
    };
}
export const wazuhParser = {
    id: "wazuh",
    name: "Wazuh / OSSEC alerts",
    description: "Wazuh alerts.json (and OSSEC JSON alerts) with rule level and MITRE ATT&CK mapping.",
    demoFile: "/static/demo/wazuh-alerts.json",
    rawLabel: "Raw JSON",
    searchHint: "Rule, agent, IP, MITRE ID…",
    timeNote: "Converted to UTC using the offset in each timestamp.",
    detect: sample => /"rule"\s*:\s*\{/.test(sample) && /"level"\s*:/.test(sample) && /"agent"\s*:\s*\{/.test(sample) && /"(full_log|decoder|manager)"\s*:/.test(sample) ? 0.97 : 0,
    parse: content => readJsonEvents(content, toEvent, "This line is not a valid Wazuh alert."),
    formatRaw: prettyJson,
    facets: [
        { key: "severity", title: "Severity", order: SEVERITY_ORDER, color: severityColor },
        { key: "tactic", title: "MITRE tactic", color: value => value === "(none)" ? "#87909e" : SEVERITY_COLORS.WARNING },
        { key: "group", title: "Rule group" },
        { key: "agent", title: "Agent" },
    ],
    sourcePanel: {
        title: "Alerts by source IP",
        emptyText: "No alerts with a source IP",
        subjectWord: ["rule", "rules"],
        select: event => event.ip === null ? null : { ip: event.ip, subject: event.facets.rule, tag: ["CRITICAL", "ERROR"].includes(event.severity) ? "high" : null },
        suspicion: stats => stats.tags.has("high") ? "high-level alerts" : stats.count >= 10 ? "many alerts" : null,
    },
    noise: { label: "Level 0–2 alerts", hint: "Very low level alerts. Click to show them." },
    coverage: () => ({ summary: "Every alert is shown with its rule level, MITRE ATT&CK tactic and technique, agent and all decoded fields.", groups: [] }),
};
