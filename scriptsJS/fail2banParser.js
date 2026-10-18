import { cleanIp, formatUtc, parseLineByLine, sampleLines, shareOf, shorten } from "./parseHelpers.js";
import { SEVERITY_COLORS, SEVERITY_ORDER, severityColor, severityFromText } from "./severity.js";
const FAIL2BAN_LINE = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2}),(\d{3}) (fail2ban\.\S+)\s+\[(\d+)\]:\s+(\w+)\s+(.*)$/;
const JAIL_ACTION = /^\[([^\]]+)\] (Ban|Unban|Restore Ban|Found|Already banned|Ignore|Increase Ban) (\S+)(.*)$/;
const ACTION_MEANINGS = {
    Found: "A failure from this IP was found in the watched log (e.g. a wrong SSH password)",
    Ban: "The IP reached the limit and is now blocked by the firewall",
    "Restore Ban": "Ban restored after fail2ban restarted",
    Unban: "The ban time ended, the IP can connect again",
    "Already banned": "The IP is already blocked",
    Ignore: "The IP is on the ignore list (ignoreip) and will not be banned",
    "Increase Ban": "Repeat offender: ban time increased",
};
const ACTION_COLORS = {
    Ban: SEVERITY_COLORS.ERROR,
    "Restore Ban": "#f08262",
    "Increase Ban": SEVERITY_COLORS.ERROR,
    Found: SEVERITY_COLORS.WARNING,
    Unban: "#5dc98b",
};
function parseFail2banLine(line, lineNumber) {
    const match = FAIL2BAN_LINE.exec(line);
    if (!match) {
        return null;
    }
    const [, year, month, day, hour, minute, second, millis, component, pid, level, message] = match;
    const timeMs = Date.UTC(+year, +month - 1, +day, +hour, +minute, +second, +millis);
    const action = JAIL_ACTION.exec(message);
    const jail = action?.[1] ?? null;
    const verb = action?.[2] ?? null;
    const ip = action ? cleanIp(action[3]) : null;
    let severity = severityFromText(level);
    if (verb === "Ban" || verb === "Increase Ban") {
        severity = "WARNING";
    }
    else if (severity === "UNKNOWN") {
        severity = "INFO";
    }
    const title = verb !== null ? `${verb} ${action?.[3]} in jail ${jail}` : shorten(message, 160);
    const metadata = [formatUtc(timeMs), component];
    if (ip !== null) {
        metadata.push(`IP: ${ip}`);
    }
    return {
        lineNumber,
        raw: line,
        timeMs,
        timeText: `${year}-${month}-${day} ${hour}:${minute}:${second},${millis}`,
        severity,
        title,
        badge: verb?.toUpperCase() ?? level.toUpperCase(),
        summary: verb !== null ? ACTION_MEANINGS[verb] ?? "" : "",
        metadata,
        accent: verb !== null ? ACTION_COLORS[verb] ?? SEVERITY_COLORS.INFO : SEVERITY_COLORS[severity],
        emphasis: verb === "Ban" || verb === "Increase Ban" || severity === "ERROR" || severity === "CRITICAL",
        noise: false,
        ip,
        facets: {
            action: verb ?? "Other",
            jail: jail ?? "(none)",
            level: severity,
        },
        details: () => ({
            fields: [
                { name: "Time (as written)", value: `${year}-${month}-${day} ${hour}:${minute}:${second},${millis}`, meaning: "fail2ban writes server local time without a time zone" },
                { name: "Component", value: component, meaning: component.endsWith(".filter") ? "Filter: reads logs and finds failures" : component.endsWith(".actions") ? "Actions: bans and unbans IPs" : null },
                { name: "Process ID", value: pid },
                { name: "Level", value: level },
                { name: "Jail", value: jail ?? "", meaning: jail !== null ? "A jail = one service fail2ban protects (sshd, nginx-http-auth, postfix…)" : null },
                { name: "Action", value: verb ?? "", meaning: verb !== null ? ACTION_MEANINGS[verb] ?? null : null, risky: verb === "Ban" },
                { name: "IP", value: action?.[3] ?? "" },
                { name: "Extra", value: action?.[4]?.trim() ?? "" },
                { name: "Message", value: message },
            ],
        }),
    };
}
export const fail2banParser = {
    id: "fail2ban",
    name: "Fail2ban log",
    description: "/var/log/fail2ban.log: failures found, bans and unbans per jail (sshd, nginx, postfix…).",
    demoFile: "/static/demo/fail2ban.log",
    rawLabel: "Raw line",
    searchHint: "IP, jail…",
    timeNote: "fail2ban writes server local time without a time zone. Shown as written.",
    detect: sample => {
        const share = shareOf(sampleLines(sample), line => FAIL2BAN_LINE.test(line));
        return share >= 0.5 ? 0.97 : share * 0.9;
    },
    parse: content => parseLineByLine(content, parseFail2banLine, {
        reason: "This line does not look like a fail2ban log line (date time,ms fail2ban.component [pid]: LEVEL message).",
    }),
    facets: [
        { key: "action", title: "Action", order: ["Ban", "Increase Ban", "Restore Ban", "Found", "Unban", "Already banned", "Ignore", "Other"], color: value => ACTION_COLORS[value] ?? "#87909e" },
        { key: "jail", title: "Jail" },
        { key: "level", title: "Level", order: SEVERITY_ORDER, color: severityColor },
    ],
    sourcePanel: {
        title: "Most active IPs",
        emptyText: "No IPs found or banned",
        subjectWord: ["jail", "jails"],
        select: event => event.ip === null || event.facets.action === "Unban" ? null : {
            ip: event.ip,
            subject: event.facets.jail,
            tag: event.facets.action === "Ban" || event.facets.action === "Increase Ban" ? "banned" : null,
        },
        suspicion: stats => {
            if (stats.subjects.size >= 2) {
                return "attacks several services";
            }
            return stats.tags.has("banned") && stats.count >= 10 ? "persistent attacker" : stats.tags.has("banned") ? "banned" : null;
        },
    },
    coverage: () => ({
        summary: "Every line is shown. Jail actions get an explanation; other fail2ban messages are kept as they are.",
        groups: [{ title: "Actions", items: Object.entries(ACTION_MEANINGS).map(([verb, meaning]) => `${verb} — ${meaning}`) }],
    }),
};
