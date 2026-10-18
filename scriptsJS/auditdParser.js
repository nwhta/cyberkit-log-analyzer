import { cleanIp, formatUtc, makeUnparsedEvent, sampleLines, shareOf, shorten, splitLines } from "./parseHelpers.js";
import { SEVERITY_COLORS, SEVERITY_ORDER, isSeriousSeverity, severityColor } from "./severity.js";
const RECORD_LINE = /^type=(\S+) msg=audit\(([^)]+)\)\s?:\s?(.*)$/;
const UNSET_ID = "4294967295";
const TYPE_MEANINGS = {
    USER_LOGIN: "Login attempt",
    USER_AUTH: "Password / authentication check",
    USER_ACCT: "Account allowed to log in? (expiry, access rules)",
    USER_START: "Session started",
    USER_END: "Session ended",
    USER_LOGOUT: "Logout",
    USER_ERR: "Error in the login process",
    USER_CMD: "Command run through sudo",
    USER_CHAUTHTOK: "Password changed",
    USER_MGMT: "User account changed",
    USER_ROLE_CHANGE: "SELinux role changed",
    CRED_ACQ: "Credentials acquired",
    CRED_DISP: "Credentials released",
    CRED_REFR: "Credentials refreshed",
    ADD_USER: "User account created",
    DEL_USER: "User account deleted",
    ADD_GROUP: "Group created",
    DEL_GROUP: "Group deleted",
    GRP_MGMT: "Group changed",
    LOGIN: "Login session ID assigned",
    SYSCALL: "System call matched an audit rule",
    EXECVE: "Program arguments",
    PATH: "File touched by the system call",
    CWD: "Working folder",
    PROCTITLE: "Full command line",
    SOCKADDR: "Network address used",
    CONFIG_CHANGE: "Audit rules changed",
    DAEMON_START: "Audit service started",
    DAEMON_END: "Audit service stopped",
    DAEMON_ABORT: "Audit service crashed",
    SERVICE_START: "systemd service started",
    SERVICE_STOP: "systemd service stopped",
    SYSTEM_BOOT: "System booted",
    SYSTEM_SHUTDOWN: "System shut down",
    SYSTEM_RUNLEVEL: "Runlevel changed",
    AVC: "SELinux decision",
    ANOM_ABEND: "Program crashed",
    ANOM_PROMISCUOUS: "Network card switched to promiscuous (sniffing) mode",
    ANOM_LOGIN_FAILURES: "Too many failed logins",
    ANOM_LOGIN_LOCATION: "Login from a forbidden location",
    NETFILTER_CFG: "Firewall rules changed",
    KERN_MODULE: "Kernel module loaded / unloaded",
    TTY: "Keystrokes typed in a terminal",
    USER_TTY: "Keystrokes typed in a terminal",
    BPF: "BPF program loaded",
    MAC_STATUS: "SELinux mode changed",
};
const SECONDARY_TYPES = new Set(["EXECVE", "PATH", "CWD", "PROCTITLE", "SOCKADDR", "BPRM_FCAPS", "OBJ_PID", "EOE"]);
const ROUTINE_TYPES = new Set(["CRED_ACQ", "CRED_DISP", "CRED_REFR", "BPF"]);
const ACCOUNT_TYPES = new Set(["ADD_USER", "DEL_USER", "ADD_GROUP", "DEL_GROUP", "USER_CHAUTHTOK", "USER_MGMT", "GRP_MGMT"]);
const HEX_KEYS = /^(?:a\d+|proctitle|cmd|data|name|exe|comm|acct|cwd|path)$/;
function decodeHex(value) {
    if (value.length % 2 !== 0 || !/^[0-9A-F]+$/.test(value)) {
        return value;
    }
    let result = "";
    for (let i = 0; i < value.length; i += 2) {
        const code = parseInt(value.slice(i, i + 2), 16);
        result += code === 0 ? " " : String.fromCharCode(code);
    }
    return /^[\x20-\x7e\s]*$/.test(result) ? result.trim() : value;
}
function parseValues(text, into = new Map()) {
    const pattern = /(\w+)=("(?:[^"\\]|\\.)*"|'[^']*'|\S+)/g;
    for (const match of text.matchAll(pattern)) {
        const key = match[1];
        const rawValue = match[2];
        if (rawValue.startsWith("'")) {
            parseValues(rawValue.slice(1, -1), into);
            continue;
        }
        const value = rawValue.startsWith("\"") ? rawValue.slice(1, -1) : HEX_KEYS.test(key) ? decodeHex(rawValue) : rawValue;
        if (!into.has(key)) {
            into.set(key, value);
        }
    }
    return into;
}
function parseStamp(stamp) {
    const serial = stamp.lastIndexOf(":");
    const time = serial >= 0 ? stamp.slice(0, serial) : stamp;
    const id = serial >= 0 ? stamp.slice(serial + 1) : stamp;
    if (/^\d+(\.\d+)?$/.test(time)) {
        return { timeMs: Math.round(Number(time) * 1000), id };
    }
    const interpreted = /^(\d{2})\/(\d{2})\/(\d{4}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$/.exec(time);
    if (interpreted) {
        const [, month, day, year, hour, minute, second, millis] = interpreted;
        return { timeMs: Date.UTC(+year, +month - 1, +day, +hour, +minute, +second, Number((millis ?? "0").padEnd(3, "0").slice(0, 3))), id };
    }
    return { timeMs: Number.NaN, id };
}
function pick(group, ...keys) {
    for (const key of keys) {
        for (const record of group.records) {
            const value = record.values.get(key);
            if (value !== undefined && value !== "" && value !== "?" && value !== "(null)" && value !== UNSET_ID && value !== "unset") {
                return value;
            }
        }
    }
    return null;
}
function commandOf(group) {
    const execve = group.records.find(record => record.type === "EXECVE");
    if (execve !== undefined) {
        const count = Number(execve.values.get("argc") ?? "0");
        const args = [];
        for (let i = 0; i < Math.max(count, 1); i++) {
            const arg = execve.values.get(`a${i}`);
            if (arg === undefined) {
                break;
            }
            args.push(arg);
        }
        if (args.length > 0) {
            return args.join(" ");
        }
    }
    return group.records.find(record => record.type === "PROCTITLE")?.values.get("proctitle") ?? pick(group, "cmd");
}
function describe(type, group, user, ip, result, command) {
    const by = user !== null ? ` for ${user}` : "";
    const from = ip !== null ? ` from ${ip}` : "";
    const failed = result === "failed" || result === "no";
    const exe = pick(group, "exe", "comm");
    switch (type) {
        case "USER_LOGIN":
            return `Login ${failed ? "failed" : "succeeded"}${by}${from}${exe ? ` (${exe.split("/").pop()})` : ""}`;
        case "USER_AUTH":
            return `Authentication ${failed ? "failed" : "succeeded"}${by}${from}${exe ? ` (${exe.split("/").pop()})` : ""}`;
        case "USER_CMD":
            return `${user ?? "Someone"} ran with sudo: ${command ?? "?"}`;
        case "ADD_USER":
        case "DEL_USER":
        case "ADD_GROUP":
        case "DEL_GROUP":
        case "USER_CHAUTHTOK":
        case "USER_MGMT":
        case "GRP_MGMT":
            return `${TYPE_MEANINGS[type]}: ${pick(group, "acct", "id") ?? "?"}${failed ? " (failed)" : ""}`;
        case "SYSCALL": {
            const key = pick(group, "key");
            const target = group.records.find(record => record.type === "PATH" && record.values.get("nametype") !== "PARENT")?.values.get("name");
            const what = command ?? target ?? exe ?? `syscall ${pick(group, "syscall") ?? "?"}`;
            return `${key ? `[${key}] ` : ""}${user ?? "?"}: ${what}${failed ? " (failed)" : ""}`;
        }
        case "AVC":
            return `SELinux ${/denied/.test(group.records[0].line) ? "denied" : "allowed"}: ${pick(group, "comm") ?? "?"} → ${pick(group, "name", "path") ?? pick(group, "tclass") ?? ""}`;
        case "SERVICE_START":
        case "SERVICE_STOP":
            return `${TYPE_MEANINGS[type]}: ${pick(group, "unit") ?? "?"}${failed ? " (failed)" : ""}`;
        default:
            return `${TYPE_MEANINGS[type] ?? type}${by}${from}${failed ? " (failed)" : ""}`;
    }
}
function toEvent(group) {
    const primary = group.records.find(record => !SECONDARY_TYPES.has(record.type)) ?? group.records[0];
    const type = primary.type;
    const { timeMs } = parseStamp(group.stamp);
    const result = pick(group, "res", "success");
    const failed = result === "failed" || result === "no";
    const avcDenied = type === "AVC" && /denied/.test(primary.line);
    const auid = pick(group, "auid");
    const user = pick(group, "acct", "AUID", "UID") ?? (auid === null ? null : /^\d+$/.test(auid) ? `uid ${auid}` : auid);
    const addr = pick(group, "addr");
    const ip = addr !== null ? cleanIp(addr) : null;
    const command = commandOf(group);
    const key = pick(group, "key");
    const outcome = avcDenied ? "Blocked" : failed ? "Failed" : result !== null ? "Success" : "Info";
    let severity = "INFO";
    if (type.startsWith("ANOM_") || type === "DAEMON_ABORT") {
        severity = "ERROR";
    }
    else if (failed || avcDenied || ACCOUNT_TYPES.has(type) || type === "CONFIG_CHANGE" || type === "NETFILTER_CFG" || type === "KERN_MODULE" || type === "MAC_STATUS") {
        severity = "WARNING";
    }
    const exe = pick(group, "exe");
    const routine = ROUTINE_TYPES.has(type) || ((type === "USER_START" || type === "USER_END" || type === "USER_ACCT") && /cron/.test(exe ?? "") && !failed);
    const metadata = [formatUtc(timeMs), `event ${group.id}`];
    if (ip !== null) {
        metadata.push(`IP: ${ip}`);
    }
    if (exe !== null) {
        metadata.push(exe);
    }
    return {
        lineNumber: group.lineNumber,
        raw: group.records.map(record => record.line).join("\n"),
        timeMs,
        timeText: group.stamp,
        severity,
        title: shorten(describe(type, group, user, ip, result, command), 160),
        badge: type,
        summary: shorten(TYPE_MEANINGS[type] ?? `Audit record ${type}`),
        metadata,
        accent: avcDenied || failed ? SEVERITY_COLORS.WARNING : SEVERITY_COLORS[severity],
        emphasis: isSeriousSeverity(severity) || failed || avcDenied,
        noise: routine,
        ip,
        facets: {
            outcome,
            type,
            key: key ?? "(no rule key)",
            user: user ?? "(unknown)",
            severity,
        },
        details: () => {
            const fields = [
                { name: "Event ID", value: group.id, meaning: "All records with this ID belong to the same action" },
                { name: "Record types", value: group.records.map(record => record.type).join(", ") },
            ];
            if (command !== null) {
                fields.push({ name: "Command", value: command, meaning: "Decoded from EXECVE / PROCTITLE (audit stores it in hex)" });
            }
            const auid = pick(group, "auid");
            if (auid !== null) {
                fields.push({ name: "auid", value: auid, meaning: "Login user ID: the real person behind the action, even after sudo/su" });
            }
            if (key !== null) {
                fields.push({ name: "Rule key", value: key, meaning: "Name of the audit rule (-k) that recorded this" });
            }
            for (const record of group.records) {
                for (const [name, value] of record.values) {
                    fields.push({ name: `${record.type}.${name}`, value, meaning: name === "res" || name === "success" ? (value === "failed" || value === "no" ? "Failed" : "Succeeded") : null, risky: (name === "res" && value === "failed") || (name === "success" && value === "no") });
                }
            }
            return { fields };
        },
    };
}
function parseAudit(content) {
    const groups = new Map();
    const order = [];
    const lines = splitLines(content);
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].replace(/\x1d/g, " ");
        if (line.trim() === "" || line.trim() === "----") {
            continue;
        }
        const match = RECORD_LINE.exec(line.replace(/^node=\S+ /, ""));
        if (!match) {
            order.push(makeUnparsedEvent(lines[i], i + 1, "This line is not an audit record (type=… msg=audit(…))."));
            continue;
        }
        const [, type, stamp, rest] = match;
        const { id } = parseStamp(stamp);
        let group = groups.get(stamp);
        if (group === undefined) {
            group = { id, stamp, lineNumber: i + 1, records: [] };
            groups.set(stamp, group);
            order.push(group);
        }
        group.records.push({ type, values: parseValues(rest), line: lines[i] });
    }
    return order.map(item => "records" in item ? toEvent(item) : item);
}
export const auditdParser = {
    id: "linux-auditd",
    name: "Linux audit log (auditd)",
    description: "/var/log/audit/audit.log, raw or from ausearch -i: logins, sudo, account changes, watched files.",
    demoFile: "/static/demo/audit.log",
    rawLabel: "Raw records",
    searchHint: "User, IP, rule key, command…",
    timeNote: "auditd writes Unix timestamps, shown in UTC. ausearch -i times are shown as written.",
    detect: sample => {
        const lines = sampleLines(sample).filter(line => line !== "----");
        const share = shareOf(lines, line => RECORD_LINE.test(line.replace(/^node=\S+ /, "")));
        return share >= 0.6 ? 0.97 : share * 0.9;
    },
    parse: parseAudit,
    facets: [
        { key: "outcome", title: "Outcome", order: ["Failed", "Blocked", "Success", "Info"], color: value => value === "Failed" ? SEVERITY_COLORS.WARNING : value === "Blocked" ? "#f08262" : value === "Success" ? "#5dc98b" : "#619aff" },
        { key: "type", title: "Record type" },
        { key: "key", title: "Rule key" },
        { key: "user", title: "User" },
        { key: "severity", title: "Severity", order: SEVERITY_ORDER, color: severityColor },
    ],
    noise: {
        label: "Routine audit records",
        hint: "Credential acquire / release records and cron sessions. Click to show them.",
    },
    sourcePanel: {
        title: "Failed logins by IP",
        emptyText: "No failed logins with a remote address",
        subjectWord: ["account", "accounts"],
        select: event => event.ip === null || event.facets.outcome !== "Failed" ? null : { ip: event.ip, subject: event.facets.user, tag: event.facets.type },
        suspicion: stats => stats.subjects.size >= 5 ? "possible password spray" : stats.count >= 5 ? "possible brute-force" : null,
    },
    coverage: () => ({
        summary: "Records of one action (same event ID) are joined into one event. Hex-encoded commands are decoded. Every record and field stays visible in Details.",
        groups: [{ title: "Record types with an explanation", items: Object.entries(TYPE_MEANINGS).map(([type, meaning]) => `${type} — ${meaning}`) }],
    }),
};
