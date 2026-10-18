import { formatUtc } from "./parseHelpers.js";
import { buildLinuxEvent, LINUX_FACETS, LINUX_NOISE, LINUX_SOURCE_PANEL, linuxCoverage } from "./linuxEvent.js";
import { readJsonLines, sampleJsonRecords } from "./jsonRecords.js";
const JOURNAL_FIELD_MEANINGS = {
    _SYSTEMD_UNIT: "systemd service that wrote the message",
    _COMM: "Process name",
    _EXE: "Program file",
    _CMDLINE: "Full command line of the process",
    _UID: "User ID of the process (0 = root)",
    _GID: "Group ID of the process",
    _TRANSPORT: "How the message reached journald (journal, syslog, kernel, stdout)",
    _BOOT_ID: "ID of the boot. Different value = the machine was restarted",
    _MACHINE_ID: "Unique ID of this machine",
    __CURSOR: "Position in the journal",
    SYSLOG_IDENTIFIER: "Program name as used in syslog",
};
function text(record, key) {
    const value = record[key];
    if (value === undefined || value === null) {
        return "";
    }
    if (Array.isArray(value)) {
        try {
            return new TextDecoder().decode(new Uint8Array(value));
        }
        catch {
            return value.join(",");
        }
    }
    return String(value);
}
function journalTime(record) {
    const micros = text(record, "__REALTIME_TIMESTAMP") || text(record, "_SOURCE_REALTIME_TIMESTAMP");
    return /^\d+$/.test(micros) ? Math.floor(Number(micros) / 1000) : Number.NaN;
}
function toEvent({ record, raw, lineNumber }) {
    const timeMs = journalTime(record);
    const priorityText = text(record, "PRIORITY");
    const facilityText = text(record, "SYSLOG_FACILITY");
    const program = text(record, "SYSLOG_IDENTIFIER") || text(record, "_COMM") || text(record, "_SYSTEMD_UNIT").replace(/\.service$/, "") || (text(record, "_TRANSPORT") === "kernel" ? "kernel" : "");
    const extraFields = Object.keys(JOURNAL_FIELD_MEANINGS)
        .filter(key => key in record)
        .map(key => ({ name: key, value: text(record, key), meaning: JOURNAL_FIELD_MEANINGS[key] }));
    return buildLinuxEvent({
        lineNumber,
        raw,
        timeMs,
        timeText: formatUtc(timeMs),
        host: text(record, "_HOSTNAME"),
        program,
        pid: text(record, "_PID") || text(record, "SYSLOG_PID"),
        message: text(record, "MESSAGE"),
        priority: /^[0-7]$/.test(priorityText) ? Number(priorityText) : null,
        facility: /^\d+$/.test(facilityText) ? Number(facilityText) : null,
        extraFields,
    });
}
export const journaldParser = {
    id: "linux-journald",
    name: "systemd journal (journalctl -o json)",
    description: "Linux systemd journal exported with: journalctl -o json > journal.json",
    demoFile: "/static/demo/journal.json",
    rawLabel: "Raw JSON",
    searchHint: "User, IP, unit, message…",
    timeNote: "journald stores exact UTC timestamps (microseconds).",
    detect: sample => {
        const records = sampleJsonRecords(sample);
        if (records.length === 0) {
            return 0;
        }
        const journal = records.filter(record => "MESSAGE" in record && ("__REALTIME_TIMESTAMP" in record || "_SYSTEMD_UNIT" in record || "SYSLOG_IDENTIFIER" in record));
        return journal.length / records.length >= 0.6 ? 0.96 : 0;
    },
    parse: content => readJsonLines(content, toEvent, "This line is not a valid journal JSON entry."),
    facets: LINUX_FACETS,
    sourcePanel: LINUX_SOURCE_PANEL,
    noise: LINUX_NOISE,
    coverage: () => linuxCoverage("Same message rules as the syslog parser, plus journald metadata (unit, UID, boot ID)."),
};
