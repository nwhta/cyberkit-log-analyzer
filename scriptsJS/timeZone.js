const STORAGE_KEY = "timeMode";
const AS_WRITTEN_PARSERS = new Set([
    "apache-error", "nginx-error", "fail2ban", "linux-syslog", "windows-firewall", "snort-fast", "paloalto",
    "windows-dns", "bind-query", "dnsmasq", "openvpn",
]);
let mode = loadMode();
let asWritten = false;
const listeners = [];
function loadMode() {
    try {
        return localStorage.getItem(STORAGE_KEY) === "utc" ? "utc" : "local";
    }
    catch {
        return "local";
    }
}
function pad(value, length = 2) {
    return String(value).padStart(length, "0");
}
function usesLocal() {
    return mode === "local" && !asWritten;
}
export function setTimeParser(parser) {
    asWritten = AS_WRITTEN_PARSERS.has(parser.id);
}
export function isAsWritten() {
    return asWritten;
}
export function getTimeMode() {
    return mode;
}
export function setTimeMode(value) {
    mode = value;
    try {
        localStorage.setItem(STORAGE_KEY, value);
    }
    catch {
        return;
    }
    for (const listener of listeners) {
        listener();
    }
}
export function onTimeModeChange(listener) {
    listeners.push(listener);
}
export function localZoneName() {
    const zone = Intl.DateTimeFormat().resolvedOptions().timeZone ?? "";
    const offsetMinutes = -new Date().getTimezoneOffset();
    const sign = offsetMinutes >= 0 ? "+" : "-";
    const absolute = Math.abs(offsetMinutes);
    const offset = `UTC${sign}${pad(Math.floor(absolute / 60))}:${pad(absolute % 60)}`;
    return zone === "" ? offset : `${zone}, ${offset}`;
}
export function zoneLabel() {
    if (asWritten) {
        return "as written in the log";
    }
    return mode === "local" ? `local time (${localZoneName()})` : "UTC";
}
export function toInputValue(ms) {
    if (!usesLocal()) {
        return new Date(ms).toISOString().slice(0, 19);
    }
    const date = new Date(ms);
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}
export function fromInputValue(value, isEnd) {
    if (value === "") {
        return null;
    }
    const hasSeconds = value.length > 16;
    const text = hasSeconds ? value : value + ":00";
    const ms = usesLocal() ? new Date(text).getTime() : Date.parse(text + "Z");
    if (Number.isNaN(ms)) {
        return null;
    }
    return isEnd ? ms + (hasSeconds ? 999 : 59_999) : ms;
}
export function formatEventTime(ms) {
    if (Number.isNaN(ms)) {
        return "no timestamp";
    }
    const text = toInputValue(ms).replace("T", " ");
    if (asWritten) {
        return text;
    }
    return mode === "local" ? `${text} local` : `${text} UTC`;
}
