import type { LogParser } from "./parserTypes.js";

export type TimeMode = "local" | "utc";

const STORAGE_KEY = "timeMode";
const AS_WRITTEN_PARSERS = new Set([
    "apache-error", "nginx-error", "fail2ban", "linux-syslog", "windows-firewall", "snort-fast", "paloalto",
    "windows-dns", "bind-query", "dnsmasq", "openvpn",
]);

let mode: TimeMode = loadMode();
let asWritten = false;
const listeners: Array<() => void> = [];

function loadMode(): TimeMode {
    try {
        return localStorage.getItem(STORAGE_KEY) === "utc" ? "utc" : "local";
    } catch {
        return "local";
    }
}

function pad(value: number, length = 2): string {
    return String(value).padStart(length, "0");
}

function usesLocal(): boolean {
    return mode === "local" && !asWritten;
}

export function setTimeParser(parser: LogParser): void {
    asWritten = AS_WRITTEN_PARSERS.has(parser.id);
}

export function isAsWritten(): boolean {
    return asWritten;
}

export function getTimeMode(): TimeMode {
    return mode;
}

export function setTimeMode(value: TimeMode): void {
    mode = value;

    try {
        localStorage.setItem(STORAGE_KEY, value);
    } catch {
        return;
    }

    for (const listener of listeners) {
        listener();
    }
}

export function onTimeModeChange(listener: () => void): void {
    listeners.push(listener);
}

export function localZoneName(): string {
    const zone = Intl.DateTimeFormat().resolvedOptions().timeZone ?? "";
    const offsetMinutes = -new Date().getTimezoneOffset();
    const sign = offsetMinutes >= 0 ? "+" : "-";
    const absolute = Math.abs(offsetMinutes);
    const offset = `UTC${sign}${pad(Math.floor(absolute / 60))}:${pad(absolute % 60)}`;

    return zone === "" ? offset : `${zone}, ${offset}`;
}

export function zoneLabel(): string {
    if (asWritten) {
        return "as written in the log";
    }

    return mode === "local" ? `local time (${localZoneName()})` : "UTC";
}

export function toInputValue(ms: number): string {
    if (!usesLocal()) {
        return new Date(ms).toISOString().slice(0, 19);
    }

    const date = new Date(ms);
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

export function fromInputValue(value: string, isEnd: boolean): number | null {
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

export function formatEventTime(ms: number): string {
    if (Number.isNaN(ms)) {
        return "no timestamp";
    }

    const text = toInputValue(ms).replace("T", " ");

    if (asWritten) {
        return text;
    }

    return mode === "local" ? `${text} local` : `${text} UTC`;
}
