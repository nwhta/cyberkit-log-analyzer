const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const ISO_HEADER = /^(?:<\d+>\d?\s*)?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\S+)\s+/;
const BSD_HEADER = /^(?:<\d+>)?([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+/;
export function parseIsoTime(text) {
    const normalized = text.replace(/(\.\d{3})\d+/, "$1");
    return /(?:Z|[+-]\d{2}:?\d{2})$/.test(normalized) ? Date.parse(normalized) : Date.parse(normalized + "Z");
}
export function bsdTime(month, day, hour, minute, second, now = Date.now()) {
    const monthIndex = MONTHS.indexOf(month);
    const year = new Date(now).getUTCFullYear();
    let ms = Date.UTC(year, monthIndex, +day, +hour, +minute, +second);
    if (ms - now > 2 * 24 * 3600 * 1000) {
        ms = Date.UTC(year - 1, monthIndex, +day, +hour, +minute, +second);
    }
    return ms;
}
export function readSyslogHeader(line) {
    const iso = ISO_HEADER.exec(line);
    if (iso) {
        return { timeMs: parseIsoTime(iso[1]), timeText: iso[1], host: iso[2], rest: line.slice(iso[0].length) };
    }
    const bsd = BSD_HEADER.exec(line);
    if (bsd) {
        const [, month, day, hour, minute, second, host] = bsd;
        return {
            timeMs: bsdTime(month, day, hour, minute, second),
            timeText: `${month} ${day} ${hour}:${minute}:${second}`,
            host,
            rest: line.slice(bsd[0].length),
        };
    }
    return null;
}
