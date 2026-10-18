import { makeUnparsedEvent, sampleLines, shareOf, splitLines, tryParseJsonObject } from "./parseHelpers.js";
export function jsonLineShare(sample) {
    return shareOf(sampleLines(sample), line => tryParseJsonObject(line) !== null);
}
export function sampleJsonRecords(sample) {
    const records = [];
    for (const line of sampleLines(sample)) {
        const record = tryParseJsonObject(line);
        if (record !== null) {
            records.push(record);
        }
    }
    return records;
}
export function readJsonLines(content, toEvent, reason) {
    const events = [];
    const lines = splitLines(content);
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.trim() === "") {
            continue;
        }
        const record = tryParseJsonObject(line);
        if (record === null) {
            events.push(makeUnparsedEvent(line, i + 1, reason));
            continue;
        }
        events.push(toEvent({ record, raw: line, lineNumber: i + 1 }));
    }
    return events;
}
export function firstValue(record, keys, read) {
    for (const key of keys) {
        const value = read(record, key);
        if (value !== undefined && value !== null && value !== "") {
            return value;
        }
    }
    return undefined;
}
