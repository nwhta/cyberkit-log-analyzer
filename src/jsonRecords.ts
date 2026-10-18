import type { ParsedEvent } from "./parserTypes.js";
import { makeUnparsedEvent, sampleLines, shareOf, splitLines, tryParseJsonObject } from "./parseHelpers.js";

export type JsonRecord = Record<string, unknown>;

export interface JsonItem {
    record: JsonRecord;
    raw: string;
    lineNumber: number;
}

export function jsonLineShare(sample: string): number {
    return shareOf(sampleLines(sample), line => tryParseJsonObject(line) !== null);
}

export function sampleJsonRecords(sample: string): JsonRecord[] {
    const records: JsonRecord[] = [];

    for (const line of sampleLines(sample)) {
        const record = tryParseJsonObject(line);

        if (record !== null) {
            records.push(record);
        }
    }

    return records;
}

export function readJsonLines(
    content: string,
    toEvent: (item: JsonItem) => ParsedEvent,
    reason: string
): ParsedEvent[] {
    const events: ParsedEvent[] = [];
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

export function firstValue(record: JsonRecord, keys: string[], read: (record: JsonRecord, key: string) => unknown): unknown {
    for (const key of keys) {
        const value = read(record, key);

        if (value !== undefined && value !== null && value !== "") {
            return value;
        }
    }

    return undefined;
}
