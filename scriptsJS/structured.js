import { readJsonLines } from "./jsonRecords.js";
const ARRAY_KEYS = ["value", "records", "Records", "items", "entries", "logs", "events", "data"];
function asItems(list) {
    return list
        .filter(item => item !== null && typeof item === "object" && !Array.isArray(item))
        .map((record, index) => ({ record: record, raw: JSON.stringify(record), lineNumber: index + 1 }));
}
export function readJsonDocument(content) {
    const trimmed = content.trimStart();
    if (!trimmed.startsWith("[") && !trimmed.startsWith("{")) {
        return null;
    }
    try {
        const document = JSON.parse(trimmed);
        if (Array.isArray(document)) {
            return asItems(document);
        }
        if (document !== null && typeof document === "object") {
            for (const key of ARRAY_KEYS) {
                const list = document[key];
                if (Array.isArray(list)) {
                    return asItems(list);
                }
            }
            return asItems([document]);
        }
    }
    catch {
        return null;
    }
    return null;
}
export function readJsonEvents(content, toEvent, reason) {
    const document = readJsonDocument(content);
    return document !== null ? document.map(toEvent) : readJsonLines(content, toEvent, reason);
}
export function prettyJson(raw) {
    try {
        return JSON.stringify(JSON.parse(raw), null, 2);
    }
    catch {
        return raw;
    }
}
export function parseCsv(text) {
    const rows = [];
    let row = [];
    let cell = "";
    let quoted = false;
    const source = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
    for (let i = 0; i < source.length; i++) {
        const char = source[i];
        if (quoted) {
            if (char === "\"") {
                if (source[i + 1] === "\"") {
                    cell += "\"";
                    i++;
                }
                else {
                    quoted = false;
                }
            }
            else {
                cell += char;
            }
            continue;
        }
        if (char === "\"") {
            quoted = true;
        }
        else if (char === ",") {
            row.push(cell);
            cell = "";
        }
        else if (char === "\n" || char === "\r") {
            if (char === "\r" && source[i + 1] === "\n") {
                i++;
            }
            row.push(cell);
            rows.push(row);
            row = [];
            cell = "";
        }
        else {
            cell += char;
        }
    }
    if (cell !== "" || row.length > 0) {
        row.push(cell);
        rows.push(row);
    }
    return rows.filter(cells => cells.some(value => value !== ""));
}
export function csvRecords(text) {
    const rows = parseCsv(text);
    const header = (rows[0] ?? []).map(name => name.trim());
    const records = [];
    const lines = [];
    for (let i = 1; i < rows.length; i++) {
        const record = {};
        header.forEach((name, index) => {
            record[name] = rows[i][index] ?? "";
        });
        records.push(record);
        lines.push(i + 1);
    }
    return { header, records, lines };
}
export function text(record, ...paths) {
    for (const path of paths) {
        let current = record;
        for (const part of path.split(".")) {
            if (current === null || typeof current !== "object") {
                current = undefined;
                break;
            }
            current = current[part];
        }
        if (current !== undefined && current !== null && current !== "") {
            return typeof current === "object" ? JSON.stringify(current) : String(current);
        }
    }
    return "";
}
export function object(record, path) {
    let current = record;
    for (const part of path.split(".")) {
        if (current === null || typeof current !== "object") {
            return undefined;
        }
        current = current[part];
    }
    return current !== null && typeof current === "object" && !Array.isArray(current) ? current : undefined;
}
