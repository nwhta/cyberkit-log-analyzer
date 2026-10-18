import type { FacetDefinition, LogParser, ParsedEvent } from "./parserTypes.js";

export const logEntries: ParsedEvent[] = [];
export const logEntryElements: HTMLDivElement[] = [];

export interface CurrentLog {
    parser: LogParser;
    facets: FacetDefinition[];
    fileName: string;
    isDemo: boolean;
}

export let currentLog: CurrentLog | null = null;

export function setCurrentLog(log: CurrentLog): void {
    currentLog = log;
}

export function clearState(): void {
    logEntries.length = 0;
    logEntryElements.length = 0;
}
