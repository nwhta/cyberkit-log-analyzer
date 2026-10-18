import type { Severity } from "./types.js";

export interface EventField {
    name: string;
    value: string;
    meaning?: string | null;
    risky?: boolean;
}

export interface DetailsSection {
    title: string;
    text: string;
}

export interface EventDetails {
    fields: EventField[];
    sections?: DetailsSection[];
}

export interface ParsedEvent {
    lineNumber: number;
    raw: string;
    timeMs: number;
    timeText: string;
    severity: Severity;
    title: string;
    badge: string;
    summary: string;
    metadata: string[];
    accent: string;
    emphasis: boolean;
    noise: boolean;
    ip: string | null;
    facets: Record<string, string>;
    details: () => EventDetails;
}

export interface FacetDefinition {
    key: string;
    title: string;
    color?: (value: string) => string;
    order?: string[];
}

export interface SourceHit {
    ip: string;
    subject: string | null;
    tag: string | null;
}

export interface SourceStats {
    ip: string;
    count: number;
    subjects: Set<string>;
    tags: Set<string>;
}

export interface SourcePanelDefinition {
    title: string;
    emptyText: string;
    subjectWord: [string, string];
    select: (event: ParsedEvent) => SourceHit | null;
    suspicion: (stats: SourceStats) => string | null;
}

export interface NoiseDefinition {
    label: string;
    hint: string;
}

export interface CoverageGroup {
    title: string;
    items: string[];
}

export interface ParserCoverage {
    summary: string;
    groups: CoverageGroup[];
}

export interface LogParser {
    id: string;
    name: string;
    description: string;
    demoFile?: string;
    rawLabel: string;
    searchHint: string;
    timeNote: string;
    detect: (sample: string) => number;
    parse: (content: string) => ParsedEvent[];
    facets: FacetDefinition[];
    sourcePanel?: SourcePanelDefinition;
    noise?: NoiseDefinition;
    formatRaw?: (raw: string) => string;
    coverage?: () => ParserCoverage;
}
