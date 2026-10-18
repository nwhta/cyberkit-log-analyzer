import type { ParsedEvent, SourcePanelDefinition, SourceStats } from "./parserTypes.js";
import { filterState } from "./filterState.js";
import { applyFilters } from "./filters.js";
import { sourcePanelElement } from "./dom.js";
import { mask } from "./sanitize.js";

const MAX_SUBJECTS_SHOWN = 3;
const MAX_ROWS = 200;

const rowsByIp = new Map<string, HTMLButtonElement>();

export function clearSourceSelection(): void {
    filterState.selectedIp = null;

    for (const row of rowsByIp.values()) {
        row.classList.remove("selected");
    }
}

export function collectSources(definition: SourcePanelDefinition, events: ParsedEvent[]): SourceStats[] {
    const byIp = new Map<string, SourceStats>();

    for (const event of events) {
        const hit = definition.select(event);

        if (hit === null) {
            continue;
        }

        let stats = byIp.get(hit.ip);

        if (!stats) {
            stats = { ip: hit.ip, count: 0, subjects: new Set(), tags: new Set() };
            byIp.set(hit.ip, stats);
        }

        stats.count++;

        if (hit.subject !== null && hit.subject !== "") {
            stats.subjects.add(hit.subject);
        }

        if (hit.tag !== null && hit.tag !== "") {
            stats.tags.add(hit.tag);
        }
    }

    return [...byIp.values()].sort((a, b) => b.count - a.count);
}

export function formatDetails(stats: SourceStats, words: [string, string]): string {
    const parts: string[] = [];
    const subjects = [...stats.subjects];

    if (subjects.length > 0) {
        const label = subjects.length === 1 ? words[0] : `${subjects.length} ${words[1]}`;
        const shown = subjects.slice(0, MAX_SUBJECTS_SHOWN).join(", ");
        const hidden = subjects.length - MAX_SUBJECTS_SHOWN;
        parts.push(hidden > 0 ? `${label}: ${shown} +${hidden}` : `${label}: ${shown}`);
    }

    if (stats.tags.size > 0) {
        const tags = [...stats.tags];
        parts.push(tags.length > MAX_SUBJECTS_SHOWN ? `${tags.slice(0, MAX_SUBJECTS_SHOWN).join(", ")} +${tags.length - MAX_SUBJECTS_SHOWN}` : tags.join(", "));
    }

    return parts.join(" · ");
}

function appendText(parent: HTMLElement, className: string, text: string): void {
    const element = document.createElement("div");
    element.className = className;
    element.textContent = text;
    parent.appendChild(element);
}

export function buildSourcePanel(definition: SourcePanelDefinition | undefined, events: ParsedEvent[]): void {
    sourcePanelElement.replaceChildren();
    sourcePanelElement.hidden = definition === undefined;

    if (definition === undefined) {
        return;
    }

    appendText(sourcePanelElement, "panelTitle", definition.title);

    const sources = collectSources(definition, events);

    if (sources.length === 0) {
        appendText(sourcePanelElement, "panelEmpty", definition.emptyText);
        return;
    }

    const rows: HTMLButtonElement[] = [];
    rowsByIp.clear();

    for (const stats of sources.slice(0, MAX_ROWS)) {
        const row = document.createElement("button");
        row.type = "button";
        row.className = "failedLogonRow";

        const suspicion = definition.suspicion(stats);
        row.classList.toggle("suspicious", suspicion !== null);
        row.classList.toggle("selected", filterState.selectedIp === stats.ip);

        const head = document.createElement("div");
        head.className = "failedLogonHead";

        const ipText = document.createElement("span");
        ipText.textContent = mask(stats.ip);

        const countText = document.createElement("span");
        countText.textContent = `${stats.count} ${stats.count === 1 ? "event" : "events"}`;

        head.append(ipText, countText);
        row.appendChild(head);

        const details = mask(formatDetails(stats, definition.subjectWord));

        if (details !== "") {
            appendText(row, "failedLogonDetails", details);
        }

        if (suspicion !== null) {
            appendText(row, "suspicionLabel", suspicion);
        }

        row.addEventListener("click", () => {
            const isAlreadySelected = filterState.selectedIp === stats.ip;
            filterState.selectedIp = isAlreadySelected ? null : stats.ip;

            for (const otherRow of rows) {
                otherRow.classList.remove("selected");
            }

            row.classList.toggle("selected", !isAlreadySelected);
            applyFilters();
        });

        rows.push(row);
        rowsByIp.set(stats.ip, row);
        sourcePanelElement.appendChild(row);
    }

    if (sources.length > MAX_ROWS) {
        appendText(sourcePanelElement, "panelEmpty", `+${sources.length - MAX_ROWS} more IPs (use search to find them)`);
    }
}
