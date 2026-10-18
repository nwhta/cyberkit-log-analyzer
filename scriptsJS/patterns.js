import { logEntries, logEntryElements } from "./state.js";
import { onFiltersApplied } from "./filters.js";
import { createEventCard } from "./eventCard.js";
import { UNPARSED_VALUE } from "./parseHelpers.js";
import { normalizeMessage, placeholderLabel, splitTemplate } from "./normalize.js";
import { mask } from "./sanitize.js";
import { formatEventTime } from "./timeZone.js";
import { logViewerElement, miniViewerContainer, patternCountElement, patternSortSelect, patternViewerElement, viewEventsButton, viewPatternsButton } from "./dom.js";
const MAX_PATTERNS_SHOWN = 500;
const EVENTS_PER_PAGE = 50;
let currentParser = null;
let viewMode = "events";
let patternKeys = [];
let templates = [];
export function resetPatterns(parser) {
    currentParser = parser;
    patternKeys = [];
    templates = [];
    patternViewerElement.replaceChildren();
}
function templateOf(event) {
    if (event.facets.parse === UNPARSED_VALUE) {
        return normalizeMessage(event.raw.split("\n", 1)[0]);
    }
    return normalizeMessage(event.title);
}
function ensureKeys() {
    if (patternKeys.length === logEntries.length) {
        return;
    }
    patternKeys = new Array(logEntries.length);
    templates = new Array(logEntries.length);
    for (let i = 0; i < logEntries.length; i++) {
        const event = logEntries[i];
        templates[i] = templateOf(event);
        patternKeys[i] = `${event.badge}\u0000${templates[i]}`;
    }
}
export function collectPatterns() {
    ensureKeys();
    const byKey = new Map();
    for (let i = 0; i < logEntries.length; i++) {
        if (logEntryElements[i].hidden) {
            continue;
        }
        const key = patternKeys[i];
        let pattern = byKey.get(key);
        if (!pattern) {
            pattern = { key, template: templates[i], indices: [] };
            byKey.set(key, pattern);
        }
        pattern.indices.push(i);
    }
    const sortMode = patternSortSelect.value;
    const direction = sortMode === "rare" ? 1 : -1;
    return [...byKey.values()].sort((a, b) => direction * (a.indices.length - b.indices.length) || a.indices[0] - b.indices[0]);
}
export function patternTimes(indices) {
    let first = Number.POSITIVE_INFINITY;
    let last = Number.NEGATIVE_INFINITY;
    for (const index of indices) {
        const timeMs = logEntries[index].timeMs;
        if (!Number.isNaN(timeMs)) {
            first = Math.min(first, timeMs);
            last = Math.max(last, timeMs);
        }
    }
    if (!Number.isFinite(first)) {
        return { first: "", last: "" };
    }
    return { first: formatEventTime(first), last: formatEventTime(last) };
}
function timeRange(indices) {
    const { first, last } = patternTimes(indices);
    return first === last ? first : `${first} → ${last}`;
}
function buildTemplateElement(template) {
    const element = document.createElement("span");
    element.className = "patternTemplate";
    for (const part of splitTemplate(mask(template))) {
        if (!part.isPlaceholder) {
            element.append(part.text);
            continue;
        }
        const placeholder = document.createElement("span");
        placeholder.className = "patternPlaceholder";
        placeholder.textContent = part.text;
        placeholder.title = `Here each event has its own ${placeholderLabel(part.text)}`;
        element.appendChild(placeholder);
    }
    return element;
}
function countText(count) {
    return count === 1 ? "1 event · unique" : `${count} similar events`;
}
export function strongestEvent(indices) {
    for (const index of indices) {
        if (logEntries[index].emphasis) {
            return logEntries[index];
        }
    }
    return logEntries[indices[0]];
}
function appendEventPage(list, pattern, parser) {
    list.querySelector(".patternMore")?.remove();
    const shown = list.childElementCount;
    const next = pattern.indices.slice(shown, shown + EVENTS_PER_PAGE);
    for (const index of next) {
        list.appendChild(createEventCard(logEntries[index], parser));
    }
    const remaining = pattern.indices.length - shown - next.length;
    if (remaining > 0) {
        const more = document.createElement("button");
        more.type = "button";
        more.className = "groupAction patternMore";
        more.textContent = `Show ${Math.min(remaining, EVENTS_PER_PAGE)} more (${remaining} left)`;
        more.addEventListener("click", () => appendEventPage(list, pattern, parser));
        list.appendChild(more);
    }
}
function createPatternCard(pattern, parser) {
    const count = pattern.indices.length;
    const sample = strongestEvent(pattern.indices);
    const card = document.createElement("div");
    card.className = count > 1 ? "patternCard stacked" : "patternCard";
    card.style.setProperty("--event-color", sample.accent);
    if (count > 2) {
        card.classList.add("deepStack");
    }
    const header = document.createElement("div");
    header.className = "eventHeader";
    const countBadge = document.createElement("span");
    countBadge.className = "patternCount";
    countBadge.textContent = `× ${count}`;
    countBadge.title = countText(count);
    const badge = document.createElement("span");
    badge.className = "eventBadge";
    badge.textContent = mask(sample.badge);
    const titleRow = document.createElement("span");
    titleRow.className = "eventTitle";
    titleRow.append(countBadge, buildTemplateElement(pattern.template));
    header.append(titleRow, badge);
    const info = document.createElement("div");
    info.className = "eventMetadata";
    info.textContent = [count === 1 ? "1 event · this message appears only once" : (pattern.template.includes("<") && splitTemplate(pattern.template).some(part => part.isPlaceholder) ? `${count} similar events: same message, only the highlighted values differ` : `${count} identical events`), timeRange(pattern.indices)]
        .filter(text => text !== "")
        .join(" · ");
    card.append(header, info);
    if (sample.summary !== "") {
        const example = document.createElement("div");
        example.className = "eventSummary";
        example.textContent = count > 1 ? `Example: ${mask(sample.summary)}` : mask(sample.summary);
        card.appendChild(example);
    }
    const details = document.createElement("details");
    details.className = "eventDetails";
    const summary = document.createElement("summary");
    summary.textContent = count === 1 ? "Show the event" : `Show all ${count} events`;
    details.appendChild(summary);
    const list = document.createElement("div");
    list.className = "patternEvents";
    details.appendChild(list);
    details.addEventListener("toggle", () => {
        if (details.open && list.childElementCount === 0) {
            appendEventPage(list, pattern, parser);
        }
    });
    card.appendChild(details);
    return card;
}
export function isPatternView() {
    return viewMode === "patterns";
}
export function renderPatterns() {
    if (viewMode !== "patterns" || currentParser === null) {
        return;
    }
    const patterns = collectPatterns();
    const shown = patterns.slice(0, MAX_PATTERNS_SHOWN);
    const fragment = document.createDocumentFragment();
    for (const pattern of shown) {
        fragment.appendChild(createPatternCard(pattern, currentParser));
    }
    if (patterns.length > shown.length) {
        const note = document.createElement("div");
        note.className = "panelEmpty patternNote";
        note.textContent = `Showing ${shown.length} of ${patterns.length} patterns. Use filters or search to narrow the list.`;
        fragment.appendChild(note);
    }
    if (patterns.length === 0) {
        const note = document.createElement("div");
        note.className = "panelEmpty patternNote";
        note.textContent = "No events match the current filters.";
        fragment.appendChild(note);
    }
    patternViewerElement.replaceChildren(fragment);
    patternViewerElement.scrollTop = 0;
    patternCountElement.textContent = patterns.length === 1 ? "1 pattern" : `${patterns.length} patterns`;
}
function setViewMode(mode) {
    viewMode = mode;
    const isPatterns = mode === "patterns";
    logViewerElement.hidden = isPatterns;
    miniViewerContainer.hidden = isPatterns;
    patternViewerElement.hidden = !isPatterns;
    patternSortSelect.hidden = !isPatterns;
    patternCountElement.hidden = !isPatterns;
    viewEventsButton.setAttribute("aria-pressed", String(!isPatterns));
    viewPatternsButton.setAttribute("aria-pressed", String(isPatterns));
    renderPatterns();
}
viewEventsButton.addEventListener("click", () => setViewMode("events"));
viewPatternsButton.addEventListener("click", () => setViewMode("patterns"));
patternSortSelect.addEventListener("change", renderPatterns);
onFiltersApplied(renderPatterns);
