import { logEntries, logEntryElements } from "./state.js";
import { filterState, resetFilterState, setFacetValueHidden } from "./filterState.js";
import { facetFiltersElement, resetFiltersButton, searchInput } from "./dom.js";
import { mask, unmaskQuery } from "./sanitize.js";
import { updateLogCounter } from "./counter.js";
const DEFAULT_CHIP_COLOR = "#619aff";
const NOISE_CHIP_COLOR = "#87909e";
let searchCache = [];
const filterListeners = [];
export function onFiltersApplied(listener) {
    filterListeners.push(listener);
}
function searchTextOf(index) {
    if (searchCache[index] === undefined) {
        const event = logEntries[index];
        searchCache[index] = `${event.raw}\n${event.title}\n${event.summary}`.toLowerCase();
    }
    return searchCache[index];
}
function isVisible(event, index) {
    if (filterState.hideNoise && event.noise) {
        return false;
    }
    for (const [key, hiddenValues] of filterState.hiddenFacetValues) {
        const value = event.facets[key];
        if (value !== undefined && hiddenValues.has(value)) {
            return false;
        }
    }
    if (filterState.selectedIp !== null && event.ip !== filterState.selectedIp) {
        return false;
    }
    if (filterState.timeFromMs !== null && event.timeMs < filterState.timeFromMs) {
        return false;
    }
    if (filterState.timeToMs !== null && event.timeMs > filterState.timeToMs) {
        return false;
    }
    if (filterState.searchText !== "") {
        return searchTextOf(index).includes(filterState.searchText);
    }
    return true;
}
export function applyFilters() {
    let visibleCount = 0;
    for (let i = 0; i < logEntries.length; i++) {
        const visible = isVisible(logEntries[i], i);
        logEntryElements[i].hidden = !visible;
        if (visible) {
            visibleCount++;
        }
    }
    updateLogCounter(visibleCount, logEntries.length);
    updateGroupActions();
    resetFiltersButton.hidden = !hasActiveFilters();
    for (const listener of filterListeners) {
        listener();
    }
}
export function setSearchText(text) {
    filterState.searchText = unmaskQuery(text.trim()).toLowerCase();
    applyFilters();
}
const groups = [];
function createFilterChip(label, count, color, onChange) {
    const element = document.createElement("button");
    element.type = "button";
    element.className = "filterChip";
    element.style.setProperty("--chip-color", color);
    const chip = {
        element,
        label,
        count,
        isHidden: () => element.classList.contains("filterHidden"),
        setHidden: hidden => {
            element.classList.toggle("filterHidden", hidden);
            onChange(hidden);
        },
        render: () => {
            element.textContent = `${mask(label)} (${count})`;
        },
    };
    chip.render();
    return chip;
}
function updateGroupActions() {
    for (const group of groups) {
        if (group.showAllButton !== null) {
            group.showAllButton.hidden = !group.chips.some(chip => chip.isHidden());
        }
    }
}
function createGroup(title) {
    const header = document.createElement("div");
    header.className = "groupHeader";
    const titleElement = document.createElement("span");
    titleElement.className = "panelTitle";
    titleElement.textContent = title;
    const actions = document.createElement("span");
    actions.className = "groupActions";
    header.append(titleElement, actions);
    const chips = document.createElement("div");
    chips.className = "chipPanel";
    facetFiltersElement.append(header, chips);
    return { actions, chips };
}
function addFacetChipBehaviour(group) {
    for (const chip of group.chips) {
        chip.element.title = group.chips.length < 2 ? "Click: hide / show" : "Click: hide / show · Double-click: show only this";
        chip.element.addEventListener("click", () => {
            chip.setHidden(!chip.isHidden());
            applyFilters();
        });
        if (group.chips.length < 2) {
            continue;
        }
        chip.element.addEventListener("dblclick", () => {
            for (const other of group.chips) {
                other.setHidden(other !== chip);
            }
            applyFilters();
        });
    }
}
function createShowAllButton(container, group) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "groupAction";
    button.textContent = "Show all";
    button.hidden = true;
    button.addEventListener("click", () => {
        for (const chip of group.chips) {
            chip.setHidden(false);
        }
        applyFilters();
    });
    container.appendChild(button);
    return button;
}
export function relabelFilterChips() {
    for (const group of groups) {
        for (const chip of group.chips) {
            chip.render();
        }
    }
}
export function resetFacetFilters() {
    for (const group of groups) {
        for (const chip of group.chips) {
            chip.setHidden(group.isNoise);
        }
    }
    filterState.searchText = "";
    searchInput.value = "";
}
export function hasActiveFilters() {
    const noiseShown = groups.some(group => group.isNoise && group.chips.some(chip => !chip.isHidden()));
    const facetHidden = [...filterState.hiddenFacetValues.values()].some(values => values.size > 0);
    return noiseShown || facetHidden || filterState.searchText !== "" || filterState.selectedIp !== null
        || filterState.timeFromMs !== null || filterState.timeToMs !== null;
}
function countFacet(events, key) {
    const counts = new Map();
    for (const event of events) {
        const value = event.facets[key];
        if (value !== undefined) {
            counts.set(value, (counts.get(value) ?? 0) + 1);
        }
    }
    return counts;
}
function sortFacetValues(counts, order) {
    const entries = [...counts];
    if (order === undefined) {
        return entries.sort((a, b) => b[1] - a[1]);
    }
    const rank = (value) => {
        const index = order.indexOf(value);
        return index < 0 ? order.length : index;
    };
    return entries.sort((a, b) => rank(a[0]) - rank(b[0]) || b[1] - a[1]);
}
function buildFacetGroup(facet, events) {
    const counts = countFacet(events, facet.key);
    if (counts.size === 0) {
        return;
    }
    const { actions, chips: chipContainer } = createGroup(facet.title);
    const group = { chips: [], showAllButton: null, isNoise: false };
    for (const [value, count] of sortFacetValues(counts, facet.order)) {
        const color = facet.color?.(value) ?? DEFAULT_CHIP_COLOR;
        const chip = createFilterChip(value, count, color, isHidden => setFacetValueHidden(facet.key, value, isHidden));
        group.chips.push(chip);
        chipContainer.appendChild(chip.element);
    }
    if (group.chips.length > 1) {
        group.showAllButton = createShowAllButton(actions, group);
    }
    addFacetChipBehaviour(group);
    groups.push(group);
}
function buildNoiseGroup(parser, events) {
    const noiseCount = events.filter(event => event.noise).length;
    if (parser.noise === undefined || noiseCount === 0) {
        filterState.hideNoise = false;
        return;
    }
    const { chips } = createGroup("Noise");
    const chip = createFilterChip(parser.noise.label, noiseCount, NOISE_CHIP_COLOR, isHidden => {
        filterState.hideNoise = isHidden;
    });
    chip.element.classList.add("filterHidden");
    chip.element.title = parser.noise.hint;
    chip.element.addEventListener("click", () => {
        chip.setHidden(!chip.isHidden());
        applyFilters();
    });
    chips.appendChild(chip.element);
    groups.push({ chips: [chip], showAllButton: null, isNoise: true });
}
export function buildFilters(parser, facets, events) {
    resetFilterState();
    searchCache = [];
    searchInput.value = "";
    searchInput.placeholder = parser.searchHint;
    facetFiltersElement.replaceChildren();
    groups.length = 0;
    buildNoiseGroup(parser, events);
    for (const facet of facets) {
        buildFacetGroup(facet, events);
    }
}
