export const filterState = {
    searchText: "",
    hiddenFacetValues: new Map(),
    selectedIp: null,
    hideNoise: true,
    timeFromMs: null,
    timeToMs: null,
};
export function resetFilterState() {
    filterState.searchText = "";
    filterState.hiddenFacetValues.clear();
    filterState.selectedIp = null;
    filterState.hideNoise = true;
    filterState.timeFromMs = null;
    filterState.timeToMs = null;
}
export function setFacetValueHidden(key, value, hidden) {
    let hiddenValues = filterState.hiddenFacetValues.get(key);
    if (!hiddenValues) {
        hiddenValues = new Set();
        filterState.hiddenFacetValues.set(key, hiddenValues);
    }
    if (hidden) {
        hiddenValues.add(value);
    }
    else {
        hiddenValues.delete(value);
    }
}
