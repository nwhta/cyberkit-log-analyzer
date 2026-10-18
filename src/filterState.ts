export const filterState = {
    searchText: "",
    hiddenFacetValues: new Map<string, Set<string>>(),
    selectedIp: null as string | null,
    hideNoise: true,
    timeFromMs: null as number | null,
    timeToMs: null as number | null,
};

export function resetFilterState(): void {
    filterState.searchText = "";
    filterState.hiddenFacetValues.clear();
    filterState.selectedIp = null;
    filterState.hideNoise = true;
    filterState.timeFromMs = null;
    filterState.timeToMs = null;
}

export function setFacetValueHidden(key: string, value: string, hidden: boolean): void {
    let hiddenValues = filterState.hiddenFacetValues.get(key);

    if (!hiddenValues) {
        hiddenValues = new Set();
        filterState.hiddenFacetValues.set(key, hiddenValues);
    }

    if (hidden) {
        hiddenValues.add(value);
    } else {
        hiddenValues.delete(value);
    }
}
