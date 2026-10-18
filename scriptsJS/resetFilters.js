import { applyFilters, resetFacetFilters } from "./filters.js";
import { resetTimeFilter } from "./timeFilter.js";
import { clearSourceSelection } from "./sourcePanel.js";
import { resetFiltersButton } from "./dom.js";
resetFiltersButton.addEventListener("click", () => {
    resetFacetFilters();
    resetTimeFilter();
    clearSourceSelection();
    applyFilters();
});
