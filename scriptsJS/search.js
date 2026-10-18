import { searchInput } from "./dom.js";
import { setSearchText } from "./filters.js";
searchInput.addEventListener("input", () => {
    setSearchText(searchInput.value);
});
