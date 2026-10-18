import { logCounterElement } from "./dom.js";
export function updateLogCounter(visibleCount, totalCount) {
    logCounterElement.textContent = `${visibleCount} of ${totalCount}`;
}
