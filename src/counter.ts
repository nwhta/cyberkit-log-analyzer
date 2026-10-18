import { logCounterElement } from "./dom.js";

export function updateLogCounter(visibleCount: number, totalCount: number): void {
  logCounterElement.textContent = `${visibleCount} of ${totalCount}`;
}
