import { filterState } from "./filterState.js";
import { applyFilters } from "./filters.js";
import { timeFromInput, timeLocalButton, timeNoteElement, timeResetButton, timeSwitchElement, timeToInput, timeTitleElement, timeUtcButton } from "./dom.js";
import { fromInputValue, getTimeMode, isAsWritten, localZoneName, onTimeModeChange, setTimeMode, setTimeParser, toInputValue, zoneLabel } from "./timeZone.js";
let firstMs = Number.NaN;
let lastMs = Number.NaN;
let noteText = "";
function renderTimeControls() {
    const asWritten = isAsWritten();
    const isLocal = getTimeMode() === "local";
    timeTitleElement.textContent = asWritten ? "Time range (as written)" : `Time range (${isLocal ? "local" : "UTC"})`;
    timeTitleElement.title = `Times are shown in ${zoneLabel()}`;
    timeSwitchElement.hidden = asWritten;
    timeLocalButton.setAttribute("aria-pressed", String(isLocal));
    timeUtcButton.setAttribute("aria-pressed", String(!isLocal));
    const notes = [noteText];
    if (asWritten) {
        notes.push("This format has no time zone, so local/UTC conversion is off.");
    }
    else if (isLocal) {
        notes.push(`Shown in your local time: ${localZoneName()}.`);
    }
    timeNoteElement.textContent = notes.filter(text => text !== "").join(" ");
    if (Number.isNaN(firstMs)) {
        for (const input of [timeFromInput, timeToInput]) {
            input.value = "";
            input.min = "";
            input.max = "";
        }
        return;
    }
    for (const input of [timeFromInput, timeToInput]) {
        input.min = toInputValue(firstMs);
        input.max = toInputValue(lastMs);
    }
    timeFromInput.value = toInputValue(filterState.timeFromMs ?? firstMs);
    timeToInput.value = toInputValue(filterState.timeToMs ?? lastMs);
}
export function buildTimeFilter(events, parser) {
    let first = Number.POSITIVE_INFINITY;
    let last = Number.NEGATIVE_INFINITY;
    let missing = 0;
    for (const event of events) {
        if (Number.isNaN(event.timeMs)) {
            missing++;
            continue;
        }
        first = Math.min(first, event.timeMs);
        last = Math.max(last, event.timeMs);
    }
    setTimeParser(parser);
    firstMs = Number.isFinite(first) ? first : Number.NaN;
    lastMs = Number.isFinite(last) ? last : Number.NaN;
    noteText = missing > 0 ? `${parser.timeNote} ${missing} event(s) have no time and are always shown.` : parser.timeNote;
    renderTimeControls();
}
export function resetTimeFilter() {
    filterState.timeFromMs = null;
    filterState.timeToMs = null;
    renderTimeControls();
}
function onTimeInputChange() {
    filterState.timeFromMs = fromInputValue(timeFromInput.value, false);
    filterState.timeToMs = fromInputValue(timeToInput.value, true);
    applyFilters();
}
timeFromInput.addEventListener("change", onTimeInputChange);
timeToInput.addEventListener("change", onTimeInputChange);
timeResetButton.addEventListener("click", () => {
    resetTimeFilter();
    applyFilters();
});
timeLocalButton.addEventListener("click", () => setTimeMode("local"));
timeUtcButton.addEventListener("click", () => setTimeMode("utc"));
onTimeModeChange(renderTimeControls);
renderTimeControls();
