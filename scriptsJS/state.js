export const logEntries = [];
export const logEntryElements = [];
export let currentLog = null;
export function setCurrentLog(log) {
    currentLog = log;
}
export function clearState() {
    logEntries.length = 0;
    logEntryElements.length = 0;
}
