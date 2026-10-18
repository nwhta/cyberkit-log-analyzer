import { currentLog, logEntries, logEntryElements } from "./state.js";
import { filterState } from "./filterState.js";
import { exportCsvButton, exportPdfButton, printReportElement, searchInput, timeFromInput, timeToInput } from "./dom.js";
import { eventMetadata } from "./eventCard.js";
import { isSanitizing, mask } from "./sanitize.js";
import { formatEventTime, zoneLabel } from "./timeZone.js";
import { collectPatterns, isPatternView, patternTimes, strongestEvent } from "./patterns.js";
import { collectSources, formatDetails } from "./sourcePanel.js";
const MAX_PDF_EVENTS = 1000;
const MAX_PDF_PATTERNS = 30;
const MAX_PDF_SOURCES = 15;
const SEVERITY_ORDER = ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "UNKNOWN"];
function visibleEvents() {
    return logEntries.filter((_, index) => !logEntryElements[index].hidden);
}
function csvCell(value) {
    const safe = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
    return /[",\n\r]/.test(safe) ? `"${safe.replace(/"/g, "\"\"")}"` : safe;
}
function csvRow(cells) {
    return cells.map(csvCell).join(",");
}
function downloadFile(content, fileName, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function baseFileName() {
    if (currentLog === null || isSanitizing()) {
        return "log-analysis";
    }
    const name = currentLog.fileName.replace(/\.[^.]+$/, "").replace(/[^\w.-]+/g, "_");
    return name === "" ? "log-analysis" : name;
}
function eventsCsv(events) {
    const facets = currentLog?.facets ?? [];
    const header = ["Line", `Time, ${zoneLabel()}`, "Severity", "Result", "Title", "Summary", "Info", "IP", ...facets.map(facet => facet.title), "Raw"];
    const rows = [csvRow(header)];
    for (const event of events) {
        rows.push(csvRow([
            String(event.lineNumber),
            formatEventTime(event.timeMs),
            event.severity,
            mask(event.badge),
            mask(event.title),
            mask(event.summary),
            eventMetadata(event).join(" · "),
            mask(event.ip ?? ""),
            ...facets.map(facet => mask(event.facets[facet.key] ?? "")),
            mask(event.raw),
        ]));
    }
    return rows.join("\r\n");
}
function patternsCsv() {
    const rows = [csvRow(["Count", "Pattern", "Result", `First seen, ${zoneLabel()}`, "Last seen", "Example"])];
    for (const pattern of collectPatterns()) {
        const sample = strongestEvent(pattern.indices);
        const { first, last } = patternTimes(pattern.indices);
        rows.push(csvRow([String(pattern.indices.length), mask(pattern.template), mask(sample.badge), first, last, mask(sample.summary)]));
    }
    return rows.join("\r\n");
}
function exportCsv() {
    if (currentLog === null) {
        alert("Analyze a log first, then export the result.");
        return;
    }
    const isPatterns = isPatternView();
    const content = isPatterns ? patternsCsv() : eventsCsv(visibleEvents());
    const fileName = `${baseFileName()}-${isPatterns ? "patterns" : "events"}.csv`;
    downloadFile("﻿" + content, fileName, "text/csv;charset=utf-8");
}
function element(tag, text = "", className = "") {
    const node = document.createElement(tag);
    node.textContent = text;
    if (className !== "") {
        node.className = className;
    }
    return node;
}
function table(headers, rows) {
    const result = element("table", "", "reportTable");
    const headRow = result.createTHead().insertRow();
    for (const header of headers) {
        headRow.appendChild(element("th", header));
    }
    const body = result.createTBody();
    for (const row of rows) {
        const tableRow = body.insertRow();
        for (const cell of row) {
            tableRow.insertCell().textContent = cell;
        }
    }
    return result;
}
function activeFilterLines() {
    const lines = [];
    const facets = currentLog?.facets ?? [];
    if (searchInput.value.trim() !== "") {
        lines.push(`Search: "${mask(searchInput.value.trim())}"`);
    }
    if (filterState.timeFromMs !== null || filterState.timeToMs !== null) {
        lines.push(`Time: ${timeFromInput.value.replace("T", " ")} → ${timeToInput.value.replace("T", " ")}`);
    }
    for (const [key, values] of filterState.hiddenFacetValues) {
        if (values.size > 0) {
            const title = facets.find(facet => facet.key === key)?.title ?? key;
            lines.push(`${title} hidden: ${[...values].map(mask).join(", ")}`);
        }
    }
    if (filterState.selectedIp !== null) {
        lines.push(`Only IP: ${mask(filterState.selectedIp)}`);
    }
    if (filterState.hideNoise && currentLog?.parser.noise !== undefined) {
        lines.push(`${currentLog.parser.noise.label} hidden`);
    }
    return lines;
}
function severitySummary(events) {
    const counts = new Map();
    for (const event of events) {
        counts.set(event.severity, (counts.get(event.severity) ?? 0) + 1);
    }
    return SEVERITY_ORDER.filter(severity => counts.has(severity)).map(severity => `${severity}: ${counts.get(severity)}`).join(" · ");
}
function buildReport() {
    if (currentLog === null) {
        return;
    }
    const events = visibleEvents();
    const report = [];
    const { parser } = currentLog;
    report.push(element("h1", "Log Analyzer report"));
    const facts = [
        `File: ${isSanitizing() ? "(hidden)" : currentLog.fileName}${currentLog.isDemo ? " (demo)" : ""}`,
        `Format: ${parser.name}`,
        `Generated: ${formatEventTime(Date.now())}`,
        `Times: ${zoneLabel()}`,
        `Events in report: ${events.length} of ${logEntries.length}`,
        `Severity: ${severitySummary(events)}`,
    ];
    if (isSanitizing()) {
        facts.push("Sensitive data hidden: IPs, users, hosts, domains, emails, SIDs, secrets were replaced with [TYPE-n] labels. The same value always gets the same label.");
    }
    const factList = element("ul", "", "reportFacts");
    for (const fact of facts) {
        factList.appendChild(element("li", fact));
    }
    report.push(factList);
    const filters = activeFilterLines();
    if (filters.length > 0) {
        report.push(element("h2", "Active filters"));
        const filterList = element("ul", "", "reportFacts");
        for (const line of filters) {
            filterList.appendChild(element("li", line));
        }
        report.push(filterList);
    }
    if (parser.sourcePanel !== undefined) {
        const sources = collectSources(parser.sourcePanel, events).slice(0, MAX_PDF_SOURCES);
        if (sources.length > 0) {
            report.push(element("h2", parser.sourcePanel.title));
            report.push(table(["IP", "Events", "Details", "Warning"], sources.map(stats => [
                mask(stats.ip),
                String(stats.count),
                mask(formatDetails(stats, parser.sourcePanel.subjectWord)),
                parser.sourcePanel.suspicion(stats) ?? "",
            ])));
        }
    }
    const patterns = collectPatterns().sort((a, b) => b.indices.length - a.indices.length).slice(0, MAX_PDF_PATTERNS);
    if (patterns.length > 0) {
        report.push(element("h2", "Most frequent message patterns"));
        report.push(table(["Count", "Pattern", "Result", "First → last"], patterns.map(pattern => {
            const { first, last } = patternTimes(pattern.indices);
            return [String(pattern.indices.length), mask(pattern.template), mask(strongestEvent(pattern.indices).badge), first === last ? first : `${first} → ${last}`];
        })));
    }
    report.push(element("h2", "Events"));
    if (events.length > MAX_PDF_EVENTS) {
        report.push(element("p", `Only the first ${MAX_PDF_EVENTS} of ${events.length} events are listed. Use Export CSV for the full list.`, "reportNote"));
    }
    report.push(table(["Time", "Result", "Event", "Summary"], events.slice(0, MAX_PDF_EVENTS).map(event => [
        formatEventTime(event.timeMs),
        mask(event.badge),
        mask(event.title),
        mask(event.summary),
    ])));
    printReportElement.replaceChildren(...report);
}
function exportPdf() {
    if (currentLog === null) {
        alert("Analyze a log first, then export the result.");
        return;
    }
    buildReport();
    window.print();
}
window.addEventListener("afterprint", () => {
    printReportElement.replaceChildren();
});
exportCsvButton.addEventListener("click", exportCsv);
exportPdfButton.addEventListener("click", exportPdf);
