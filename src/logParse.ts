import type { FacetDefinition, LogParser, ParsedEvent } from "./parserTypes.js";
import { clearState, currentLog, logEntries, logEntryElements, setCurrentLog } from "./state.js";
import { drawMinimap } from "./miniViewer.js";
import { applyFilters, buildFilters, relabelFilterChips } from "./filters.js";
import { buildTimeFilter } from "./timeFilter.js";
import { buildSourcePanel } from "./sourcePanel.js";
import { analyzeButton, demoBadge, dropZoneElement, fileNameElement, formatNameElement, logInput, logViewerElement, sanitizeToggle } from "./dom.js";
import { detectParser, supportedFormatNames } from "./parserRegistry.js";
import { createEventCard } from "./eventCard.js";
import { UNPARSED_VALUE } from "./parseHelpers.js";
import { SEVERITY_COLORS } from "./severity.js";
import { setCoverage } from "./coveragePopover.js";
import { setDemoLoader } from "./demo.js";
import "./formatsInfo.js";
import "./whatsNewBadge.js";
import { reportUnknownFormat, reportUsage } from "./usage.js";
import { evtxToXml, isEvtx } from "./evtx.js";
import { showQuickFeedback } from "./quickFeedback.js";
import { resetPatterns } from "./patterns.js";
import { onSanitizeChange, prepareSanitizer, resetSanitizer, setSanitizing } from "./sanitize.js";
import { onTimeModeChange, setTimeParser } from "./timeZone.js";
import "./exportReport.js";
import "./resetFilters.js";

const MAX_FILE_SIZE_MB = 200;
const MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024;

const PARSE_STATUS_FACET: FacetDefinition = {
    key: "parse",
    title: "Parse status",
    order: [UNPARSED_VALUE, "Parsed"],
    color: value => value === UNPARSED_VALUE ? SEVERITY_COLORS.WARNING : "#5dc98b",
};

function markParseStatus(events: ParsedEvent[]): number {
    let unparsed = 0;

    for (const event of events) {
        if (event.facets.parse === UNPARSED_VALUE) {
            unparsed++;
        }
    }

    if (unparsed > 0) {
        for (const event of events) {
            event.facets.parse ??= "Parsed";
        }
    }

    return unparsed;
}

function showFormat(parser: LogParser, confidence: number, total: number, unparsed: number, isDemo: boolean): void {
    const details = [`${total} events`];

    if (unparsed > 0) {
        details.push(`${unparsed} not recognized`);
    }

    details.push(`detected automatically, confidence ${Math.round(confidence * 100)}%`);

    if (isDemo) {
        details.push("demo log");
    }

    formatNameElement.textContent = parser.name;
    formatNameElement.title = `${parser.name}\n${details.join(" · ")}`;
    demoBadge.hidden = !isDemo;
    setCoverage(parser);
}

function showLog(parser: LogParser, confidence: number, content: string, isDemo: boolean, fileName: string): void {
    const events = parser.parse(content);

    if (events.length === 0) {
        alert(`The file looks like "${parser.name}" but contains no events.`);
        return;
    }

    const unparsed = markParseStatus(events);
    const facets = unparsed > 0 ? [PARSE_STATUS_FACET, ...parser.facets] : parser.facets;

    setCurrentLog({ parser, facets, fileName, isDemo });
    setTimeParser(parser);
    resetSanitizer();
    prepareSanitizer(events);
    renderEntries(parser, events, isDemo);
    resetPatterns(parser);
    showFormat(parser, confidence, events.length, unparsed, isDemo);

    buildFilters(parser, facets, events);
    buildTimeFilter(events, parser);
    buildSourcePanel(parser.sourcePanel, events);
    applyFilters();
    drawMinimap(logEntries, logEntryElements);
    reportUsage(isDemo ? "demo" : "analyze", parser.id);
    showQuickFeedback();
}

async function readLogFile(file: File): Promise<string> {
    const head = new Uint8Array(await file.slice(0, 8).arrayBuffer());

    if (!isEvtx(head)) {
        return file.text();
    }

    analyzeButton.textContent = "Reading .evtx…";
    await new Promise(resolve => setTimeout(resolve, 0));

    const result = evtxToXml(await file.arrayBuffer());

    if (result.records === 0) {
        throw new Error("No events could be read from this .evtx file. It may be damaged.");
    }

    return result.xml;
}

async function analyzeLog(): Promise<void> {
    const logFile = logInput.files?.[0];

    if (!logFile) {
        alert("Select a log file, or press Demo to try a sample log.");
        return;
    }

    if (logFile.size > MAX_FILE_SIZE_BYTES) {
        alert(`This file is too large to analyze in the browser (max ${MAX_FILE_SIZE_MB} MB).\nTip: export or cut a smaller time range and try again.`);
        return;
    }

    analyzeButton.disabled = true;
    analyzeButton.textContent = "Analyzing…";

    try {
        const content = await readLogFile(logFile);
        const detection = detectParser(content);

        if (detection === null) {
            reportUnknownFormat(logFile.name);
            alert("Could not recognize this log format.\n\nSupported formats:\n• " + supportedFormatNames().join("\n• "));
            return;
        }

        showLog(detection.parser, detection.confidence, content, false, logFile.name);
    } catch (error) {
        alert(error instanceof Error ? error.message : "Unable to analyze the file.");
    } finally {
        analyzeButton.disabled = false;
        analyzeButton.textContent = "Analyze";
    }
}

function analyzeDemo(chosen: LogParser, content: string): void {
    const detection = detectParser(content) ?? { parser: chosen, confidence: 1 };

    logInput.value = "";
    dropZoneElement.classList.remove("hasFile");
    fileNameElement.textContent = `Demo: ${chosen.demoFile?.split("/").pop() ?? chosen.name}`;
    fileNameElement.title = "Sample data made for this demo, not a real log";

    try {
        showLog(detection.parser, detection.confidence, content, true, chosen.demoFile?.split("/").pop() ?? chosen.name);
    } catch (error) {
        alert(error instanceof Error ? error.message : "Unable to analyze the demo log.");
    }
}

function createDemoBanner(parser: LogParser): HTMLDivElement {
    const banner = document.createElement("div");
    banner.className = "demoBanner";

    const title = document.createElement("strong");
    title.textContent = `Demo log · ${parser.name}`;

    const text = document.createElement("span");
    text.textContent = "Sample data made for this demo, with normal activity and typical attacks mixed in. It was analyzed in your browser, like your own files would be. Choose your own log file to analyze it.";

    banner.append(title, text);
    return banner;
}

function renderEntries(parser: LogParser, events: ParsedEvent[], isDemo: boolean): void {
    clearState();
    logViewerElement.replaceChildren();

    const fragment = document.createDocumentFragment();

    if (isDemo) {
        fragment.appendChild(createDemoBanner(parser));
    }

    for (const event of events) {
        const element = createEventCard(event, parser);

        logEntries.push(event);
        logEntryElements.push(element);
        fragment.appendChild(element);
    }

    logViewerElement.appendChild(fragment);
}

function refreshView(): void {
    if (currentLog === null) {
        return;
    }

    const fragment = document.createDocumentFragment();
    const banner = logViewerElement.querySelector(".demoBanner");

    if (banner !== null) {
        fragment.appendChild(banner);
    }

    for (let i = 0; i < logEntries.length; i++) {
        const card = createEventCard(logEntries[i], currentLog.parser);
        card.hidden = logEntryElements[i].hidden;
        logEntryElements[i] = card;
        fragment.appendChild(card);
    }

    logViewerElement.replaceChildren(fragment);
    relabelFilterChips();
    buildSourcePanel(currentLog.parser.sourcePanel, logEntries);
    applyFilters();
}

sanitizeToggle.checked = false;
sanitizeToggle.addEventListener("change", () => {
    sanitizeToggle.disabled = true;

    requestAnimationFrame(() => {
        setSanitizing(sanitizeToggle.checked, logEntries);
        sanitizeToggle.disabled = false;
    });
});

onSanitizeChange(refreshView);
onTimeModeChange(refreshView);

analyzeButton.addEventListener("click", analyzeLog);
logInput.addEventListener("change", () => {
    demoBadge.hidden = true;
});
setDemoLoader(analyzeDemo);
