import type { ParsedEvent } from "./parserTypes.js";
import { miniViewerCanvas } from "./dom.js";
import { mask } from "./sanitize.js";
import { formatEventTime } from "./timeZone.js";

let currentEntries: ParsedEvent[] = [];
let currentLogElements: HTMLDivElement[] = [];

export function drawMinimap(data: ParsedEvent[], elements: HTMLDivElement[]): void {
    currentEntries = data;
    currentLogElements = elements;
    render();
}

function render(): void {
    const canvasContext = miniViewerCanvas.getContext("2d");
    const container = miniViewerCanvas.parentElement;

    if (!canvasContext || !container) {
        return;
    }

    const cssHeight = container.clientHeight;
    const total = currentEntries.length;
    const ratio = window.devicePixelRatio || 1;

    miniViewerCanvas.width = Math.round(60 * ratio);
    miniViewerCanvas.height = Math.max(1, Math.round(cssHeight * ratio));
    miniViewerCanvas.style.height = `${cssHeight}px`;

    canvasContext.clearRect(0, 0, miniViewerCanvas.width, miniViewerCanvas.height);

    if (total === 0) {
        return;
    }

    const height = miniViewerCanvas.height;
    const width = miniViewerCanvas.width;

    for (const pass of ["normal", "emphasis"] as const) {
        for (let i = 0; i < total; i++) {
            const entry = currentEntries[i];

            if ((pass === "emphasis") !== entry.emphasis) {
                continue;
            }

            const top = Math.floor((i * height) / total);
            const bottom = Math.floor(((i + 1) * height) / total);

            canvasContext.fillStyle = entry.accent;
            canvasContext.fillRect(0, top, width, Math.max(1, bottom - top));
        }
    }
}

function rowIndexAt(offsetY: number): number | null {
    const total = currentEntries.length;
    const cssHeight = miniViewerCanvas.clientHeight;

    if (total === 0 || cssHeight === 0) {
        return null;
    }

    return Math.max(0, Math.min(total - 1, Math.floor((offsetY / cssHeight) * total)));
}

const tooltip = document.createElement("div");
tooltip.className = "minimapTooltip";
tooltip.hidden = true;
document.body.appendChild(tooltip);

function showTooltip(event: MouseEvent): void {
    const index = rowIndexAt(event.offsetY);

    if (index === null) {
        tooltip.hidden = true;
        return;
    }

    const entry = currentEntries[index];
    const time = document.createElement("div");
    time.className = "minimapTooltipTime";
    time.textContent = formatEventTime(entry.timeMs);

    const title = document.createElement("div");
    title.className = "minimapTooltipTitle";
    title.textContent = mask(entry.title);
    title.style.borderLeftColor = entry.accent;

    tooltip.replaceChildren(time, title);

    if (currentLogElements[index]?.hidden) {
        const note = document.createElement("div");
        note.className = "minimapTooltipNote";
        note.textContent = "hidden by filters";
        tooltip.appendChild(note);
    }

    tooltip.hidden = false;

    const box = tooltip.getBoundingClientRect();
    const top = Math.min(window.innerHeight - box.height - 8, Math.max(8, event.clientY - box.height / 2));
    tooltip.style.top = `${top}px`;
    tooltip.style.left = `${Math.max(8, event.clientX - box.width - 14)}px`;
}

miniViewerCanvas.addEventListener("mousemove", showTooltip);
miniViewerCanvas.addEventListener("mouseleave", () => {
    tooltip.hidden = true;
});

miniViewerCanvas.addEventListener("click", (event: MouseEvent) => {
    const clickedRowIndex = rowIndexAt(event.offsetY);

    if (clickedRowIndex === null) {
        return;
    }

    const targetElement = currentLogElements[clickedRowIndex];

    if (!targetElement) {
        return;
    }

    targetElement.scrollIntoView({ behavior: "smooth", block: "center" });
    targetElement.classList.add("highlightedLogEntry");

    setTimeout(() => {
        targetElement.classList.remove("highlightedLogEntry");
    }, 1500);
});

let resizeScheduled = false;
const container = miniViewerCanvas.parentElement;

if (container) {
    new ResizeObserver(() => {
        if (resizeScheduled) {
            return;
        }

        resizeScheduled = true;

        requestAnimationFrame(() => {
            resizeScheduled = false;
            render();
        });
    }).observe(container);
}

miniViewerCanvas.style.cursor = "pointer";
