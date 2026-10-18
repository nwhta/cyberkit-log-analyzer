import type { EventDetails, LogParser, ParsedEvent } from "./parserTypes.js";
import { formatUtc } from "./parseHelpers.js";
import { mask } from "./sanitize.js";
import { formatEventTime } from "./timeZone.js";

export function eventMetadata(event: ParsedEvent): string[] {
    const utcText = formatUtc(event.timeMs);
    return event.metadata.map(item => mask(item === utcText ? formatEventTime(event.timeMs) : item));
}

export function createEventCard(event: ParsedEvent, parser: LogParser): HTMLDivElement {
    const card = document.createElement("div");
    card.className = "eventRow";
    card.style.setProperty("--event-color", event.accent);

    const header = document.createElement("div");
    header.className = "eventHeader";

    const title = document.createElement("span");
    title.className = "eventTitle";
    title.textContent = mask(event.title);

    const badge = document.createElement("span");
    badge.className = "eventBadge";
    badge.textContent = mask(event.badge);

    header.append(title, badge);
    card.appendChild(header);

    if (event.summary !== "") {
        const summary = document.createElement("div");
        summary.className = "eventSummary";
        summary.textContent = mask(event.summary);
        card.appendChild(summary);
    }

    const metadata = document.createElement("div");
    metadata.className = "eventMetadata";
    metadata.textContent = eventMetadata(event).join(" · ");

    const details = createLazyDetails("Details", "eventDetails", () => buildDetailsContent(event.details()));
    const raw = createLazyDetails(parser.rawLabel, "eventRaw", () => buildRawContent(event, parser));

    card.append(metadata, details, raw);
    return card;
}

function createLazyDetails(label: string, className: string, buildContent: () => HTMLElement): HTMLDetailsElement {
    const details = document.createElement("details");
    details.className = className;

    const summary = document.createElement("summary");
    summary.textContent = label;
    details.appendChild(summary);

    let built = false;

    details.addEventListener("toggle", () => {
        if (details.open && !built) {
            details.appendChild(buildContent());
            built = true;
        }
    });

    return details;
}

function buildDetailsContent(details: EventDetails): HTMLElement {
    const container = document.createElement("div");
    const table = document.createElement("table");
    table.className = "fieldTable";

    for (const field of details.fields) {
        const row = table.insertRow();

        if (field.risky) {
            row.className = "riskyRow";
        }

        row.insertCell().textContent = field.name;
        row.insertCell().textContent = field.value === "" ? "—" : mask(field.value);
        row.insertCell().textContent = mask(field.meaning ?? "");
    }

    container.appendChild(table);

    for (const section of details.sections ?? []) {
        const title = document.createElement("div");
        title.className = "detailsSubtitle";
        title.textContent = section.title;

        const text = document.createElement("pre");
        text.className = "windowsMessage";
        text.textContent = mask(section.text);

        container.append(title, text);
    }

    return container;
}

function buildRawContent(event: ParsedEvent, parser: LogParser): HTMLElement {
    const pre = document.createElement("pre");
    pre.className = "rawXml";
    pre.textContent = mask(parser.formatRaw ? parser.formatRaw(event.raw) : event.raw);
    return pre;
}
