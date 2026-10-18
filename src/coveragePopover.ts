import type { LogParser } from "./parserTypes.js";
import { coverageButton } from "./dom.js";
import { attachHoverPopover, hidePopover, makeElement } from "./popover.js";

let currentParser: LogParser | null = null;

function buildCoverage(): Node[] | null {
    if (currentParser === null || currentParser.coverage === undefined) {
        return null;
    }

    const coverage = currentParser.coverage();
    const nodes: Node[] = [
        makeElement("div", "popoverTitle", currentParser.name),
        makeElement("p", "popoverText", coverage.summary),
    ];

    for (const group of coverage.groups) {
        nodes.push(makeElement("div", "panelTitle", `${group.title} (${group.items.length})`));

        const list = makeElement("ul", "popoverList");

        for (const item of group.items) {
            list.appendChild(makeElement("li", "", item));
        }

        nodes.push(list);
    }

    return nodes;
}

export function setCoverage(parser: LogParser | null): void {
    hidePopover();
    currentParser = parser;
    coverageButton.hidden = parser === null || parser.coverage === undefined;
}

attachHoverPopover(coverageButton, buildCoverage);
