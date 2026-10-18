import { formatsButton } from "./dom.js";
import { PARSERS } from "./parserRegistry.js";
import { attachHoverPopover, makeElement } from "./popover.js";

function buildFormatsList(): Node[] {
    const list = makeElement("ul", "popoverList formatList");

    for (const parser of PARSERS) {
        const row = makeElement("li", "");
        row.append(makeElement("span", "formatListName", parser.name), makeElement("span", "formatListText", parser.description));
        list.appendChild(row);
    }

    return [
        makeElement("div", "popoverTitle", `Supported formats (${PARSERS.length})`),
        makeElement("p", "popoverText", "Just drop a file: the format is recognized from its content, not from the file name. Lines that do not fit the format are still shown and marked \"Unparsed\"."),
        list,
    ];
}

formatsButton.textContent = `${PARSERS.length} formats`;
attachHoverPopover(formatsButton, buildFormatsList);
