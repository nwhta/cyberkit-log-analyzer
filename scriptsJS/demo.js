import { demoButton } from "./dom.js";
import { PARSERS } from "./parserRegistry.js";
import { attachClickPopover, hidePopover, makeElement } from "./popover.js";
let loader = null;
async function loadDemo(parser) {
    if (parser.demoFile === undefined || loader === null) {
        return;
    }
    hidePopover();
    demoButton.disabled = true;
    try {
        const response = await fetch(parser.demoFile, { cache: "no-cache" });
        if (!response.ok) {
            throw new Error(`Demo file is not available (HTTP ${response.status}).`);
        }
        loader(parser, await response.text());
    }
    catch (error) {
        alert(error instanceof Error ? error.message : "Could not load the demo log.");
    }
    finally {
        demoButton.disabled = false;
    }
}
function buildMenu() {
    const menu = makeElement("div", "demoMenu");
    for (const parser of PARSERS) {
        if (parser.demoFile === undefined) {
            continue;
        }
        const item = makeElement("button", "demoItem");
        item.type = "button";
        item.append(makeElement("span", "formatListName", parser.name), makeElement("span", "formatListText", parser.description));
        item.addEventListener("click", () => void loadDemo(parser));
        menu.appendChild(item);
    }
    return [
        makeElement("div", "popoverTitle", "Try a demo log"),
        makeElement("p", "popoverText", "Sample logs made for this demo, with normal activity and typical attacks mixed in. The file is opened and analyzed in your browser exactly like your own logs would be: nothing is uploaded."),
        menu,
    ];
}
export function setDemoLoader(callback) {
    loader = callback;
}
attachClickPopover(demoButton, buildMenu);
