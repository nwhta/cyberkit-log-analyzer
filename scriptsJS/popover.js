import { infoPopover } from "./dom.js";
const HIDE_DELAY_MS = 200;
const GAP_PX = 8;
let currentTrigger = null;
let currentMode = "hover";
let hideTimer;
function isOpen() {
    return infoPopover.matches(":popover-open");
}
function place(trigger) {
    const rect = trigger.getBoundingClientRect();
    const width = infoPopover.offsetWidth;
    const height = infoPopover.offsetHeight;
    const fitsRight = rect.right + GAP_PX + width <= window.innerWidth - GAP_PX;
    const left = fitsRight ? rect.right + GAP_PX : Math.max(GAP_PX, window.innerWidth - width - GAP_PX);
    const top = Math.max(GAP_PX, Math.min(rect.top, window.innerHeight - height - GAP_PX));
    infoPopover.style.left = `${left}px`;
    infoPopover.style.top = `${top}px`;
}
export function hidePopover() {
    window.clearTimeout(hideTimer);
    if (isOpen()) {
        infoPopover.hidePopover();
    }
    currentTrigger?.setAttribute("aria-expanded", "false");
    currentTrigger = null;
}
function show(trigger, build, mode) {
    window.clearTimeout(hideTimer);
    if (isOpen() && currentTrigger === trigger) {
        return;
    }
    const content = build();
    if (content === null || content.length === 0) {
        return;
    }
    hidePopover();
    infoPopover.replaceChildren(...content);
    infoPopover.showPopover();
    place(trigger);
    currentTrigger = trigger;
    currentMode = mode;
    trigger.setAttribute("aria-expanded", "true");
}
function scheduleHide() {
    window.clearTimeout(hideTimer);
    hideTimer = window.setTimeout(hidePopover, HIDE_DELAY_MS);
}
function toggle(trigger, build, mode) {
    if (isOpen() && currentTrigger === trigger) {
        hidePopover();
    }
    else {
        show(trigger, build, mode);
    }
}
export function attachHoverPopover(trigger, build) {
    trigger.addEventListener("mouseenter", () => show(trigger, build, "hover"));
    trigger.addEventListener("mouseleave", () => currentMode === "hover" && scheduleHide());
    trigger.addEventListener("focus", () => show(trigger, build, "hover"));
    trigger.addEventListener("click", () => show(trigger, build, "hover"));
}
export function attachClickPopover(trigger, build) {
    trigger.addEventListener("click", () => toggle(trigger, build, "click"));
}
export function makeElement(tag, className, text = "") {
    const element = document.createElement(tag);
    element.className = className;
    element.textContent = text;
    return element;
}
infoPopover.addEventListener("mouseenter", () => window.clearTimeout(hideTimer));
infoPopover.addEventListener("mouseleave", () => currentMode === "hover" && scheduleHide());
document.addEventListener("pointerdown", event => {
    const target = event.target;
    if (isOpen() && !infoPopover.contains(target) && !currentTrigger?.contains(target)) {
        hidePopover();
    }
});
document.addEventListener("keydown", event => {
    if (event.key === "Escape") {
        hidePopover();
    }
});
