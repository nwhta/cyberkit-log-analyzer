import { infoPopover } from "./dom.js";

const HIDE_DELAY_MS = 200;
const GAP_PX = 8;

type BuildContent = () => Node[] | null;
type Mode = "hover" | "click";

let currentTrigger: HTMLElement | null = null;
let currentMode: Mode = "hover";
let hideTimer: number | undefined;

function isOpen(): boolean {
    return infoPopover.matches(":popover-open");
}

function place(trigger: HTMLElement): void {
    const rect = trigger.getBoundingClientRect();
    const width = infoPopover.offsetWidth;
    const height = infoPopover.offsetHeight;

    const fitsRight = rect.right + GAP_PX + width <= window.innerWidth - GAP_PX;
    const left = fitsRight ? rect.right + GAP_PX : Math.max(GAP_PX, window.innerWidth - width - GAP_PX);
    const top = Math.max(GAP_PX, Math.min(rect.top, window.innerHeight - height - GAP_PX));

    infoPopover.style.left = `${left}px`;
    infoPopover.style.top = `${top}px`;
}

export function hidePopover(): void {
    window.clearTimeout(hideTimer);

    if (isOpen()) {
        infoPopover.hidePopover();
    }

    currentTrigger?.setAttribute("aria-expanded", "false");
    currentTrigger = null;
}

function show(trigger: HTMLElement, build: BuildContent, mode: Mode): void {
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

function scheduleHide(): void {
    window.clearTimeout(hideTimer);
    hideTimer = window.setTimeout(hidePopover, HIDE_DELAY_MS);
}

function toggle(trigger: HTMLElement, build: BuildContent, mode: Mode): void {
    if (isOpen() && currentTrigger === trigger) {
        hidePopover();
    } else {
        show(trigger, build, mode);
    }
}

export function attachHoverPopover(trigger: HTMLElement, build: BuildContent): void {
    trigger.addEventListener("mouseenter", () => show(trigger, build, "hover"));
    trigger.addEventListener("mouseleave", () => currentMode === "hover" && scheduleHide());
    trigger.addEventListener("focus", () => show(trigger, build, "hover"));
    trigger.addEventListener("click", () => show(trigger, build, "hover"));
}

export function attachClickPopover(trigger: HTMLElement, build: BuildContent): void {
    trigger.addEventListener("click", () => toggle(trigger, build, "click"));
}

export function makeElement<K extends keyof HTMLElementTagNameMap>(tag: K, className: string, text = ""): HTMLElementTagNameMap[K] {
    const element = document.createElement(tag);
    element.className = className;
    element.textContent = text;
    return element;
}

infoPopover.addEventListener("mouseenter", () => window.clearTimeout(hideTimer));
infoPopover.addEventListener("mouseleave", () => currentMode === "hover" && scheduleHide());

document.addEventListener("pointerdown", event => {
    const target = event.target as Node;

    if (isOpen() && !infoPopover.contains(target) && !currentTrigger?.contains(target)) {
        hidePopover();
    }
});

document.addEventListener("keydown", event => {
    if (event.key === "Escape") {
        hidePopover();
    }
});
