export interface Placeholder {
    token: string;
    label: string;
    pattern: RegExp;
}

export const PLACEHOLDERS: Placeholder[] = [
    { token: "<EMAIL>", label: "email address", pattern: /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g },
    { token: "<UUID>", label: "UUID", pattern: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi },
    { token: "<TIME>", label: "date / time", pattern: /\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?|\b\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?\b/g },
    { token: "<MAC>", label: "MAC address", pattern: /\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b/gi },
    { token: "<IP>", label: "IP address", pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b|(?<![\w:])(?=[0-9a-f:]*::|(?:[0-9a-f]{1,4}:){3})[0-9a-f]{0,4}(?::{1,2}[0-9a-f]{1,4}){1,7}(?:::)?(?![\w:])/gi },
    { token: "<HEX>", label: "hex value", pattern: /\b0x[0-9a-f]+\b/gi },
    { token: "<ID>", label: "ID / hash / token", pattern: /\b(?=[a-z_-]*\d)(?=\d*[a-z])[\w-]{12,}\b|\b[0-9a-f]{8,}\b/gi },
    { token: "<STR>", label: "quoted text", pattern: /"[^"\n]{1,200}"|'[^'\n]{1,200}'/g },
    { token: "<NUM>", label: "number", pattern: /\b\d+(?:\.\d+)?/g },
];

const KEPT_PREFIX = /^\d{1,5} — /;
const TOKEN_PATTERN = new RegExp(PLACEHOLDERS.map(placeholder => placeholder.token).join("|"), "g");
const MAX_TEMPLATE_LENGTH = 300;

export function normalizeMessage(text: string): string {
    const shortened = text.length > MAX_TEMPLATE_LENGTH ? text.slice(0, MAX_TEMPLATE_LENGTH) : text;
    const prefix = KEPT_PREFIX.exec(shortened)?.[0] ?? "";
    let result = shortened.slice(prefix.length);

    for (const placeholder of PLACEHOLDERS) {
        result = result.replace(placeholder.pattern, match => match.startsWith("\"") || match.startsWith("'") ? `${match[0]}${placeholder.token}${match[0]}` : placeholder.token);
    }

    return (prefix + result).replace(/\s+/g, " ").trim();
}

export interface TemplatePart {
    text: string;
    isPlaceholder: boolean;
}

export function splitTemplate(template: string): TemplatePart[] {
    const parts: TemplatePart[] = [];
    let last = 0;

    for (const match of template.matchAll(TOKEN_PATTERN)) {
        const start = match.index ?? 0;

        if (start > last) {
            parts.push({ text: template.slice(last, start), isPlaceholder: false });
        }

        parts.push({ text: match[0], isPlaceholder: true });
        last = start + match[0].length;
    }

    if (last < template.length) {
        parts.push({ text: template.slice(last), isPlaceholder: false });
    }

    return parts;
}

export function placeholderLabel(token: string): string {
    return PLACEHOLDERS.find(placeholder => placeholder.token === token)?.label ?? "variable value";
}
