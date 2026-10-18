const factory = globalThis.trustedTypes;
const xmlPolicy = factory?.createPolicy("xml-parser", { createHTML: input => input }) ?? null;
export function parseXmlDocument(content) {
    const input = (xmlPolicy?.createHTML(content) ?? content);
    return new DOMParser().parseFromString(input, "application/xml");
}
