interface XmlPolicy {
    createHTML(input: string): unknown;
}

interface TrustedTypesFactory {
    createPolicy(name: string, rules: { createHTML: (input: string) => string }): XmlPolicy;
}

const factory = (globalThis as { trustedTypes?: TrustedTypesFactory }).trustedTypes;

const xmlPolicy: XmlPolicy | null = factory?.createPolicy("xml-parser", { createHTML: input => input }) ?? null;

export function parseXmlDocument(content: string): Document {
    const input = (xmlPolicy?.createHTML(content) ?? content) as string;
    return new DOMParser().parseFromString(input, "application/xml");
}
