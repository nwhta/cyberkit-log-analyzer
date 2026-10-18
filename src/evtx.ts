const FILE_MAGIC = "ElfFile\0";
const CHUNK_MAGIC = "ElfChnk\0";
const FILE_HEADER_SIZE = 4096;
const CHUNK_SIZE = 65536;
const CHUNK_HEADER_SIZE = 512;
const RECORD_MAGIC = 0x00002a2a;

type XmlNode =
    | { kind: "element"; name: string; attributes: { name: string; value: XmlNode[] }[]; children: XmlNode[] }
    | { kind: "text"; value: string }
    | { kind: "raw"; value: string }
    | { kind: "substitution"; index: number; optional: boolean }
    | { kind: "template"; nodes: XmlNode[]; values: SubstitutionValue[] };

interface SubstitutionValue {
    type: number;
    offset: number;
    size: number;
}

export interface EvtxResult {
    xml: string;
    records: number;
    failed: number;
}

function escapeXml(text: string): string {
    return text.replace(/[&<>"]/g, char => char === "&" ? "&amp;" : char === "<" ? "&lt;" : char === ">" ? "&gt;" : "&quot;")
        .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "");
}

function hex(value: bigint | number): string {
    return "0x" + value.toString(16);
}

export function isEvtx(bytes: Uint8Array): boolean {
    return bytes.length >= 8 && String.fromCharCode(...bytes.slice(0, 8)) === FILE_MAGIC;
}

class Chunk {
    private readonly view: DataView;
    private readonly templates = new Map<number, XmlNode[]>();
    private readonly names = new Map<number, string>();
    private readonly utf16 = new TextDecoder("utf-16le");
    private readonly latin1 = new TextDecoder("latin1");

    constructor(private readonly bytes: Uint8Array) {
        this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    }

    get freeSpaceOffset(): number {
        return this.view.getUint32(48, true);
    }

    *records(): Generator<{ id: bigint; xml: string } | null> {
        let offset = CHUNK_HEADER_SIZE;
        const end = Math.min(this.freeSpaceOffset || CHUNK_SIZE, this.bytes.length);

        while (offset + 24 <= end) {
            if (this.view.getUint32(offset, true) !== RECORD_MAGIC) {
                break;
            }

            const size = this.view.getUint32(offset + 4, true);

            if (size < 28 || offset + size > this.bytes.length) {
                break;
            }

            const id = this.view.getBigUint64(offset + 8, true);

            try {
                const position = { at: offset + 24 };
                const nodes = this.parseFragment(position, offset + size - 4, null, true);
                yield { id, xml: this.render(nodes, []) };
            } catch {
                yield null;
            }

            offset += size;
        }
    }

    private u8(position: { at: number }): number {
        return this.bytes[position.at++];
    }

    private u16(position: { at: number }): number {
        const value = this.view.getUint16(position.at, true);
        position.at += 2;
        return value;
    }

    private u32(position: { at: number }): number {
        const value = this.view.getUint32(position.at, true);
        position.at += 4;
        return value;
    }

    private nameAt(offset: number): string {
        const cached = this.names.get(offset);

        if (cached !== undefined) {
            return cached;
        }

        const count = this.view.getUint16(offset + 6, true);
        const name = this.utf16.decode(this.bytes.subarray(offset + 8, offset + 8 + count * 2));
        this.names.set(offset, name);
        return name;
    }

    private readName(position: { at: number }): string {
        const offset = this.u32(position);
        const name = this.nameAt(offset);

        if (offset === position.at) {
            const count = this.view.getUint16(offset + 6, true);
            position.at += 8 + count * 2 + 2;
        }

        return name;
    }

    private parseFragment(position: { at: number }, end: number, stopAtEnd: number | null, bare = false): XmlNode[] {
        const nodes: XmlNode[] = [];

        while (position.at < end) {
            const token = this.bytes[position.at];
            const base = token & 0x0f;

            if (base === 0x00) {
                position.at++;
                break;
            }

            if (base === 0x0f) {
                position.at += 4;
                continue;
            }

            if (base === 0x0c) {
                nodes.push(this.parseTemplateInstance(position));
                continue;
            }

            if (base === 0x01) {
                nodes.push(this.parseElement(position, bare));
                continue;
            }

            if (stopAtEnd !== null && base === 0x04) {
                break;
            }

            const content = this.parseContent(position);

            if (content === null) {
                throw new Error(`Unexpected BinXML token 0x${token.toString(16)}`);
            }

            nodes.push(content);
        }

        return nodes;
    }

    private parseContent(position: { at: number }): XmlNode | null {
        const token = this.bytes[position.at];
        const base = token & 0x0f;

        switch (base) {
            case 0x05: {
                position.at += 2;
                const count = this.u16(position);
                const value = this.utf16.decode(this.bytes.subarray(position.at, position.at + count * 2));
                position.at += count * 2;
                return { kind: "text", value };
            }
            case 0x07: {
                position.at++;
                const count = this.u16(position);
                const value = this.utf16.decode(this.bytes.subarray(position.at, position.at + count * 2));
                position.at += count * 2;
                return { kind: "raw", value: `<![CDATA[${value}]]>` };
            }
            case 0x08: {
                position.at++;
                return { kind: "raw", value: `&#${this.u16(position)};` };
            }
            case 0x09: {
                position.at++;
                return { kind: "raw", value: `&${this.readName(position)};` };
            }
            case 0x0a: {
                position.at++;
                const target = this.readName(position);
                return { kind: "raw", value: `<?${target} ` };
            }
            case 0x0b: {
                position.at++;
                const count = this.u16(position);
                const value = this.utf16.decode(this.bytes.subarray(position.at, position.at + count * 2));
                position.at += count * 2;
                return { kind: "raw", value: `${value}?>` };
            }
            case 0x0d:
            case 0x0e: {
                position.at++;
                const index = this.u16(position);
                position.at++;
                return { kind: "substitution", index, optional: base === 0x0e };
            }
            default:
                return null;
        }
    }

    private parseElement(position: { at: number }, bare: boolean): XmlNode {
        const token = this.u8(position);

        if (!bare) {
            position.at += 2;
        }

        const dataSize = this.u32(position);
        const end = position.at + dataSize;
        const name = this.readName(position);
        const attributes: { name: string; value: XmlNode[] }[] = [];
        const children: XmlNode[] = [];

        if (token & 0x40) {
            position.at += 4;

            while ((this.bytes[position.at] & 0x0f) === 0x06) {
                position.at++;
                const attributeName = this.readName(position);
                const value: XmlNode[] = [];

                while ([0x05, 0x08, 0x09, 0x0d, 0x0e].includes(this.bytes[position.at] & 0x0f)) {
                    const content = this.parseContent(position);

                    if (content === null) {
                        break;
                    }

                    value.push(content);
                }

                attributes.push({ name: attributeName, value });
            }
        }

        const close = this.u8(position) & 0x0f;

        if (close === 0x02) {
            while (position.at < end) {
                const next = this.bytes[position.at] & 0x0f;

                if (next === 0x04) {
                    position.at++;
                    break;
                }

                if (next === 0x01) {
                    children.push(this.parseElement(position, bare));
                    continue;
                }

                if (next === 0x0c) {
                    children.push(this.parseTemplateInstance(position));
                    continue;
                }

                const content = this.parseContent(position);

                if (content === null) {
                    throw new Error(`Unexpected token in element ${name}`);
                }

                children.push(content);
            }
        } else if (close !== 0x03) {
            throw new Error(`Bad element close token in ${name}`);
        }

        return { kind: "element", name, attributes, children };
    }

    private templateAt(offset: number): XmlNode[] {
        const cached = this.templates.get(offset);

        if (cached !== undefined) {
            return cached;
        }

        const dataSize = this.view.getUint32(offset + 20, true);
        const position = { at: offset + 24 };
        const nodes = this.parseFragment(position, offset + 24 + dataSize, null);
        this.templates.set(offset, nodes);
        return nodes;
    }

    private parseTemplateInstance(position: { at: number }): XmlNode {
        position.at += 2;
        position.at += 4;
        const definitionOffset = this.u32(position);
        const nodes = this.templateAt(definitionOffset);

        if (definitionOffset === position.at) {
            const dataSize = this.view.getUint32(definitionOffset + 20, true);
            position.at = definitionOffset + 24 + dataSize;
        }

        const count = this.u32(position);
        const descriptors: { size: number; type: number }[] = [];

        for (let i = 0; i < count; i++) {
            const size = this.u16(position);
            const type = this.u8(position);
            position.at++;
            descriptors.push({ size, type });
        }

        const values: SubstitutionValue[] = [];

        for (const descriptor of descriptors) {
            values.push({ type: descriptor.type, offset: position.at, size: descriptor.size });
            position.at += descriptor.size;
        }

        return { kind: "template", nodes, values };
    }

    private filetime(offset: number): string {
        const ticks = this.view.getBigUint64(offset, true);

        if (ticks === 0n) {
            return "";
        }

        const ms = Number(ticks / 10000n) - 11644473600000;
        const fraction = (ticks % 10000000n).toString().padStart(7, "0");
        return new Date(ms).toISOString().slice(0, 19) + `.${fraction}Z`;
    }

    private systemtime(offset: number): string {
        const get = (index: number): number => this.view.getUint16(offset + index * 2, true);
        const date = new Date(Date.UTC(get(0), get(1) - 1, get(3), get(4), get(5), get(6), get(7)));
        return Number.isNaN(date.getTime()) ? "" : date.toISOString();
    }

    private sid(offset: number, size: number): string {
        if (size < 8) {
            return "";
        }

        const revision = this.bytes[offset];
        const count = this.bytes[offset + 1];
        let authority = 0n;

        for (let i = 2; i < 8; i++) {
            authority = (authority << 8n) | BigInt(this.bytes[offset + i]);
        }

        const parts = [`S-${revision}-${authority}`];

        for (let i = 0; i < count && 8 + i * 4 + 4 <= size; i++) {
            parts.push(String(this.view.getUint32(offset + 8 + i * 4, true)));
        }

        return parts.join("-");
    }

    private guid(offset: number): string {
        const b = this.bytes;
        const h = (index: number): string => b[offset + index].toString(16).padStart(2, "0");
        const part1 = this.view.getUint32(offset, true).toString(16).padStart(8, "0");
        const part2 = this.view.getUint16(offset + 4, true).toString(16).padStart(4, "0");
        const part3 = this.view.getUint16(offset + 6, true).toString(16).padStart(4, "0");
        return `{${part1}-${part2}-${part3}-${h(8)}${h(9)}-${h(10)}${h(11)}${h(12)}${h(13)}${h(14)}${h(15)}}`.toUpperCase();
    }

    private value(value: SubstitutionValue, depth: number): string | null {
        const { type, offset, size } = value;

        if (size === 0 && type !== 0x01) {
            return null;
        }

        if (type & 0x80) {
            const base = type & 0x7f;

            if (base === 0x01) {
                return escapeXml(this.utf16.decode(this.bytes.subarray(offset, offset + size)).split("\0").filter(Boolean).join(", "));
            }

            const width = { 0x04: 1, 0x06: 2, 0x08: 4, 0x0a: 8, 0x14: 4, 0x15: 8, 0x0f: 16 }[base] ?? 0;

            if (width === 0) {
                return null;
            }

            const items: string[] = [];

            for (let at = offset; at + width <= offset + size; at += width) {
                items.push(this.value({ type: base, offset: at, size: width }, depth) ?? "");
            }

            return items.join(", ");
        }

        switch (type) {
            case 0x00:
                return null;
            case 0x01:
                return escapeXml(this.utf16.decode(this.bytes.subarray(offset, offset + size)).replace(/\0+$/, ""));
            case 0x02:
                return escapeXml(this.latin1.decode(this.bytes.subarray(offset, offset + size)).replace(/\0+$/, ""));
            case 0x03:
                return String(this.view.getInt8(offset));
            case 0x04:
                return String(this.view.getUint8(offset));
            case 0x05:
                return String(this.view.getInt16(offset, true));
            case 0x06:
                return String(this.view.getUint16(offset, true));
            case 0x07:
                return String(this.view.getInt32(offset, true));
            case 0x08:
                return String(this.view.getUint32(offset, true));
            case 0x09:
                return String(this.view.getBigInt64(offset, true));
            case 0x0a:
                return String(this.view.getBigUint64(offset, true));
            case 0x0b:
                return String(this.view.getFloat32(offset, true));
            case 0x0c:
                return String(this.view.getFloat64(offset, true));
            case 0x0d:
                return this.view.getUint32(offset, true) !== 0 ? "true" : "false";
            case 0x0e:
                return Array.from(this.bytes.subarray(offset, offset + size), byte => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
            case 0x0f:
                return this.guid(offset);
            case 0x10:
                return size === 8 ? hex(this.view.getBigUint64(offset, true)) : hex(this.view.getUint32(offset, true));
            case 0x11:
                return this.filetime(offset);
            case 0x12:
                return this.systemtime(offset);
            case 0x13:
                return this.sid(offset, size);
            case 0x14:
                return hex(this.view.getUint32(offset, true));
            case 0x15:
                return hex(this.view.getBigUint64(offset, true));
            case 0x21: {
                if (depth > 8) {
                    return null;
                }

                const position = { at: offset };
                const nodes = this.parseFragment(position, offset + size, null, true);
                return this.render(nodes, [], depth + 1);
            }
            default:
                return null;
        }
    }

    private render(nodes: XmlNode[], values: SubstitutionValue[], depth = 0): string {
        let out = "";

        for (const node of nodes) {
            out += this.renderNode(node, values, depth);
        }

        return out;
    }

    private renderNode(node: XmlNode, values: SubstitutionValue[], depth: number): string {
        switch (node.kind) {
            case "text":
                return escapeXml(node.value);
            case "raw":
                return node.value;
            case "substitution": {
                const value = values[node.index];
                return value === undefined ? "" : this.value(value, depth) ?? "";
            }
            case "template":
                return this.render(node.nodes, node.values, depth);
            case "element": {
                let attributes = "";

                for (const attribute of node.attributes) {
                    const onlyOptional = attribute.value.length === 1 && attribute.value[0].kind === "substitution" && attribute.value[0].optional;
                    const rendered = this.render(attribute.value, values, depth);

                    if (onlyOptional && rendered === "") {
                        continue;
                    }

                    attributes += ` ${attribute.name}="${rendered.replace(/"/g, "&quot;")}"`;
                }

                const inner = this.render(node.children, values, depth);
                return inner === "" ? `<${node.name}${attributes}/>` : `<${node.name}${attributes}>${inner}</${node.name}>`;
            }
        }
    }
}

export function evtxToXml(buffer: ArrayBuffer): EvtxResult {
    const bytes = new Uint8Array(buffer);

    if (!isEvtx(bytes)) {
        throw new Error("This is not an .evtx file.");
    }

    const parts: string[] = ['<?xml version="1.0" encoding="UTF-8"?>\n<Events>'];
    let records = 0;
    let failed = 0;
    const seen = new Set<bigint>();

    for (let offset = FILE_HEADER_SIZE; offset + CHUNK_HEADER_SIZE <= bytes.length; offset += CHUNK_SIZE) {
        const chunkBytes = bytes.subarray(offset, Math.min(offset + CHUNK_SIZE, bytes.length));

        if (String.fromCharCode(...chunkBytes.subarray(0, 8)) !== CHUNK_MAGIC) {
            continue;
        }

        for (const record of new Chunk(chunkBytes).records()) {
            if (record === null) {
                failed++;
                continue;
            }

            if (seen.has(record.id)) {
                continue;
            }

            seen.add(record.id);
            parts.push(record.xml);
            records++;
        }
    }

    parts.push("</Events>\n");
    return { xml: parts.join("\n"), records, failed };
}
