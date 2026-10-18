import type { AuditResult, EventDataField, Severity, WindowsLogEntry } from "./types.js";
import { getWindowsEventCategory } from "./windowsEventCatalog.js";

import { type EventFacts, isRoutineEvent, normalizeIp, summarizeEvent } from "./eventExplainer.js";
import { SYSMON_PROVIDER } from "./sysmonCatalog.js";
import { parseXmlDocument } from "./trustedXml.js";
import { summarizeSysmon, sysmonAlert } from "./sysmonExplainer.js";
import { DEFENDER_PROVIDER, defenderAlert, summarizeDefender } from "./defenderCatalog.js";

const WINDOWS_NAMESPACE =
    "http://schemas.microsoft.com/win/2004/08/events/event";

const AUDIT_FAILURE_FLAG = 0x0010000000000000n;
const AUDIT_SUCCESS_FLAG = 0x0020000000000000n;

export function parseWindowsXml(content: string): WindowsLogEntry[] {
    if (/<!DOCTYPE|<!ENTITY/i.test(content)) {
        throw new Error("DTD and entity declarations are not supported.");
    }

    const xmlDocument = parseXmlDocument(content);

    if (xmlDocument.getElementsByTagName("parsererror").length > 0) {
        throw new Error("Invalid XML file.");
    }

    const root = xmlDocument.documentElement;

    if (root.localName !== "Events" && root.localName !== "Event") {
        throw new Error("Expected a Windows Event Log XML export.");
    }

    const events = Array.from(
        xmlDocument.getElementsByTagNameNS(WINDOWS_NAMESPACE, "Event")
    );

    if (events.length === 0) {
        throw new Error("No Windows events found.");
    }

    const entries: WindowsLogEntry[] = [];

    for (let i = 0; i < events.length; i++) {
        entries.push(parseWindowsEvent(events[i], i + 1));
    }

    return entries;
}

function parseWindowsEvent(event: Element,eventNumber: number): WindowsLogEntry {
    const system = event.getElementsByTagNameNS( WINDOWS_NAMESPACE, "System")[0];

    if (!system) {
        throw new Error(`Event ${eventNumber} has no System element.`);
    }

    const eventId = readText(system, "EventID");
    const windowsLevel = readText(system, "Level");
    const keywords = readText(system, "Keywords");
    const computer = readText(system, "Computer");
    const channel = readText(system, "Channel");

    const providerElement = system.getElementsByTagNameNS(WINDOWS_NAMESPACE,"Provider")[0];

    const provider = providerElement?.getAttribute("Name") ?? "";

    const timeElement = system.getElementsByTagNameNS(WINDOWS_NAMESPACE,"TimeCreated")[0];
    const timestamp = timeElement?.getAttribute("SystemTime") ?? "";

    const separator = timestamp.indexOf("T");
    const date = separator >= 0 ? timestamp.slice(0, separator) : "";
    const time = separator >= 0 ? timestamp.slice(separator + 1) : "";

    const dataElements = event.getElementsByTagNameNS(
        WINDOWS_NAMESPACE,
        "Data"
    );

    let ip: string | null = null;
    let mac: string | null = null;

    const eventData: EventDataField[] = [];
    const dataByName = new Map<string, string>();

    const addField = (name: string, value: string): void => {
        eventData.push({ name, value });

        if (name !== "" && !dataByName.has(name)) {
            dataByName.set(name, value);
        }
    };

    for (const data of Array.from(dataElements)) {
        const name = data.getAttribute("Name") ?? "";
        const value = data.textContent?.trim() ?? "";

        addField(name, value);

        if (name === "IpAddress" && value !== "" && value !== "-") {
            ip = normalizeIp(value);
        }

        if (
            ["mac", "macaddress"].includes(name.toLowerCase()) &&
            value !== "" &&
            value !== "-"
        ) {
            mac = value;
        }
    }

    const serializer = new XMLSerializer();

    const userData = event.getElementsByTagNameNS(
        WINDOWS_NAMESPACE,
        "UserData"
    )[0];

    if (userData) {
        for (const element of Array.from(userData.getElementsByTagName("*"))) {
            if (element.children.length === 0) {
                addField(element.localName, element.textContent?.trim() ?? "");
            }
        }
    }

    const renderingInfo = event.getElementsByTagNameNS(
        WINDOWS_NAMESPACE,
        "RenderingInfo"
    )[0];

    const renderedMessage = renderingInfo
        ? readText(renderingInfo, "Message")
        : "";

    const auditResult = parseAuditResult(keywords);
    const category = getWindowsEventCategory(provider, eventId);
    const facts: EventFacts = { eventId, provider, auditResult, category, data: dataByName };
    const isSysmon = provider === SYSMON_PROVIDER;
    const isDefender = provider === DEFENDER_PROVIDER;
    const summary = isSysmon ? summarizeSysmon(facts) : isDefender ? summarizeDefender(facts) : summarizeEvent(facts);
    const alert = isSysmon ? sysmonAlert(facts) : isDefender ? defenderAlert(facts) : null;

    return {
        lineNumber: eventNumber,
        line: serializer.serializeToString(event),
        date,
        time,
        severity: parseWindowsLevel(windowsLevel),
        ip,
        mac,

        message: renderedMessage || summary,
        eventId,
        provider,
        computer,
        channel,
        windowsLevel,
        keywords,
        timestamp,

        auditResult,
        category,
        subjectUser: cleanDataValue(dataByName.get("SubjectUserName")),
        targetUser: cleanDataValue(dataByName.get("TargetUserName")),
        logonType: cleanDataValue(dataByName.get("LogonType")),

        eventData,
        renderedMessage,
        summary,
        alert,
        isRoutine: !isSysmon && !isDefender && isRoutineEvent(facts),
        timeMs: parseTimestamp(timestamp),
    };
}

function parseTimestamp(timestamp: string): number {
    return Date.parse(timestamp.replace(/(\.\d{3})\d+/, "$1"));
}

function parseAuditResult(keywords: string): AuditResult {
    if (keywords === "") {
        return "NONE";
    }

    try {
        const value = BigInt(keywords);

        if ((value & AUDIT_FAILURE_FLAG) !== 0n) {
            return "FAILURE";
        }

        if ((value & AUDIT_SUCCESS_FLAG) !== 0n) {
            return "SUCCESS";
        }
    } catch {
    }

    return "NONE";
}

function cleanDataValue(value: string | undefined): string | null {
    if (value === undefined || value === "" || value === "-") {
        return null;
    }

    return value;
}

function readText(parent: Element, tagName: string): string {
    return parent
        .getElementsByTagNameNS(WINDOWS_NAMESPACE, tagName)[0]
        ?.textContent?.trim() ?? "";
}

function parseWindowsLevel(level: string): Severity {
    switch (level) {
        case "0":
            return "INFO";
        case "1":
            return "CRITICAL";
        case "2":
            return "ERROR";
        case "3":
            return "WARNING";
        case "4":
            return "INFO";
        case "5":
            return "DEBUG";
        default:
            return "UNKNOWN";
    }
}
