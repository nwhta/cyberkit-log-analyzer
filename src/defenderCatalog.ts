import type { SecurityCategory } from "./types.js";
import type { EventFacts } from "./eventExplainer.js";

export const DEFENDER_PROVIDER = "Microsoft-Windows-Windows Defender";

interface DefenderEventInfo {
    description: string;
    category: SecurityCategory;
    alert?: string;
}

export const DEFENDER_EVENTS: Readonly<Record<string, DefenderEventInfo>> = {
    "1006": { description: "Defender found malware or unwanted software", category: "FILE", alert: "Malware detected" },
    "1007": { description: "Defender took action against malware", category: "FILE" },
    "1008": { description: "Defender failed to act on malware", category: "FILE", alert: "Malware NOT removed" },
    "1009": { description: "Item restored from quarantine", category: "FILE", alert: "Quarantine restore" },
    "1013": { description: "Malware history deleted", category: "FILE", alert: "Detection history deleted" },
    "1015": { description: "Defender detected suspicious behavior", category: "PROCESS", alert: "Suspicious behavior" },
    "1116": { description: "Defender detected malware or unwanted software", category: "FILE", alert: "Malware detected" },
    "1117": { description: "Defender took action to protect the system", category: "FILE" },
    "1118": { description: "Defender action failed (non-critical)", category: "FILE", alert: "Malware NOT removed" },
    "1119": { description: "Defender action failed (critical)", category: "FILE", alert: "Malware NOT removed" },
    "1121": { description: "Attack surface reduction rule blocked an action", category: "PROCESS", alert: "ASR rule blocked" },
    "1122": { description: "Attack surface reduction rule audited an action", category: "PROCESS" },
    "1123": { description: "Controlled folder access blocked an app (ransomware protection)", category: "FILE", alert: "Ransomware protection" },
    "1125": { description: "Network protection blocked a malicious site", category: "NETWORK", alert: "Malicious site blocked" },
    "1150": { description: "Defender is healthy", category: "SYSTEM" },
    "1151": { description: "Defender health report", category: "SYSTEM" },
    "2000": { description: "Defender signatures updated", category: "SYSTEM" },
    "2001": { description: "Defender signature update failed", category: "SYSTEM" },
    "2010": { description: "Cloud-delivered protection updated signatures", category: "SYSTEM" },
    "3002": { description: "Real-time protection hit an error", category: "SYSTEM", alert: "Protection error" },
    "5000": { description: "Real-time protection enabled", category: "SYSTEM" },
    "5001": { description: "Real-time protection DISABLED", category: "SYSTEM", alert: "Protection disabled" },
    "5004": { description: "Real-time protection configuration changed", category: "SYSTEM" },
    "5007": { description: "Defender configuration changed", category: "SYSTEM" },
    "5008": { description: "Defender engine crashed", category: "SYSTEM", alert: "Defender crashed" },
    "5010": { description: "Scanning for malware and unwanted software DISABLED", category: "SYSTEM", alert: "Protection disabled" },
    "5012": { description: "Virus scanning DISABLED", category: "SYSTEM", alert: "Protection disabled" },
    "5013": { description: "Tamper protection blocked a change to Defender", category: "SYSTEM", alert: "Tamper attempt" },
    "1000": { description: "Malware scan started", category: "SYSTEM" },
    "1001": { description: "Malware scan finished", category: "SYSTEM" },
    "1002": { description: "Malware scan stopped before finishing", category: "SYSTEM" },
};

function value(facts: EventFacts, ...names: string[]): string | null {
    for (const name of names) {
        const found = facts.data.get(name);

        if (found !== undefined && found !== "" && found !== "-") {
            return found;
        }
    }

    return null;
}

function cleanPath(path: string | null): string | null {
    return path === null ? null : path.replace(/^(?:file|containerfile|process|behavior):_?/i, "").split(";")[0];
}

export function summarizeDefender(facts: EventFacts): string {
    const info = DEFENDER_EVENTS[facts.eventId];
    const threat = value(facts, "Threat Name");
    const path = cleanPath(value(facts, "Path"));
    const user = value(facts, "Detection User", "User");
    const action = value(facts, "Action Name");
    const process = value(facts, "Process Name");

    switch (facts.eventId) {
        case "1006":
        case "1116":
            return `${threat ?? "Malware"} found${path ? ` in ${path}` : ""}${user ? ` (user ${user})` : ""}${process && process !== "Unknown" ? ` · started by ${process}` : ""}`;
        case "1007":
        case "1117":
            return `${action ?? "Action taken"}: ${threat ?? "threat"}${path ? ` in ${path}` : ""}`;
        case "1008":
        case "1118":
        case "1119":
            return `Could not ${(action ?? "remove").toLowerCase()} ${threat ?? "the threat"}${path ? ` in ${path}` : ""}: ${value(facts, "Error Description") ?? "unknown error"}`;
        case "1121":
        case "1122":
        case "1123":
            return `${process ?? "A program"} → ${path ?? value(facts, "Target") ?? "?"}${value(facts, "ID") ? ` (rule ${value(facts, "ID")})` : ""}`;
        case "5007":
        case "5004":
            return `${value(facts, "Old Value") ?? ""} → ${value(facts, "New Value") ?? ""}`.trim();
        default:
            return info?.description ?? "Microsoft Defender event";
    }
}

export function defenderAlert(facts: EventFacts): { name: string; reason: string } | null {
    const info = DEFENDER_EVENTS[facts.eventId];

    if (facts.eventId === "5007") {
        const change = `${value(facts, "New Value") ?? ""}`;

        if (/Exclusions/i.test(change)) {
            return { name: "Defender exclusion added", reason: "Attackers add exclusions so their tools are not scanned." };
        }

        if (/DisableRealtimeMonitoring|DisableAntiSpyware|DisableBehaviorMonitoring|DisableIOAVProtection|= 0x1/i.test(change)) {
            return { name: "Protection setting turned off", reason: "A Defender protection feature was switched off." };
        }

        return null;
    }

    if (info?.alert === undefined) {
        return null;
    }

    const reasons: Readonly<Record<string, string>> = {
        "Malware detected": "Defender found a known threat. Check whether it was removed (event 1117) and how it got there.",
        "Malware NOT removed": "The threat may still be active. Investigate this computer.",
        "Protection disabled": "Turning off Defender is a typical step before running malware.",
        "Tamper attempt": "Something tried to change Defender settings and was blocked.",
        "Detection history deleted": "Deleting history can hide traces of an infection.",
        "Quarantine restore": "A quarantined file was put back — make sure this was intended.",
    };

    return { name: info.alert, reason: reasons[info.alert] ?? info.description };
}
