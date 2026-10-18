import { SYSMON_EVENTS, SYSMON_PROVIDER } from "./sysmonCatalog.js";
import { DEFENDER_EVENTS, DEFENDER_PROVIDER } from "./defenderCatalog.js";
export const SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing";
const EVENTLOG_PROVIDER = "Microsoft-Windows-Eventlog";
const SECURITY_EVENTS = {
    "4720": { description: "User account created", category: "ACCOUNT" },
    "4722": { description: "Account enabled", category: "ACCOUNT" },
    "4723": { description: "Account password change attempted", category: "ACCOUNT" },
    "4724": { description: "Account password reset attempted", category: "ACCOUNT" },
    "4725": { description: "Account disabled", category: "ACCOUNT" },
    "4726": { description: "User account deleted", category: "ACCOUNT" },
    "4738": { description: "User account changed", category: "ACCOUNT" },
    "4740": { description: "User account locked out", category: "ACCOUNT" },
    "4767": { description: "User account unlocked", category: "ACCOUNT" },
    "4781": { description: "Account renamed", category: "ACCOUNT" },
    "4798": { description: "User's local group membership enumerated", category: "ACCOUNT" },
    "4741": { description: "Computer account created", category: "ACCOUNT" },
    "4742": { description: "Computer account changed", category: "ACCOUNT" },
    "4743": { description: "Computer account deleted", category: "ACCOUNT" },
    "4794": { description: "Directory Services Restore Mode password set", category: "ACCOUNT" },
    "4765": { description: "SID History added to an account", category: "ACCOUNT" },
    "4799": { description: "Security group membership enumerated", category: "GROUP" },
    "4624": { description: "Account logon succeeded", category: "LOGON" },
    "4625": { description: "Account logon failed", category: "LOGON" },
    "4634": { description: "Account session ended", category: "LOGON" },
    "4647": { description: "User initiated logoff", category: "LOGON" },
    "4648": { description: "Explicit credentials used in a logon attempt", category: "LOGON" },
    "4672": { description: "New logon received special privileges", category: "LOGON" },
    "4778": { description: "Session reconnected", category: "LOGON" },
    "4779": { description: "Session disconnected", category: "LOGON" },
    "4964": { description: "Special groups assigned to a new logon", category: "LOGON" },
    "4825": { description: "Remote Desktop access denied", category: "LOGON" },
    "4768": { description: "Kerberos ticket (TGT) requested", category: "AUTHENTICATION" },
    "4769": { description: "Kerberos service ticket requested", category: "AUTHENTICATION" },
    "4770": { description: "Kerberos service ticket renewed", category: "AUTHENTICATION" },
    "4771": { description: "Kerberos pre-authentication failed", category: "AUTHENTICATION" },
    "4776": { description: "Credential validation (NTLM)", category: "AUTHENTICATION" },
    "4800": { description: "Workstation locked", category: "LOGON" },
    "4801": { description: "Workstation unlocked", category: "LOGON" },
    "4688": { description: "Process started", category: "PROCESS" },
    "4689": { description: "Process ended", category: "PROCESS" },
    "4697": { description: "Service installed", category: "SERVICE" },
    "4698": { description: "Scheduled task created", category: "SCHEDULED_TASK" },
    "4699": { description: "Scheduled task deleted", category: "SCHEDULED_TASK" },
    "4700": { description: "Scheduled task enabled", category: "SCHEDULED_TASK" },
    "4701": { description: "Scheduled task disabled", category: "SCHEDULED_TASK" },
    "4702": { description: "Scheduled task modified", category: "SCHEDULED_TASK" },
    "4728": { description: "Member added to a global security group", category: "GROUP" },
    "4729": { description: "Member removed from a global security group", category: "GROUP" },
    "4732": { description: "Member added to a local security group", category: "GROUP" },
    "4733": { description: "Member removed from a local security group", category: "GROUP" },
    "4727": { description: "Global security group created", category: "GROUP" },
    "4731": { description: "Local security group created", category: "GROUP" },
    "4735": { description: "Local security group changed", category: "GROUP" },
    "4737": { description: "Global security group changed", category: "GROUP" },
    "4756": { description: "Member added to a universal security group", category: "GROUP" },
    "4757": { description: "Member removed from a universal security group", category: "GROUP" },
    "4719": { description: "System audit configuration changed", category: "AUDIT_POLICY" },
    "4907": { description: "Object audit settings changed", category: "AUDIT_POLICY" },
    "5379": { description: "Credential Manager credentials were read", category: "CREDENTIALS" },
    "5058": { description: "Key file operation", category: "CREDENTIALS" },
    "5061": { description: "Cryptographic operation", category: "CREDENTIALS" },
    "4673": { description: "A privileged service was called", category: "PRIVILEGE_USE" },
    "4674": { description: "An operation was attempted on a privileged object", category: "PRIVILEGE_USE" },
    "4656": { description: "A handle to an object was requested", category: "OBJECT_ACCESS" },
    "4663": { description: "An attempt was made to access an object", category: "OBJECT_ACCESS" },
    "4660": { description: "An object was deleted", category: "OBJECT_ACCESS" },
    "4670": { description: "Permissions on an object were changed", category: "OBJECT_ACCESS" },
    "4657": { description: "A registry value was modified", category: "OBJECT_ACCESS" },
    "5140": { description: "A network share was accessed", category: "OBJECT_ACCESS" },
    "5145": { description: "A network share object was checked for access", category: "OBJECT_ACCESS" },
    "4662": { description: "An operation was performed on an Active Directory object", category: "OBJECT_ACCESS" },
    "5136": { description: "A directory service object was modified", category: "OBJECT_ACCESS" },
    "5156": { description: "Network connection allowed", category: "NETWORK" },
    "5157": { description: "Network connection blocked", category: "NETWORK" },
    "4946": { description: "Firewall rule added", category: "NETWORK" },
    "4947": { description: "Firewall rule modified", category: "NETWORK" },
    "4948": { description: "Firewall rule deleted", category: "NETWORK" },
    "4608": { description: "Windows is starting up", category: "SYSTEM" },
    "4609": { description: "Windows is shutting down", category: "SYSTEM" },
    "4826": { description: "Boot configuration data loaded", category: "SYSTEM" },
    "6416": { description: "A new external device was recognized", category: "SYSTEM" },
    "4616": { description: "System time changed", category: "SYSTEM" },
};
const EVENTLOG_EVENTS = {
    "1102": { description: "Security log was cleared", category: "SYSTEM" },
    "1100": { description: "Event logging service shut down", category: "SYSTEM" },
};
function findEventInfo(provider, eventId) {
    if (provider === SECURITY_PROVIDER) {
        return SECURITY_EVENTS[eventId] ?? null;
    }
    if (provider === EVENTLOG_PROVIDER) {
        return EVENTLOG_EVENTS[eventId] ?? null;
    }
    if (provider === SYSMON_PROVIDER) {
        return SYSMON_EVENTS[eventId] ?? null;
    }
    if (provider === DEFENDER_PROVIDER) {
        return DEFENDER_EVENTS[eventId] ?? null;
    }
    return null;
}
export function getWindowsEventDescription(provider, eventId) {
    return findEventInfo(provider, eventId)?.description ?? "Uncatalogued Windows event";
}
export function getWindowsEventCategory(provider, eventId) {
    return findEventInfo(provider, eventId)?.category ?? "OTHER";
}
export function isFailedLogon(provider, eventId) {
    return provider === SECURITY_PROVIDER && (eventId === "4625" || eventId === "4771");
}
export const CATEGORY_LABELS = {
    LOGON: "Logon",
    AUTHENTICATION: "Kerberos / NTLM",
    ACCOUNT: "Accounts",
    GROUP: "Groups",
    PROCESS: "Processes",
    SERVICE: "Services",
    SCHEDULED_TASK: "Scheduled tasks",
    AUDIT_POLICY: "Audit policy",
    CREDENTIALS: "Credentials & keys",
    PRIVILEGE_USE: "Privilege use",
    OBJECT_ACCESS: "Object access",
    NETWORK: "Network & firewall",
    SYSTEM: "System integrity",
    FILE: "Files",
    REGISTRY: "Registry",
    WMI: "WMI",
    OTHER: "Other",
};
const LOGON_TYPE_NAMES = {
    "0": "System",
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RDP",
    "11": "CachedInteractive",
};
export function getLogonTypeName(logonType) {
    return LOGON_TYPE_NAMES[logonType] ?? `Type ${logonType}`;
}
export function getCatalogCoverage() {
    const groups = new Map();
    const all = [...Object.entries(SECURITY_EVENTS), ...Object.entries(EVENTLOG_EVENTS)];
    for (const [eventId, info] of all) {
        const items = groups.get(info.category) ?? [];
        items.push(`${eventId} — ${info.description}`);
        groups.set(info.category, items);
    }
    const order = Object.keys(CATEGORY_LABELS);
    const securityGroups = [...groups].sort((a, b) => order.indexOf(a[0]) - order.indexOf(b[0])).map(([category, items]) => ({
        title: CATEGORY_LABELS[category],
        items: items.sort(),
    }));
    const sysmonItems = Object.entries(SYSMON_EVENTS).map(([eventId, info]) => `Sysmon ${eventId} — ${info.description}`);
    const defenderItems = Object.entries(DEFENDER_EVENTS).map(([eventId, info]) => `Defender ${eventId} — ${info.description}`);
    return [...securityGroups, { title: "Sysmon", items: sysmonItems }, { title: "Microsoft Defender Antivirus", items: defenderItems }];
}
export function countCatalogedEvents() {
    return Object.keys(SECURITY_EVENTS).length + Object.keys(EVENTLOG_EVENTS).length + Object.keys(SYSMON_EVENTS).length + Object.keys(DEFENDER_EVENTS).length;
}
