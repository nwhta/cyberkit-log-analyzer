import { SYSMON_EVENTS } from "./sysmonCatalog.js";
const COMMAND_RULES = [
    { name: "Encoded PowerShell", reason: "PowerShell runs a base64-encoded command, a common way to hide what a script does.", pattern: /powershell[^\n]*\s-(?:e|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+/=]{16,}/i },
    { name: "Download and run", reason: "The command downloads something from the internet and runs it in memory.", pattern: /(?:downloadstring|downloadfile|invoke-webrequest|iwr\s|invoke-restmethod|irm\s|net\.webclient|start-bitstransfer)[^\n]*(?:http|ftp)|(?:iex|invoke-expression)\s*\(/i },
    { name: "LOLBin download", reason: "A built-in Windows tool is misused to download or run remote code (living off the land).", pattern: /certutil[^\n]*-urlcache|bitsadmin[^\n]*\/transfer|mshta[^\n]*https?:|regsvr32[^\n]*\/i:https?:|rundll32[^\n]*javascript:/i },
    { name: "Shadow copy deletion", reason: "Deleting volume shadow copies stops file recovery. Ransomware does this right before encrypting.", pattern: /vssadmin[^\n]*delete\s+shadows|wmic[^\n]*shadowcopy\s+delete|wbadmin[^\n]*delete\s+catalog|bcdedit[^\n]*recoveryenabled\s+no/i },
    { name: "Log clearing", reason: "Clearing event logs hides an attacker's tracks.", pattern: /wevtutil[^\n]*\s(?:cl|clear-log)\s|clear-eventlog/i },
    { name: "Credential dumping tool", reason: "Known tool or technique for stealing passwords from memory.", pattern: /mimikatz|sekurlsa|procdump[^\n]*lsass|comsvcs(?:\.dll)?[^\n]*minidump|lsass\.dmp/i },
    { name: "New local user", reason: "A user account is created from the command line.", pattern: /net1?\s+user\s+\S+\s+\S*\s*\/add/i },
    { name: "Admin group change", reason: "Someone is added to the Administrators group from the command line.", pattern: /net1?\s+localgroup\s+administrators\s+\S+\s+\/add/i },
    { name: "Defender disabled", reason: "Microsoft Defender protection is being turned off.", pattern: /set-mppreference[^\n]*-disable|add-mppreference[^\n]*-exclusion/i },
];
const OFFICE_PARENT = /\\(?:winword|excel|powerpnt|outlook|onenote|msaccess|mspub)\.exe$/i;
const SHELL_CHILD = /\\(?:cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)\.exe$/i;
const SCRIPT_HOSTS = /\\(?:powershell|pwsh|rundll32|regsvr32|mshta|certutil|wscript|cscript|bitsadmin)\.exe$/i;
const SUSPICIOUS_FOLDER = /\\(?:Users\\Public|AppData\\Local\\Temp|Windows\\Temp|ProgramData|PerfLogs)\\/i;
const EXECUTABLE_FILE = /\.(?:exe|dll|scr|ps1|bat|cmd|vbs|js|hta|lnk|msi)$/i;
const STARTUP_FOLDER = /\\Start Menu\\Programs\\Startup\\/i;
const PERSISTENCE_KEYS = /\\CurrentVersion\\(?:Run|RunOnce|RunServices|Policies\\Explorer\\Run)\b|\\Winlogon\\(?:Shell|Userinit|Notify)|\\Image File Execution Options\\[^\\]+\\Debugger|\\Services\\[^\\]+\\ImagePath|\\Environment\\UserInitMprLogonScript/i;
const SUSPICIOUS_PORTS = new Set(["4444", "1337", "31337", "6666", "6667", "6668", "6669", "8888", "9001", "50050"]);
const LSASS_RIGHTS = /0x(?:1010|1410|1438|143a|1fffff|1f3fff|40)$/i;
const ACCESS_RIGHTS = {
    "0x1000": "Query limited information (harmless, very common)",
    "0x1010": "Query limited information + read memory: typical for credential dumping from LSASS",
    "0x1410": "Query information + read memory: typical for credential dumping from LSASS",
    "0x1438": "Read and write memory: used by Mimikatz-like tools",
    "0x143a": "Read/write memory + create threads: used by Mimikatz-like tools",
    "0x1fffff": "Full access to the process",
    "0x40": "Duplicate handle: used by some credential dumping tools",
};
const FIELD_MEANINGS = {
    Image: "Program that did this",
    ParentImage: "Program that started it",
    CommandLine: "Full command, including arguments",
    ParentCommandLine: "Command of the parent program",
    IntegrityLevel: "High or System means administrator rights",
    Hashes: "Fingerprints of the file. Search them on VirusTotal to check if it is known malware",
    LogonId: "Session ID. Links this to a logon event (4624) with the same ID",
    ProcessGuid: "Unique process ID. Use it to find every event of the same process",
    ParentProcessGuid: "Unique ID of the parent process",
    SourceImage: "Program that opened or injected into another process",
    TargetImage: "Program that was opened or injected into",
    TargetFilename: "File that was created, changed or deleted",
    TargetObject: "Registry key or value",
    Details: "New registry value",
    QueryName: "Domain name that was looked up",
    QueryResults: "Answer: IP addresses returned",
    DestinationIp: "Remote IP address",
    DestinationPort: "Remote port",
    DestinationHostname: "Remote host name",
    Initiated: "true = this computer started the connection",
    ImageLoaded: "Driver or DLL that was loaded",
    Signed: "false = not digitally signed by its vendor",
    SignatureStatus: "Valid = the signature checks out",
    PipeName: "Named pipe: a channel processes use to talk to each other",
    RuleName: "Name of the Sysmon rule that matched",
    User: "Account that ran the program",
    StartAddress: "Memory address where the injected code starts",
    CallTrace: "Code path that opened the process",
};
function field(facts, name) {
    const value = facts.data.get(name);
    return value === undefined || value === "" || value === "-" ? null : value;
}
function fileName(path) {
    if (path === null) {
        return "unknown program";
    }
    return path.split("\\").pop() ?? path;
}
function short(text, max = 140) {
    return text.length > max ? text.slice(0, max) + "…" : text;
}
function isPublicIp(ip) {
    return !/^(?:10\.|127\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|::1$|fe80:|fc|fd)/i.test(ip);
}
export function summarizeSysmon(facts) {
    const image = fileName(field(facts, "Image"));
    const user = field(facts, "User");
    const by = user !== null ? ` as ${user}` : "";
    switch (facts.eventId) {
        case "1":
            return `${image} started by ${fileName(field(facts, "ParentImage"))}${by}: ${short(field(facts, "CommandLine") ?? "")}`;
        case "3": {
            const target = field(facts, "DestinationHostname") ?? field(facts, "DestinationIp") ?? "?";
            return `${image} connected to ${target}:${field(facts, "DestinationPort") ?? "?"} (${field(facts, "Protocol") ?? "tcp"})`;
        }
        case "5":
            return `${image} exited`;
        case "6":
            return `Driver ${fileName(field(facts, "ImageLoaded"))} loaded · signed: ${field(facts, "Signed") ?? "?"}`;
        case "7":
            return `${image} loaded ${fileName(field(facts, "ImageLoaded"))}`;
        case "8":
            return `${fileName(field(facts, "SourceImage"))} started a thread inside ${fileName(field(facts, "TargetImage"))}`;
        case "10":
            return `${fileName(field(facts, "SourceImage"))} opened ${fileName(field(facts, "TargetImage"))} (access ${field(facts, "GrantedAccess") ?? "?"})`;
        case "11":
        case "23":
        case "26":
        case "27":
        case "28":
        case "29":
        case "2":
        case "15":
            return `${image}: ${field(facts, "TargetFilename") ?? "file"}`;
        case "12":
        case "13":
        case "14":
            return `${image}: ${field(facts, "EventType") ?? "change"} ${short(field(facts, "TargetObject") ?? "", 120)}${field(facts, "Details") ? ` = ${short(field(facts, "Details"), 80)}` : ""}`;
        case "17":
        case "18":
            return `${image}: pipe ${field(facts, "PipeName") ?? "?"}`;
        case "19":
        case "20":
        case "21":
            return `WMI ${field(facts, "Operation") ?? "change"}: ${short(field(facts, "Name") ?? field(facts, "Consumer") ?? field(facts, "Destination") ?? field(facts, "Query") ?? "", 120)}`;
        case "22":
            return `${image} looked up ${field(facts, "QueryName") ?? "?"} → ${short(field(facts, "QueryResults") ?? "no answer", 80)}`;
        case "24":
            return `${image} changed the clipboard${by}`;
        case "25":
            return `${image}: ${field(facts, "Type") ?? "image changed in memory"}`;
        case "4":
            return `Sysmon service is now ${field(facts, "State") ?? "?"}`;
        case "16":
            return `Sysmon configuration changed: ${field(facts, "Configuration") ?? ""}`;
        default:
            return SYSMON_EVENTS[facts.eventId]?.description ?? `Sysmon event ${facts.eventId}`;
    }
}
export function sysmonAlert(facts) {
    const image = field(facts, "Image") ?? "";
    const commandLine = field(facts, "CommandLine") ?? "";
    switch (facts.eventId) {
        case "1": {
            const rule = COMMAND_RULES.find(item => item.pattern.test(commandLine));
            if (rule !== undefined) {
                return { name: rule.name, reason: rule.reason };
            }
            if (OFFICE_PARENT.test(field(facts, "ParentImage") ?? "") && SHELL_CHILD.test(image)) {
                return { name: "Office spawned a shell", reason: "A Word/Excel/Outlook document started a command shell or script host. Classic sign of a malicious macro." };
            }
            if (SUSPICIOUS_FOLDER.test(image)) {
                return { name: "Runs from unusual folder", reason: "The program runs from a temporary or public folder, where normal software is rarely installed." };
            }
            return null;
        }
        case "3": {
            const port = field(facts, "DestinationPort") ?? "";
            const ip = field(facts, "DestinationIp") ?? "";
            if (SUSPICIOUS_PORTS.has(port)) {
                return { name: "Connection to suspicious port", reason: `Port ${port} is a default port of hacking tools and remote shells.` };
            }
            if (SCRIPT_HOSTS.test(image) && field(facts, "Initiated") === "true" && isPublicIp(ip)) {
                return { name: "Script host talks to internet", reason: "A scripting tool (PowerShell, rundll32, mshta…) connected to the internet. Often used to download malware or reach a command server." };
            }
            return null;
        }
        case "4":
            return (field(facts, "State") ?? "").toLowerCase() === "stopped"
                ? { name: "Sysmon stopped", reason: "Monitoring was turned off. Attackers stop Sysmon to work unseen." }
                : null;
        case "6":
            return field(facts, "Signed") === "false" || (field(facts, "SignatureStatus") ?? "Valid") !== "Valid"
                ? { name: "Unsigned driver", reason: "A kernel driver without a valid signature was loaded. Rootkits work this way." }
                : null;
        case "8":
            return { name: "Code injection", reason: "One process started code inside another. Malware uses this to hide inside trusted programs." };
        case "10":
            return /\\lsass\.exe$/i.test(field(facts, "TargetImage") ?? "") && LSASS_RIGHTS.test(field(facts, "GrantedAccess") ?? "")
                ? { name: "LSASS memory access", reason: "A program read the memory of LSASS, the process that holds Windows passwords. Typical for credential dumping." }
                : null;
        case "11": {
            const target = field(facts, "TargetFilename") ?? "";
            if (STARTUP_FOLDER.test(target)) {
                return { name: "Startup folder persistence", reason: "A file was put into the Startup folder, so it runs at every logon." };
            }
            return SUSPICIOUS_FOLDER.test(target) && EXECUTABLE_FILE.test(target)
                ? { name: "Executable dropped", reason: "A program or script was written into a temporary or public folder." }
                : null;
        }
        case "12":
        case "13":
        case "14":
            return PERSISTENCE_KEYS.test(field(facts, "TargetObject") ?? "")
                ? { name: "Registry persistence", reason: "This registry location makes a program start automatically (Run key, Winlogon, IFEO debugger or service path)." }
                : null;
        case "15":
            return /Zone\.Identifier$/i.test(field(facts, "TargetFilename") ?? "")
                ? null
                : { name: "Hidden data stream", reason: "Data was hidden in an alternate data stream of a file." };
        case "16":
            return { name: "Sysmon config changed", reason: "The monitoring rules were changed. Check that nobody weakened them." };
        case "19":
        case "20":
        case "21":
            return { name: "WMI persistence", reason: "WMI subscriptions can run code on events (logon, timer). Rare in normal use, popular for hidden persistence." };
        case "22": {
            const query = field(facts, "QueryName") ?? "";
            if (query.length > 60) {
                return { name: "Possible DNS tunneling", reason: "Very long DNS name. Data can be smuggled out inside DNS queries." };
            }
            return SCRIPT_HOSTS.test(image)
                ? { name: "Script host DNS lookup", reason: "A scripting tool looked up a domain. Often the first step of downloading malware." }
                : null;
        }
        case "25":
            return { name: "Process tampering", reason: "The program in memory does not match the file on disk (process hollowing / herpaderping)." };
        case "27":
        case "28":
            return { name: "Blocked by Sysmon", reason: "Sysmon stopped this action because of a blocking rule." };
        default:
            return null;
    }
}
export function explainSysmonField(name, value) {
    if (name === "GrantedAccess") {
        return ACCESS_RIGHTS[value.toLowerCase()] ?? "Access rights requested to the other process";
    }
    if (name === "IntegrityLevel") {
        return value === "High" || value === "System" ? "Administrator / system rights" : "Normal user rights";
    }
    return FIELD_MEANINGS[name] ?? null;
}
