import type { AuditResult, SecurityCategory } from "./types.js";
import { SECURITY_PROVIDER, getLogonTypeName, getWindowsEventDescription } from "./windowsEventCatalog.js";
import {
    SERVICE_ACCOUNT_SIDS,
    findReplicationRights,
    getEncryptionInfo,
    getKerberosResultMeaning,
    getNtStatusMeaning,
    getPercentCodeListMeaning,
    getPercentCodeMeaning,
    getPrivilegeInfo,
    getProtocolName,
    getSidMeaning,
} from "./windowsCodes.js";

export interface EventFacts {
    eventId: string;
    provider: string;
    auditResult: AuditResult;
    category: SecurityCategory;
    data: ReadonlyMap<string, string>;
}

function field(facts: EventFacts, name: string): string | null {
    const value = facts.data.get(name);

    if (value === undefined || value === "" || value === "-") {
        return null;
    }

    return value;
}

function fileName(path: string | null): string | null {
    if (path === null) {
        return null;
    }

    return path.split(/[\\/]/).pop() ?? path;
}

export function normalizeIp(ip: string): string {
    return ip.toLowerCase().startsWith("::ffff:") ? ip.slice(7) : ip;
}

function statusMeaning(code: string): string | null {
    return getNtStatusMeaning(code) ?? getKerberosResultMeaning(code);
}

function memberName(facts: EventFacts): string {
    const name = field(facts, "MemberName");

    if (name !== null) {
        const match = /^CN=([^,]+)/i.exec(name);
        return match ? match[1] : name;
    }

    return field(facts, "MemberSid") ?? "an account";
}

function shortUser(name: string | null): string | null {
    return name === null ? null : name.split("@")[0];
}

function isLocalAddress(ip: string): boolean {
    return ip === "127.0.0.1" || ip === "::1";
}

function failureReason(facts: EventFacts): string | null {
    for (const name of ["SubStatus", "Status"]) {
        const code = field(facts, name);

        if (code !== null && code !== "0x0") {
            return getNtStatusMeaning(code) ?? code;
        }
    }

    const reason = field(facts, "FailureReason");
    return reason === null ? null : getPercentCodeMeaning(reason) ?? reason;
}

export function parsePrivilegeList(value: string): string[] {
    return value.split(/\s+/).filter(item => item !== "");
}

export function summarizeEvent(facts: EventFacts): string {
    const subject = field(facts, "SubjectUserName");
    const target = field(facts, "TargetUserName");
    const rawIp = field(facts, "IpAddress");
    const ip = rawIp === null ? null : normalizeIp(rawIp);
    const logonTypeCode = field(facts, "LogonType");
    const logonType = logonTypeCode === null ? null : getLogonTypeName(logonTypeCode);

    const fromIp = ip !== null && !isLocalAddress(ip) ? ` from ${ip}` : "";
    const viaType = logonType !== null ? ` (${logonType})` : "";

    const fallback = getWindowsEventDescription(facts.provider, facts.eventId) +
        (subject !== null ? ` — by ${subject}` : "");

    if (facts.eventId === "1102" && facts.provider !== SECURITY_PROVIDER) {
        return `${subject ?? "Someone"} cleared the Security log — previous events were erased`;
    }

    if (facts.eventId === "1100" && facts.provider !== SECURITY_PROVIDER) {
        return "Event logging service stopped — events after this moment are not recorded until restart";
    }

    if (facts.provider !== SECURITY_PROVIDER) {
        return fallback;
    }

    switch (facts.eventId) {
        case "4624":
            return `${target ?? "Unknown account"} logged on${viaType}${fromIp}`;

        case "4625": {
            const reason = failureReason(facts);
            return `${target ?? "Unknown account"} failed to log on${viaType}${fromIp}` +
                (reason !== null ? `: ${reason}` : "");
        }

        case "4634":
            return `${target ?? "Unknown account"} logged off${viaType}`;

        case "4647":
            return `${target ?? "Unknown account"} signed out`;

        case "4648": {
            const server = field(facts, "TargetServerName");
            const process = fileName(field(facts, "ProcessName"));
            return `${subject ?? "Someone"} used the credentials of ${target ?? "another account"}` +
                (server !== null ? ` to access ${server}` : "") +
                (process !== null ? ` (via ${process})` : "");
        }

        case "4672": {
            const list = field(facts, "PrivilegeList");
            const privileges = list === null ? [] : parsePrivilegeList(list);
            const riskyCount = privileges.filter(p => getPrivilegeInfo(p)?.risky).length;
            return `${subject ?? "An account"} logged on with administrator-level rights` +
                ` (${privileges.length} special privileges, ${riskyCount} high-risk)`;
        }

        case "4688": {
            const process = fileName(field(facts, "NewProcessName"));
            const parent = fileName(field(facts, "ParentProcessName"));
            return `${subject ?? "Someone"} started ${process ?? "a process"}` +
                (parent !== null ? ` (launched by ${parent})` : "");
        }

        case "4689":
            return `Process ${fileName(field(facts, "ProcessName")) ?? ""} ended (user: ${subject ?? "unknown"})`;

        case "4697":
            return `${subject ?? "Someone"} installed service "${field(facts, "ServiceName") ?? "unknown"}"` +
                ` → ${field(facts, "ServiceFileName") ?? "unknown file"}`;

        case "4698":
        case "4699":
        case "4700":
        case "4701":
        case "4702": {
            const verbs: Record<string, string> = {
                "4698": "created", "4699": "deleted", "4700": "enabled", "4701": "disabled", "4702": "modified",
            };
            return `${subject ?? "Someone"} ${verbs[facts.eventId]} scheduled task ${field(facts, "TaskName") ?? ""}`;
        }

        case "4720":
            return `${subject ?? "Someone"} created a new user account: ${target ?? "unknown"}`;
        case "4722":
            return `${subject ?? "Someone"} enabled account ${target ?? "unknown"}`;
        case "4723":
            return `${subject ?? "Someone"} tried to change the password of ${target ?? "unknown"}`;
        case "4724":
            return `${subject ?? "Someone"} tried to reset the password of ${target ?? "unknown"}`;
        case "4725":
            return `${subject ?? "Someone"} disabled account ${target ?? "unknown"}`;
        case "4726":
            return `${subject ?? "Someone"} deleted account ${target ?? "unknown"}`;
        case "4738":
            return `${subject ?? "Someone"} changed account ${target ?? "unknown"}`;
        case "4740":

            return `Account ${target ?? "unknown"} was locked out after too many failed logons` +
                (field(facts, "TargetDomainName") !== null ? ` (source computer: ${field(facts, "TargetDomainName")})` : "");
        case "4767":
            return `${subject ?? "Someone"} unlocked account ${target ?? "unknown"}`;
        case "4781":
            return `${subject ?? "Someone"} renamed account ${field(facts, "OldTargetUserName") ?? "?"} → ${field(facts, "NewTargetUserName") ?? "?"}`;

        case "4728":
        case "4732":
        case "4729":
        case "4733": {
            const added = facts.eventId === "4728" || facts.eventId === "4732";

            const member = memberName(facts);
            return `${subject ?? "Someone"} ${added ? "added" : "removed"} ${member} ${added ? "to" : "from"} group ${target ?? "unknown"}`;
        }

        case "4798":
            return `${fileName(field(facts, "CallerProcessName")) ?? subject ?? "A program"} listed the groups of user ${target ?? "unknown"}`;
        case "4799":
            return `${fileName(field(facts, "CallerProcessName")) ?? subject ?? "A program"} listed the members of group ${target ?? "unknown"}`;

        case "5379":
            return `${subject ?? "A program"} read saved credentials from Credential Manager`;

        case "4616":
            return `${subject ?? "Someone"} changed the system time: ${field(facts, "PreviousTime") ?? "?"} → ${field(facts, "NewTime") ?? "?"}`;

        case "4719":
            return `${subject ?? "Someone"} changed the system audit policy`;
        case "4907":
            return `${subject ?? "Someone"} changed audit settings of ${field(facts, "ObjectName") ?? "an object"}`;

        case "4778":
            return `${field(facts, "AccountName") ?? "User"} reconnected to a session from ${field(facts, "ClientName") ?? "?"} (${field(facts, "ClientAddress") ?? "?"})`;
        case "4779":
            return `${field(facts, "AccountName") ?? "User"} disconnected from a session (${field(facts, "ClientAddress") ?? "?"})`;
        case "4964":
            return `${target ?? "An account"} logged on as a member of a monitored special group`;
        case "4825":
            return `${field(facts, "AccountName") ?? "User"} was denied Remote Desktop access from ${field(facts, "ClientAddress") ?? "?"} (not a member of Remote Desktop Users)`;

        case "4768": {
            const result = field(facts, "Status");
            const ok = result === null || result === "0x0";
            return ok
                ? `${target ?? "Account"} received a Kerberos logon ticket${fromIp}`
                : `Kerberos logon ticket for ${target ?? "account"} refused${fromIp}: ${statusMeaning(result) ?? result}`;
        }
        case "4769": {
            const enc = field(facts, "TicketEncryptionType");
            const encInfo = enc === null ? null : getEncryptionInfo(enc);
            return `${shortUser(target) ?? "Account"} requested a ticket for service ${field(facts, "ServiceName") ?? "?"}${fromIp}` +
                (encInfo?.weak ? ` — weak encryption ${encInfo.name}` : "");
        }
        case "4770":
            return `${shortUser(target) ?? "Account"} renewed a ticket for service ${field(facts, "ServiceName") ?? "?"}`;
        case "4771": {
            const result = field(facts, "Status");
            return `Kerberos logon failed for ${target ?? "account"}${fromIp}` +
                (result !== null ? `: ${statusMeaning(result) ?? result}` : "");
        }
        case "4776": {
            const result = field(facts, "Status");
            const ok = result === null || result === "0x0";
            const station = field(facts, "Workstation");
            return `NTLM password check for ${target ?? "account"}` +
                (station !== null ? ` from computer ${station}` : "") +
                (ok ? ": success" : `: ${statusMeaning(result) ?? result}`);
        }

        case "4741":
            return `${subject ?? "Someone"} created computer account ${target ?? "unknown"}`;
        case "4742":
            return `${subject ?? "Someone"} changed computer account ${target ?? "unknown"}`;
        case "4743":
            return `${subject ?? "Someone"} deleted computer account ${target ?? "unknown"}`;
        case "4794":
            return `${subject ?? "Someone"} set the Directory Services Restore Mode (DSRM) password`;
        case "4765":
            return `SID History was added to account ${target ?? "unknown"} — it may gain rights of another account`;
        case "4727":
        case "4731":
            return `${subject ?? "Someone"} created security group ${target ?? "unknown"}`;
        case "4735":
        case "4737":
            return `${subject ?? "Someone"} changed security group ${target ?? "unknown"}`;
        case "4756":
        case "4757": {
            const added = facts.eventId === "4756";
            const member = memberName(facts);
            return `${subject ?? "Someone"} ${added ? "added" : "removed"} ${member} ${added ? "to" : "from"} group ${target ?? "unknown"}`;
        }
        case "4662": {
            const rights = findReplicationRights(field(facts, "Properties") ?? "");
            return rights.length > 0
                ? `${subject ?? "Someone"} requested directory replication (${rights.join(", ")}) — possible DCSync attack if this is not a domain controller`
                : `${subject ?? "Someone"} performed an operation on AD object ${field(facts, "ObjectName") ?? ""}`;
        }
        case "5136":
            return `${subject ?? "Someone"} modified AD object ${field(facts, "ObjectDN") ?? ""} (attribute ${field(facts, "AttributeLDAPDisplayName") ?? "?"})`;

        case "4673":
        case "4674": {
            const process = fileName(field(facts, "ProcessName"));
            const list = field(facts, "PrivilegeList");
            const verb = facts.auditResult === "FAILURE" ? "tried to use" : "used";
            return `${process ?? subject ?? "A program"} ${verb} privilege ${list === null ? "?" : parsePrivilegeList(list).join(", ")}` +
                (facts.auditResult === "FAILURE" ? " but does not have it" : "");
        }

        case "4656":
        case "4663": {
            const object = field(facts, "ObjectName") ?? "an object";
            const accesses = field(facts, "AccessList") ?? field(facts, "Accesses");
            const what = accesses === null ? "" : ` (${getPercentCodeListMeaning(accesses) ?? accesses})`;
            const process = fileName(field(facts, "ProcessName"));
            const denied = facts.auditResult === "FAILURE";
            return `${subject ?? "Someone"} ${denied ? "was DENIED access to" : "accessed"} ${object}${what}` +
                (process !== null ? ` via ${process}` : "");
        }
        case "4660":
            return `${subject ?? "Someone"} deleted an object (via ${fileName(field(facts, "ProcessName")) ?? "?"})`;
        case "4670":
            return `${subject ?? "Someone"} changed permissions of ${field(facts, "ObjectName") ?? "an object"}`;
        case "4657":
            return `${subject ?? "Someone"} set registry value ${field(facts, "ObjectName") ?? ""}\\${field(facts, "ObjectValueName") ?? ""} = ${field(facts, "NewValue") ?? "?"}`;
        case "5140":
            return `${subject ?? "Someone"} opened network share ${field(facts, "ShareName") ?? "?"}` +
                (field(facts, "IpAddress") !== null ? ` from ${normalizeIp(field(facts, "IpAddress") ?? "")}` : "");
        case "5145":
            return `${subject ?? "Someone"} accessed ${field(facts, "RelativeTargetName") ?? "a file"} on share ${field(facts, "ShareName") ?? "?"}`;

        case "5156":
        case "5157": {
            const app = fileName(field(facts, "Application"));
            const direction = getPercentCodeMeaning(field(facts, "Direction") ?? "") ?? "";
            const protocol = getProtocolName(field(facts, "Protocol") ?? "") ?? "";
            const verb = facts.eventId === "5156" ? "allowed" : "BLOCKED";
            return `Firewall ${verb} ${direction.toLowerCase()} ${protocol} connection ` +
                `${field(facts, "SourceAddress") ?? "?"}:${field(facts, "SourcePort") ?? "?"} → ` +
                `${field(facts, "DestAddress") ?? "?"}:${field(facts, "DestPort") ?? "?"}` +
                (app !== null ? ` (${app})` : "");
        }
        case "4946":
            return `Firewall rule added: "${field(facts, "RuleName") ?? "?"}"`;
        case "4947":
            return `Firewall rule modified: "${field(facts, "RuleName") ?? "?"}"`;
        case "4948":
            return `Firewall rule deleted: "${field(facts, "RuleName") ?? "?"}"`;

        case "4608":
            return "Windows started — audit logging begins";
        case "4609":
            return "Windows is shutting down";
        case "4826":
            return "Boot configuration loaded" +
                (field(facts, "KernelDebug") === "%%1842" ? " — kernel debugging is ON" : "");
        case "6416":
            return `New device connected: ${field(facts, "DeviceDescription") ?? field(facts, "DeviceId") ?? "unknown device"}`;
        case "5058":
        case "5061":
            return `${subject ?? "A program"} performed a cryptographic key operation (${field(facts, "KeyName") ?? "key"})`;

        case "4800":
            return `${target ?? "User"} locked the workstation`;
        case "4801":
            return `${target ?? "User"} unlocked the workstation`;

        default:
            return fallback;
    }
}

export function explainField(name: string, value: string): string | null {
    if (value === "" || value === "-") {
        return null;
    }

    if (name === "LogonType") {
        return getLogonTypeName(value);
    }

    if (name === "Status" || name === "SubStatus" || name === "FailureCode") {
        return statusMeaning(value);
    }

    if (name === "TicketEncryptionType") {
        return getEncryptionInfo(value)?.name ?? null;
    }

    if (name === "Protocol") {
        return getProtocolName(value);
    }

    if (name === "Properties") {
        const rights = findReplicationRights(value);
        return rights.length > 0 ? `Replication rights: ${rights.join(", ")}` : null;
    }

    if (/^%%\d+/.test(value.trim())) {
        return getPercentCodeListMeaning(value) ?? getPercentCodeMeaning(value);
    }

    if (/^S-1-/i.test(value)) {
        return getSidMeaning(value);
    }

    return null;
}

export function humanizeFieldName(name: string): string {
    const spaced = name.replace(/([a-z0-9])([A-Z])/g, "$1 $2");
    return spaced.charAt(0) + spaced.slice(1).toLowerCase();
}

function isServiceAccount(name: string | null, sid: string | null): boolean {
    if (sid !== null && SERVICE_ACCOUNT_SIDS.has(sid)) {
        return true;
    }

    if (name === null) {
        return false;
    }

    name = name.split("@")[0];

    return name.endsWith("$") || /^(DWM|UMFD)-\d+$/i.test(name) ||
        ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"].includes(name.toUpperCase());
}

const ROUTINE_EVENT_IDS: ReadonlySet<string> = new Set([
    "4624", "4634", "4672", "4798", "4799", "5379",
    "4768", "4769", "4770", "4776", "5058", "5061",
]);

export function isRoutineEvent(facts: EventFacts): boolean {
    if (facts.auditResult === "FAILURE") {
        return false;
    }

    if (facts.provider !== SECURITY_PROVIDER || !ROUTINE_EVENT_IDS.has(facts.eventId)) {
        return false;
    }

    const subjectName = field(facts, "SubjectUserName");
    const subjectSid = field(facts, "SubjectUserSid");
    const targetName = field(facts, "TargetUserName");
    const targetSid = field(facts, "TargetUserSid");

    const hasSubject = subjectName !== null || subjectSid !== null;
    const hasTarget = targetName !== null || targetSid !== null;

    if (!hasSubject && !hasTarget) {
        return false;
    }

    if (facts.eventId === "4624" || facts.eventId === "4634") {
        return hasTarget && isServiceAccount(targetName, targetSid);
    }

    const subjectIsService = !hasSubject || isServiceAccount(subjectName, subjectSid);
    const targetIsService = !hasTarget || isServiceAccount(targetName, targetSid);

    return subjectIsService && targetIsService;
}
