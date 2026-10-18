export interface PrivilegeInfo {
    name: string;
    meaning: string;
    risky: boolean;
}

const PRIVILEGES: Readonly<Record<string, PrivilegeInfo>> = {
    SeTcbPrivilege: { name: "Act as part of the operating system", meaning: "Full trust: can do almost anything the OS itself can", risky: true },
    SeDebugPrivilege: { name: "Debug programs", meaning: "Can read and modify memory of any process (used by credential dumpers like Mimikatz)", risky: true },
    SeSecurityPrivilege: { name: "Manage auditing and security log", meaning: "Can read, change and clear the Security log", risky: true },
    SeBackupPrivilege: { name: "Back up files and directories", meaning: "Can read any file, ignoring file permissions", risky: true },
    SeRestorePrivilege: { name: "Restore files and directories", meaning: "Can write any file, ignoring file permissions", risky: true },
    SeTakeOwnershipPrivilege: { name: "Take ownership of files or objects", meaning: "Can become owner of any file and then change its permissions", risky: true },
    SeLoadDriverPrivilege: { name: "Load and unload device drivers", meaning: "Can load code into the Windows kernel", risky: true },
    SeImpersonatePrivilege: { name: "Impersonate a client after authentication", meaning: "Can act on behalf of other users who connect to it", risky: true },
    SeAssignPrimaryTokenPrivilege: { name: "Replace a process level token", meaning: "Can start processes as another user", risky: true },
    SeCreateTokenPrivilege: { name: "Create a token object", meaning: "Can create any identity, including admin ones", risky: true },
    SeEnableDelegationPrivilege: { name: "Enable delegation", meaning: "Can let accounts reuse other users' credentials on other servers", risky: true },
    SeSystemEnvironmentPrivilege: { name: "Modify firmware environment values", meaning: "Can change UEFI/BIOS variables", risky: true },
    SeAuditPrivilege: { name: "Generate security audits", meaning: "Can write entries into the Security log", risky: false },
    SeChangeNotifyPrivilege: { name: "Bypass traverse checking", meaning: "Can pass through folders it has no access to (normal for everyone)", risky: false },
    SeShutdownPrivilege: { name: "Shut down the system", meaning: "Can shut down the computer", risky: false },
    SeIncreaseQuotaPrivilege: { name: "Adjust memory quotas for a process", meaning: "Can change how much memory a process may use", risky: false },
    SeSystemtimePrivilege: { name: "Change the system time", meaning: "Can change the clock (can confuse log timelines)", risky: false },
    SeCreateGlobalPrivilege: { name: "Create global objects", meaning: "Can create objects shared between user sessions", risky: false },
    SeDelegateSessionUserImpersonatePrivilege: { name: "Impersonate other users in the same session", meaning: "Can get a token of another user in the same session", risky: false },
};

export function getPrivilegeInfo(privilege: string): PrivilegeInfo | null {
    return PRIVILEGES[privilege] ?? null;
}

const NT_STATUS: Readonly<Record<string, string>> = {
    "0x0": "Success",
    "0xc000006d": "Bad user name or authentication information",
    "0xc000006a": "Wrong password",
    "0xc0000064": "User name does not exist",
    "0xc000006e": "Account restriction (e.g. blank password not allowed)",
    "0xc000006f": "Logon outside allowed hours",
    "0xc0000070": "Logon from a computer that is not allowed",
    "0xc0000071": "Password expired",
    "0xc0000072": "Account disabled",
    "0xc0000193": "Account expired",
    "0xc0000224": "User must change password at next logon",
    "0xc0000234": "Account locked out",
    "0xc000015b": "This logon type is not granted to the user",
    "0xc0000133": "Clock difference between computer and domain controller is too big",
    "0xc0000413": "Blocked by authentication firewall",
};

export function getNtStatusMeaning(code: string): string | null {
    return NT_STATUS[code.toLowerCase()] ?? null;
}

const PERCENT_CODES: Readonly<Record<string, string>> = {
    "%%1842": "Yes",
    "%%1843": "No",

    "%%1832": "Identification (can only check who the user is)",
    "%%1833": "Impersonation (can act as the user on this computer)",
    "%%1840": "Delegation (can act as the user on other computers too)",

    "%%2304": "An error occurred during logon",
    "%%2305": "The user account has expired",
    "%%2307": "Account locked out",
    "%%2308": "The user has not been granted the requested logon type on this computer",
    "%%2309": "The account's password has expired",
    "%%2310": "Account currently disabled",
    "%%2311": "Account logon time restriction violation",
    "%%2312": "User not allowed to log on at this computer",
    "%%2313": "Unknown user name or bad password",

    "%%1537": "DELETE",
    "%%1538": "READ_CONTROL (read permissions)",
    "%%1539": "WRITE_DAC (change permissions)",
    "%%1540": "WRITE_OWNER (take ownership)",
    "%%1541": "SYNCHRONIZE",
    "%%4416": "ReadData / ListDirectory",
    "%%4417": "WriteData / AddFile",
    "%%4418": "AppendData / AddSubdirectory",
    "%%4419": "ReadEA",
    "%%4420": "WriteEA",
    "%%4421": "Execute / Traverse",
    "%%4423": "ReadAttributes",
    "%%4424": "WriteAttributes",
    "%%4432": "Query key value",
    "%%4433": "Set key value",
    "%%4434": "Create sub-key",
    "%%4435": "Enumerate sub-keys",

    "%%14592": "Inbound",
    "%%14593": "Outbound",
};

export function getPercentCodeListMeaning(value: string): string | null {
    const codes = value.split(/\s+/).filter(code => code !== "");

    if (codes.length === 0 || !codes.every(code => /^%%\d+$/.test(code))) {
        return null;
    }

    if (!codes.some(code => code in PERCENT_CODES)) {
        return null;
    }

    return codes.map(code => PERCENT_CODES[code] ?? code).join(", ");
}

export function getPercentCodeMeaning(code: string): string | null {
    return PERCENT_CODES[code.trim()] ?? null;
}

const WELL_KNOWN_SIDS: Readonly<Record<string, string>> = {
    "S-1-0-0": "Nobody (NULL SID)",
    "S-1-5-7": "ANONYMOUS LOGON",
    "S-1-5-18": "SYSTEM (the operating system itself)",
    "S-1-5-19": "LOCAL SERVICE (built-in low-privilege service account)",
    "S-1-5-20": "NETWORK SERVICE (built-in service account with network access)",
    "S-1-5-32-544": "Administrators group",
    "S-1-5-32-545": "Users group",
    "S-1-5-32-555": "Remote Desktop Users group",
};

export function getSidMeaning(sid: string): string | null {
    return WELL_KNOWN_SIDS[sid.toUpperCase()] ?? null;
}

export const SERVICE_ACCOUNT_SIDS: ReadonlySet<string> = new Set(["S-1-5-18", "S-1-5-19", "S-1-5-20"]);

const KERBEROS_RESULT: Readonly<Record<string, string>> = {
    "0x0": "Success",
    "0x6": "User name does not exist",
    "0x12": "Account disabled, expired or locked out",
    "0x17": "Password expired",
    "0x18": "Wrong password (pre-authentication failed)",
    "0x1f": "Integrity check failed",
    "0x25": "Clock difference is too big",
};

export function getKerberosResultMeaning(code: string): string | null {
    return KERBEROS_RESULT[code.toLowerCase()] ?? null;
}

export interface EncryptionInfo {
    name: string;
    weak: boolean;
}

const TICKET_ENCRYPTION: Readonly<Record<string, EncryptionInfo>> = {
    "0x1": { name: "DES-CBC-CRC (obsolete, weak)", weak: true },
    "0x3": { name: "DES-CBC-MD5 (obsolete, weak)", weak: true },
    "0x11": { name: "AES128", weak: false },
    "0x12": { name: "AES256", weak: false },
    "0x17": { name: "RC4-HMAC (weak — Kerberoasting risk)", weak: true },
    "0x18": { name: "RC4-HMAC-EXP (weak)", weak: true },
};

export function getEncryptionInfo(code: string): EncryptionInfo | null {
    return TICKET_ENCRYPTION[code.toLowerCase()] ?? null;
}

const AD_REPLICATION_RIGHTS: Readonly<Record<string, string>> = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
};

export function findReplicationRights(value: string): string[] {
    const lower = value.toLowerCase();
    return Object.keys(AD_REPLICATION_RIGHTS)
        .filter(guid => lower.includes(guid))
        .map(guid => AD_REPLICATION_RIGHTS[guid]);
}

const PROTOCOLS: Readonly<Record<string, string>> = {
    "1": "ICMP",
    "6": "TCP",
    "17": "UDP",
};

export function getProtocolName(code: string): string | null {
    return PROTOCOLS[code] ?? null;
}
