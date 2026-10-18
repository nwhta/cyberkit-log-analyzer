import type { Severity } from "./types.js";
import type { EventField } from "./parserTypes.js";
import { cleanIp } from "./parseHelpers.js";

export type LinuxOutcome = "Failed" | "Blocked" | "Error" | "Success" | "Info";

export interface LinuxInsight {
    category: string;
    outcome: LinuxOutcome;
    title: string;
    ip: string | null;
    user: string | null;
    port: string | null;
    severity: Severity | null;
    noise: boolean;
    fields: EventField[];
}

type Interpreter = (message: string) => LinuxInsight | null;

const ADMIN_GROUPS = /^(?:sudo|wheel|admin|root|adm|docker|lxd)$/;
const FAILURE_WORDS = /\b(?:fail(?:ed|ure)?|denied|refused|invalid|unauthori[sz]ed|forbidden|rejected)\b/i;
const ERROR_WORDS = /\b(?:error|fatal|critical|panic|segfault|corrupt|timed? ?out)\b/i;

function insight(category: string, outcome: LinuxOutcome, title: string, extra: Partial<LinuxInsight> = {}): LinuxInsight {
    return { category, outcome, title, ip: null, user: null, port: null, severity: null, noise: false, fields: [], ...extra };
}

function ipOf(value: string | undefined): string | null {
    return value === undefined ? null : cleanIp(value);
}

const SSH_FAILED = /^Failed (password|publickey|keyboard-interactive\/pam|none|hostbased) for (invalid user )?(\S*) from (\S+) port (\d+)/;
const SSH_ACCEPTED = /^Accepted (\S+) for (\S+) from (\S+) port (\d+)/;
const SSH_INVALID = /^Invalid user (\S*) from (\S+)(?: port (\d+))?/;
const SSH_MAX_TRIES = /maximum authentication attempts exceeded for (invalid user )?(\S*) from (\S+) port (\d+)/;
const SSH_CLOSED = /^(?:Connection closed by|Disconnected from|Received disconnect from|Connection reset by)(?: (?:authenticating|invalid) user (\S*)| user (\S+))? (\S+) port (\d+)/;
const SSH_PROBE = /^(?:Did not receive identification string from|banner exchange: Connection from|kex_exchange_identification: .* from|Unable to negotiate with|Bad protocol version identification .* from|error: kex_exchange_identification: .*?) ?(\S+)(?: port (\d+))?/;
const PAM_AUTH_FAILURE = /^pam_unix\((\S+?):auth\): authentication failure;.*?(?:rhost=(\S*))?(?:\s+user=(\S+))?$/;
const PAM_SESSION = /^pam_unix\((\S+?):session\): session (opened|closed) for user (\S+?)(?:\(uid=\d+\))?(?: by .*)?$/;
const PAM_MORE_FAILURES = /^PAM (\d+) more authentication failures?;.*?rhost=(\S*)(?:\s+user=(\S+))?/;

function interpretSsh(message: string): LinuxInsight | null {
    let match = SSH_FAILED.exec(message);
    if (match) {
        const invalid = match[2] !== undefined;
        return insight("SSH", "Failed", invalid ? `SSH login failed: unknown user "${match[3]}"` : `SSH login failed for ${match[3]}`, {
            ip: ipOf(match[4]),
            user: match[3],
            port: match[5],
            fields: [
                { name: "Method", value: match[1], meaning: match[1] === "password" ? "Password login" : "Key or other method" },
                { name: "User exists", value: invalid ? "no" : "yes", meaning: invalid ? "Attackers try common names (admin, test, oracle…) to find real accounts" : null, risky: invalid },
            ],
        });
    }

    match = SSH_ACCEPTED.exec(message);
    if (match) {
        const isRoot = match[2] === "root";
        return insight("SSH", "Success", `SSH login: ${match[2]} (${match[1]})`, {
            ip: ipOf(match[3]),
            user: match[2],
            port: match[4],
            severity: isRoot || match[1] === "password" ? "WARNING" : "INFO",
            fields: [
                { name: "Method", value: match[1], meaning: match[1] === "publickey" ? "SSH key: the safest method" : "Password login: can be brute-forced, prefer SSH keys", risky: match[1] === "password" },
                ...(isRoot ? [{ name: "Root login", value: "yes", meaning: "Direct root login over SSH should usually be disabled (PermitRootLogin no)", risky: true }] : []),
            ],
        });
    }

    match = SSH_MAX_TRIES.exec(message);
    if (match) {
        return insight("SSH", "Failed", `Too many SSH attempts for ${match[2] || "a user"}`, { ip: ipOf(match[3]), user: match[2], port: match[4] });
    }

    match = SSH_INVALID.exec(message);
    if (match) {
        return insight("SSH", "Failed", `SSH: unknown user "${match[1]}"`, { ip: ipOf(match[2]), user: match[1], port: match[3] ?? null });
    }

    match = SSH_CLOSED.exec(message);
    if (match) {
        const user = match[1] ?? match[2] ?? null;
        return insight("SSH", "Info", `SSH connection closed${user ? ` (${user})` : ""}`, { ip: ipOf(match[3]), user, port: match[4] });
    }

    match = SSH_PROBE.exec(message);
    if (match && /\d/.test(match[1])) {
        return insight("SSH", "Failed", "SSH probe: connection without a real login attempt", {
            ip: ipOf(match[1]),
            port: match[2] ?? null,
            fields: [{ name: "Meaning", value: "probe", meaning: "Scanners connect only to read the SSH version banner", risky: true }],
        });
    }

    if (/^Server listening on/.test(message)) {
        return insight("Services", "Info", "SSH server started listening", { noise: true });
    }

    return null;
}

function interpretPam(message: string): LinuxInsight | null {
    let match = PAM_AUTH_FAILURE.exec(message);
    if (match) {
        const service = match[1];
        const category = service.startsWith("sshd") ? "SSH" : service.startsWith("sudo") || service.startsWith("su") ? "Sudo / su" : "Authentication";
        return insight(category, "Failed", `Wrong password (${service})${match[3] ? ` for ${match[3]}` : ""}`, { ip: ipOf(match[2] || undefined), user: match[3] ?? null });
    }

    match = PAM_MORE_FAILURES.exec(message);
    if (match) {
        return insight("SSH", "Failed", `${match[1]} more failed passwords${match[3] ? ` for ${match[3]}` : ""}`, { ip: ipOf(match[2] || undefined), user: match[3] ?? null });
    }

    match = PAM_SESSION.exec(message);
    if (match) {
        const service = match[1];
        const routine = /^(?:cron|CRON|systemd-user|crond)/.test(service);
        return insight(routine ? "Cron" : service.startsWith("ssh") ? "SSH" : service.startsWith("su") ? "Sudo / su" : "Sessions", "Info", `Session ${match[2]} for ${match[3]} (${service})`, { user: match[3], noise: routine });
    }

    return null;
}

const SUDO_LINE = /^\s*(\S+) : (?:(\d+) incorrect password attempts? ; )?(?:(user NOT in sudoers|command not allowed) ; )?(?:TTY=(\S+) ; )?PWD=(\S+) ; USER=(\S+) ; (?:COMMAND=(.*))?$/;

function interpretSudo(message: string): LinuxInsight | null {
    const match = SUDO_LINE.exec(message);

    if (match) {
        const [, user, wrongCount, notAllowed, tty, pwd, runAs, command] = match;
        const failed = wrongCount !== undefined || notAllowed !== undefined;
        const fields: EventField[] = [
            { name: "User", value: user },
            { name: "Run as", value: runAs, meaning: runAs === "root" ? "Administrator rights" : null },
            { name: "Command", value: command ?? "" },
            { name: "Folder", value: pwd },
            { name: "Terminal", value: tty ?? "" },
        ];

        if (notAllowed !== undefined) {
            fields.unshift({ name: "Refused", value: notAllowed, meaning: "This user is not allowed to use sudo. Someone may be trying to get admin rights.", risky: true });
        }

        return insight("Sudo / su", failed ? "Failed" : "Success", failed ? `sudo refused for ${user}${wrongCount ? ` (${wrongCount} wrong passwords)` : ""}` : `${user} ran as ${runAs}: ${command ?? ""}`, {
            user,
            severity: failed ? "WARNING" : "INFO",
            fields,
        });
    }

    return interpretPam(message);
}

function interpretSu(message: string): LinuxInsight | null {
    let match = /^FAILED SU \(to (\S+)\) (\S+) on (\S+)/.exec(message);
    if (match) {
        return insight("Sudo / su", "Failed", `su to ${match[1]} failed for ${match[2]}`, { user: match[2] });
    }

    match = /^(?:\(to (\S+)\) (\S+) on (\S+)|Successful su for (\S+) by (\S+))/.exec(message);
    if (match) {
        const target = match[1] ?? match[4];
        const user = match[2] ?? match[5];
        return insight("Sudo / su", "Success", `${user} switched to ${target}`, { user, severity: target === "root" ? "WARNING" : "INFO" });
    }

    return interpretPam(message);
}

function interpretAccounts(message: string): LinuxInsight | null {
    let match = /^new user: name=([^,]+), UID=(\d+)/.exec(message);
    if (match) {
        return insight("Accounts", "Success", `User created: ${match[1]}`, {
            user: match[1],
            severity: match[2] === "0" ? "CRITICAL" : "WARNING",
            fields: [{ name: "UID", value: match[2], meaning: match[2] === "0" ? "UID 0 = a second root account! Very suspicious." : "Normal user ID", risky: match[2] === "0" }],
        });
    }

    match = /^new group: name=([^,]+)/.exec(message);
    if (match) {
        return insight("Accounts", "Success", `Group created: ${match[1]}`);
    }

    match = /add '([^']+)' to (?:shadow )?group '([^']+)'/.exec(message);
    if (match) {
        const admin = ADMIN_GROUPS.test(match[2]);
        return insight("Accounts", "Success", `${match[1]} added to group ${match[2]}`, {
            user: match[1],
            severity: admin ? "WARNING" : "INFO",
            fields: admin ? [{ name: "Admin group", value: match[2], meaning: "Members of this group get administrator-level rights", risky: true }] : [],
        });
    }

    match = /^(?:delete user|removed group|delete '[^']+' from group)/.exec(message);
    if (match) {
        return insight("Accounts", "Success", message, { severity: "WARNING" });
    }

    match = /password changed for (\S+)/.exec(message);
    if (match) {
        return insight("Accounts", "Success", `Password changed for ${match[1]}`, { user: match[1] });
    }

    match = /^change user '([^']+)' (password|shell|home)/.exec(message);
    if (match) {
        return insight("Accounts", "Success", `User ${match[1]}: ${match[2]} changed`, { user: match[1] });
    }

    return interpretPam(message);
}

function parseKeyValues(text: string): Map<string, string> {
    const values = new Map<string, string>();

    for (const match of text.matchAll(/([A-Z]+)=(\S*)/g)) {
        if (!values.has(match[1])) {
            values.set(match[1], match[2]);
        }
    }

    return values;
}

function interpretFirewall(message: string): LinuxInsight | null {
    if (!/\bIN=\S* OUT=/.test(message)) {
        return null;
    }

    const prefix = /\[(UFW [A-Z ]+)\]/.exec(message)?.[1] ?? message.slice(0, message.indexOf("IN=")).replace(/^\[\s*\d+\.\d+\]\s*/, "").trim();
    const values = parseKeyValues(message);
    const blocked = /BLOCK|DROP|REJECT|DENY/i.test(prefix);
    const audit = /AUDIT/i.test(prefix) && !blocked;
    const source = values.get("SRC") ?? "?";
    const port = values.get("DPT") ?? null;
    const protocol = values.get("PROTO") ?? "";

    return insight("Firewall", blocked ? "Blocked" : "Info", `${prefix || "Firewall"}: ${source} → ${values.get("DST") ?? "?"}${port ? `:${port}` : ""} ${protocol}`, {
        ip: ipOf(source),
        port,
        severity: blocked ? "WARNING" : "INFO",
        noise: audit,
        fields: [
            { name: "Action", value: prefix, meaning: blocked ? "The firewall dropped this packet" : "The firewall let this packet through / only logged it" },
            { name: "Source IP (SRC)", value: source },
            { name: "Destination IP (DST)", value: values.get("DST") ?? "" },
            { name: "Protocol", value: protocol },
            { name: "Source port (SPT)", value: values.get("SPT") ?? "" },
            { name: "Destination port (DPT)", value: port ?? "", meaning: port ? portMeaning(port) : null },
            { name: "Interface in", value: values.get("IN") ?? "" },
            { name: "TCP flags", value: ["SYN", "ACK", "FIN", "RST", "PSH", "URG"].filter(flag => new RegExp(`\\b${flag}\\b`).test(message)).join(" "), meaning: /\bSYN\b/.test(message) && !/\bACK\b/.test(message) ? "SYN only = a new connection attempt" : null },
        ],
    });
}

const PORT_NAMES: Readonly<Record<string, string>> = {
    "21": "FTP", "22": "SSH", "23": "Telnet (old, insecure)", "25": "SMTP mail", "53": "DNS", "80": "HTTP", "110": "POP3",
    "135": "Windows RPC", "139": "NetBIOS", "143": "IMAP", "443": "HTTPS", "445": "SMB (Windows shares)", "1433": "MS SQL",
    "3306": "MySQL", "3389": "Remote Desktop", "5432": "PostgreSQL", "5900": "VNC", "6379": "Redis", "8080": "HTTP alt", "27017": "MongoDB",
};

function portMeaning(port: string): string | null {
    return PORT_NAMES[port] ? `Port ${port}: ${PORT_NAMES[port]}` : null;
}

function interpretKernel(message: string): LinuxInsight | null {
    const firewall = interpretFirewall(message);
    if (firewall !== null) {
        return firewall;
    }

    let match = /apparmor="(DENIED|ALLOWED|AUDIT|STATUS)" operation="([^"]+)"(?:.*?profile="([^"]+)")?(?:.*?name="([^"]+)")?(?:.*?comm="([^"]+)")?/.exec(message);
    if (match) {
        const denied = match[1] === "DENIED";
        return insight("Security (AppArmor / SELinux)", denied ? "Blocked" : "Info", `AppArmor ${match[1].toLowerCase()}: ${match[5] ?? "program"} → ${match[2]} ${match[4] ?? ""}`.trim(), {
            severity: denied ? "WARNING" : "INFO",
            noise: match[1] === "STATUS",
            fields: [
                { name: "Profile", value: match[3] ?? "", meaning: "AppArmor rule set for this program" },
                { name: "Operation", value: match[2] },
                { name: "Target", value: match[4] ?? "" },
                { name: "Program", value: match[5] ?? "" },
            ],
        });
    }

    match = /avc:\s+denied\s+\{ ([^}]+) \} for .*?comm="([^"]+)"/.exec(message);
    if (match) {
        return insight("Security (AppArmor / SELinux)", "Blocked", `SELinux denied ${match[1].trim()} for ${match[2]}`, { severity: "WARNING" });
    }

    match = /Out of memory: Killed process (\d+) \(([^)]+)\)/.exec(message);
    if (match) {
        return insight("Kernel", "Error", `Out of memory: killed ${match[2]} (pid ${match[1]})`, { severity: "CRITICAL" });
    }

    match = /(\S+)\[(\d+)\]: segfault at/.exec(message);
    if (match) {
        return insight("Kernel", "Error", `${match[1]} crashed (segfault)`, { severity: "ERROR" });
    }

    if (/Kernel panic|BUG: |Oops:|general protection fault|watchdog: BUG: soft lockup/.test(message)) {
        return insight("Kernel", "Error", "Kernel crash / bug", { severity: "CRITICAL" });
    }

    if (/I\/O error|EXT4-fs error|XFS .*(?:error|corruption)|Buffer I\/O error|blk_update_request: .*error|ata\d+.*failed command/.test(message)) {
        return insight("Kernel", "Error", "Disk / file system error", { severity: "ERROR" });
    }

    match = /possible SYN flooding on port (\d+)/.exec(message);
    if (match) {
        return insight("Kernel", "Error", `Possible SYN flood on port ${match[1]}`, { port: match[1], severity: "WARNING" });
    }

    if (/New USB device found|usb-storage|USB Mass Storage device detected/.test(message)) {
        return insight("Kernel", "Info", "USB device connected", { severity: "INFO" });
    }

    return null;
}

function interpretCron(message: string): LinuxInsight | null {
    let match = /^\((\S+)\) CMD \((.*)\)\s*$/.exec(message);
    if (match) {
        return insight("Cron", "Info", `Cron job (${match[1]}): ${match[2]}`, { user: match[1], fields: [{ name: "Command", value: match[2] }] });
    }

    match = /^\((\S+)\) (REPLACE|BEGIN EDIT|END EDIT|DELETE|LIST) \((\S+)\)/.exec(message);
    if (match) {
        return insight("Cron", "Success", `Crontab of ${match[3]}: ${match[2].toLowerCase()} by ${match[1]}`, {
            user: match[1],
            severity: match[2] === "REPLACE" || match[2] === "DELETE" ? "WARNING" : "INFO",
            noise: match[2] === "LIST" || match[2] === "BEGIN EDIT",
            fields: [{ name: "Why it matters", value: match[2], meaning: "Changing a crontab is a common way to make malware start again and again", risky: match[2] === "REPLACE" }],
        });
    }

    return interpretPam(message);
}

function interpretPostfix(message: string): LinuxInsight | null {
    let match = /warning: (\S+?)\[([^\]]+)\]: SASL (\S+) authentication failed/.exec(message);
    if (match) {
        return insight("Mail", "Failed", `Mail login failed (SASL ${match[3]})`, { ip: ipOf(match[2]), fields: [{ name: "Client", value: match[1] }] });
    }

    match = /NOQUEUE: reject: (\S+) from (\S+?)\[([^\]]+)\]: (\d{3}) [\d.]+ (.*?);/.exec(message);
    if (match) {
        return insight("Mail", "Blocked", `Mail rejected: ${match[5]}`, {
            ip: ipOf(match[3]),
            fields: [{ name: "Stage", value: match[1] }, { name: "Client", value: match[2] }, { name: "SMTP code", value: match[4], meaning: match[4].startsWith("5") ? "Permanent rejection" : "Temporary rejection" }],
        });
    }

    match = /to=<([^>]*)>.*?status=(sent|bounced|deferred|expired) \((.*)\)/.exec(message);
    if (match) {
        const ok = match[2] === "sent";
        return insight("Mail", ok ? "Success" : "Error", `Mail to ${match[1]}: ${match[2]}`, {
            severity: ok ? "INFO" : match[2] === "deferred" ? "WARNING" : "ERROR",
            fields: [{ name: "Details", value: match[3] }],
        });
    }

    match = /^(connect|disconnect) from (\S+?)\[([^\]]+)\]/.exec(message);
    if (match) {
        return insight("Mail", "Info", `SMTP ${match[1]} from ${match[2]}`, { ip: ipOf(match[3]), noise: true });
    }

    match = /(?:auth failed|Authentication failure|password mismatch).*?user=<([^>]*)>.*?rip=([\d.a-f:]+)/i.exec(message);
    if (match) {
        return insight("Mail", "Failed", `Mailbox login failed for ${match[1] || "unknown"}`, { ip: ipOf(match[2]), user: match[1] || null });
    }

    match = /Login: user=<([^>]*)>.*?rip=([\d.a-f:]+)/.exec(message);
    if (match) {
        return insight("Mail", "Success", `Mailbox login: ${match[1]}`, { ip: ipOf(match[2]), user: match[1] });
    }

    return null;
}

function interpretSystemd(message: string): LinuxInsight | null {
    let match = /^(?:Failed to start|(\S+): Failed with result) '?([^'.]+)'?\.?/.exec(message);
    if (match) {
        return insight("Services", "Error", `Service failed: ${match[1] ?? match[2]}`, { severity: "ERROR" });
    }

    match = /^(\S+\.service): Main process exited, code=(\S+), status=(.+)$/.exec(message);
    if (match) {
        return insight("Services", "Error", `${match[1]} exited (${match[3]})`, { severity: "ERROR" });
    }

    match = /^(\S+\.service): (?:Scheduled restart job|Start request repeated too quickly)/.exec(message);
    if (match) {
        return insight("Services", "Error", `${match[1]} keeps restarting`, { severity: "WARNING" });
    }

    match = /^(Started|Stopped|Starting|Stopping|Finished|Reached target|Listening on|Created slice|Removed slice|Mounted|Deactivated successfully) ?(.*)$/.exec(message);
    if (match) {
        return insight("Services", "Info", `${match[1]} ${match[2]}`.trim(), { noise: true });
    }

    match = /^New session (\S+) of user (\S+)\./.exec(message);
    if (match) {
        return insight("Sessions", "Info", `New session for ${match[2]}`, { user: match[2] });
    }

    match = /^(?:Removed session|Session \S+ logged out)/.exec(message);
    if (match) {
        return insight("Sessions", "Info", message, { noise: true });
    }

    return null;
}

function interpretFail2ban(message: string): LinuxInsight | null {
    const match = /(NOTICE|WARNING|INFO)\s+\[([^\]]+)\] (Ban|Unban|Restore Ban|Found|Already banned) (\S+)/.exec(message);

    if (!match) {
        return null;
    }

    const action = match[3];
    return insight("Fail2ban", action === "Ban" || action === "Restore Ban" ? "Blocked" : "Info", `fail2ban [${match[2]}]: ${action} ${match[4]}`, {
        ip: ipOf(match[4]),
        severity: action === "Ban" ? "WARNING" : "INFO",
    });
}

const INTERPRETERS: [RegExp, Interpreter][] = [
    [/^sshd(?:-session)?$|^ssh$/, interpretSsh],
    [/^sudo$/, interpretSudo],
    [/^su$/, interpretSu],
    [/^(?:useradd|userdel|usermod|groupadd|groupdel|gpasswd|passwd|chpasswd|chage|adduser|deluser)$/, interpretAccounts],
    [/^kernel$/, interpretKernel],
    [/^(?:CRON|cron|crond|anacron|crontab)$/, interpretCron],
    [/^(?:postfix\/.+|dovecot|sendmail|exim\d?)$/, interpretPostfix],
    [/^systemd(?:-logind)?$|^systemd\[|^init$/, interpretSystemd],
    [/^fail2ban/, interpretFail2ban],
    [/^(?:login|gdm-password\]?|lightdm|polkitd|systemd-user|sshd-session|vsftpd|proftpd)$/, interpretPam],
];

export function interpretLinuxMessage(program: string, message: string): LinuxInsight {
    for (const [pattern, interpret] of INTERPRETERS) {
        if (pattern.test(program)) {
            const result = interpret(message);
            if (result !== null) {
                return result;
            }
        }
    }

    const generic = interpretPam(message) ?? interpretFirewall(message);
    if (generic !== null) {
        return generic;
    }

    if (ERROR_WORDS.test(message)) {
        return insight("Other", "Error", message.slice(0, 160), { severity: "ERROR" });
    }

    if (FAILURE_WORDS.test(message)) {
        return insight("Other", "Failed", message.slice(0, 160), { severity: "WARNING" });
    }

    return insight("Other", "Info", message.slice(0, 160));
}

export function listLinuxCoverage(): { title: string; items: string[] }[] {
    return [
        { title: "SSH (sshd)", items: ["Failed and accepted logins (password / key)", "Unknown users (username guessing)", "Too many attempts, probes without login", "Root login over SSH"] },
        { title: "sudo / su", items: ["Commands run as root", "Wrong sudo passwords, users not in sudoers", "su to another user, failed su"] },
        { title: "Accounts", items: ["User / group created or deleted", "Added to admin groups (sudo, wheel, docker…)", "Password changes", "Second root account (UID 0)"] },
        { title: "Firewall (kernel)", items: ["UFW BLOCK / ALLOW / AUDIT", "iptables / nftables LOG lines (SRC, DST, ports, flags)"] },
        { title: "Kernel", items: ["Out of memory kills", "Segfaults, kernel crashes", "Disk and file system errors", "SYN flood warnings", "USB devices", "AppArmor / SELinux denials"] },
        { title: "Cron", items: ["Cron jobs that ran", "Crontab edited or replaced"] },
        { title: "Mail (Postfix, Dovecot)", items: ["SASL / mailbox login failures", "Rejected senders", "Delivery status: sent, deferred, bounced"] },
        { title: "Services (systemd)", items: ["Services that failed or keep restarting", "Logins and sessions"] },
        { title: "Fail2ban", items: ["Bans and unbans written to syslog"] },
    ];
}
