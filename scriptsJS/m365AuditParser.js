import { readJsonLines } from "./jsonRecords.js";
import { buildCloudEvent, CLOUD_SOURCE_PANEL, cloudFacets } from "./cloudEvents.js";
import { csvRecords, prettyJson, readJsonDocument, text } from "./structured.js";
const OPERATION_MEANINGS = {
    UserLoggedIn: "User signed in",
    UserLoginFailed: "Sign-in failed",
    "New-InboxRule": "Inbox rule created",
    "Set-InboxRule": "Inbox rule changed",
    UpdateInboxRules: "Inbox rules changed (from Outlook)",
    "Set-Mailbox": "Mailbox settings changed",
    "Add-MailboxPermission": "Mailbox access given to someone else",
    "Add-RecipientPermission": "\"Send as\" permission given",
    "Add-MailboxFolderPermission": "Folder access given to someone else",
    "New-TransportRule": "Mail flow (transport) rule created",
    "Set-TransportRule": "Mail flow (transport) rule changed",
    "New-ManagementRoleAssignment": "Exchange admin role assigned",
    "Add member to role.": "User added to an admin role",
    "Consent to application.": "Permission granted to an application",
    "Add service principal credentials.": "New secret or certificate added to an app",
    "Add application.": "Application registered",
    "Reset user password.": "Password reset by an admin",
    "Change user password.": "User changed their password",
    "Disable Strong Authentication.": "MFA turned off for a user",
    "Update user.": "User account changed",
    "Set-AdminAuditLogConfig": "Audit log settings changed",
    "Set-CASMailbox": "Mail protocols (IMAP/POP/ActiveSync) settings changed",
    MailItemsAccessed: "Mail items read",
    Send: "Email sent",
    SendAs: "Email sent as another user",
    SendOnBehalf: "Email sent on behalf of another user",
    HardDelete: "Email permanently deleted",
    SoftDelete: "Email deleted",
    MoveToDeletedItems: "Email moved to Deleted Items",
    FileAccessed: "File opened",
    FileDownloaded: "File downloaded",
    FileSyncDownloadedFull: "Files synced to a computer",
    FileUploaded: "File uploaded",
    FileDeleted: "File deleted",
    AnonymousLinkCreated: "Anyone-with-the-link sharing created",
    SharingInvitationCreated: "File shared with someone",
    SearchExported: "eDiscovery search exported",
    SearchExportDownloaded: "eDiscovery export downloaded",
};
const SUSPICIOUS_RULE_WORDS = /invoice|payment|wire|transfer|password|bank|urgent|ceo|hacked|phish|security/i;
function parameters(audit) {
    const result = new Map();
    const list = audit.Parameters;
    if (Array.isArray(list)) {
        for (const item of list) {
            if (item !== null && typeof item === "object") {
                result.set(String(item.Name ?? ""), String(item.Value ?? ""));
            }
        }
    }
    return result;
}
function modified(audit) {
    const list = audit.ModifiedProperties;
    return Array.isArray(list) ? list.map(item => `${text(item, "Name")}=${text(item, "NewValue")}`).join("; ") : "";
}
function riskOf(operation, audit) {
    const params = parameters(audit);
    const changes = modified(audit);
    if (/InboxRule/.test(operation)) {
        const forward = params.get("ForwardTo") ?? params.get("ForwardAsAttachmentTo") ?? params.get("RedirectTo");
        const hides = params.get("DeleteMessage") === "True" || /RSS|Archive|Conversation History|Junk/i.test(params.get("MoveToFolder") ?? "");
        const words = params.get("SubjectContainsWords") ?? params.get("SubjectOrBodyContainsWords") ?? params.get("BodyContainsWords") ?? "";
        if (forward) {
            return { name: "Inbox rule forwards mail", reason: `Mail is forwarded to ${forward}. A classic sign of a hacked mailbox.`, severity: "ERROR" };
        }
        if (hides || SUSPICIOUS_RULE_WORDS.test(words)) {
            return { name: "Inbox rule hides mail", reason: "The rule deletes or hides messages (often about invoices or security) so the owner does not see them.", severity: "ERROR" };
        }
        return { name: "Inbox rule created", reason: "Check that the user made this rule.", severity: "WARNING" };
    }
    if (operation === "Set-Mailbox" && (params.has("ForwardingSmtpAddress") || params.has("ForwardingAddress"))) {
        return { name: "Mailbox forwarding", reason: `All mail is forwarded to ${params.get("ForwardingSmtpAddress") ?? params.get("ForwardingAddress")}.`, severity: "ERROR" };
    }
    if (operation === "Add member to role." && /Global Administrator|Company Administrator|Privileged|Exchange Administrator|Security Administrator/i.test(changes + JSON.stringify(audit.Target ?? ""))) {
        return { name: "Admin role assigned", reason: "Someone became an administrator.", severity: "ERROR" };
    }
    if (operation === "Consent to application.") {
        return { name: "App consent", reason: "An app got access to data. Malicious apps use this (OAuth consent phishing).", severity: /IsAdminConsent.?=.?True/i.test(changes) ? "ERROR" : "WARNING" };
    }
    if (operation === "Add service principal credentials." || /Certificates and secrets/i.test(operation)) {
        return { name: "App secret added", reason: "A new secret lets the app (or an attacker) sign in without a user.", severity: "WARNING" };
    }
    if (operation === "Disable Strong Authentication." || (operation === "Update user." && /StrongAuthenticationRequirement=\[\]/.test(changes))) {
        return { name: "MFA disabled", reason: "Multi-factor authentication was turned off for a user.", severity: "ERROR" };
    }
    if (operation === "Set-AdminAuditLogConfig" && /False/i.test(params.get("UnifiedAuditLogIngestionEnabled") ?? "")) {
        return { name: "Audit log disabled", reason: "Turning off auditing hides what happens next.", severity: "CRITICAL" };
    }
    if (operation === "New-ManagementRoleAssignment" && /ApplicationImpersonation/i.test(params.get("Role") ?? "")) {
        return { name: "Impersonation role", reason: "ApplicationImpersonation lets an account read every mailbox.", severity: "ERROR" };
    }
    if (["Add-MailboxPermission", "Add-RecipientPermission", "New-TransportRule", "Set-TransportRule"].includes(operation)) {
        return { name: OPERATION_MEANINGS[operation], reason: "Changes who can read or send mail. Check that it was planned.", severity: "WARNING" };
    }
    if (operation === "AnonymousLinkCreated") {
        return { name: "Anonymous sharing link", reason: "Anyone with the link can open the file, without signing in.", severity: "WARNING" };
    }
    if (operation === "SearchExported" || operation === "SearchExportDownloaded") {
        return { name: "eDiscovery export", reason: "Large amounts of mail or files were exported.", severity: "WARNING" };
    }
    return null;
}
function auditOf(record) {
    const raw = record.AuditData ?? record.auditData;
    if (typeof raw === "string") {
        try {
            return JSON.parse(raw);
        }
        catch {
            return record;
        }
    }
    return raw !== null && typeof raw === "object" ? raw : record;
}
function toEvent(item) {
    const audit = auditOf(item.record);
    const operation = text(audit, "Operation") || text(item.record, "Operations", "Operation");
    const status = text(audit, "ResultStatus");
    const failed = operation === "UserLoginFailed" || /^(failed|false|failure)$/i.test(status);
    const time = text(audit, "CreationTime") || text(item.record, "CreationDate");
    const user = text(audit, "UserId") || text(item.record, "UserIds", "UserId");
    const ip = text(audit, "ClientIP", "ClientIPAddress", "ActorIpAddress");
    const object = text(audit, "ObjectId", "SourceFileName", "Item.Subject");
    const params = parameters(audit);
    const meaning = OPERATION_MEANINGS[operation];
    return buildCloudEvent({
        lineNumber: item.lineNumber,
        raw: typeof (item.record.AuditData) === "string" ? item.record.AuditData : item.raw,
        timeMs: Date.parse(/[zZ]|[+-]\d{2}:\d{2}$/.test(time) ? time : time + "Z"),
        timeText: time,
        operation,
        title: `${meaning ?? operation}${user ? ` · ${user}` : ""}`,
        summary: [meaning ? operation : "", object ? `object: ${object}` : "", params.size > 0 ? [...params].slice(0, 3).map(([key, value]) => `${key}=${value}`).join(", ") : "", failed ? text(audit, "LogonError") : ""].filter(Boolean).join(" · "),
        actor: user || null,
        ip: ip || null,
        result: failed ? "Failure" : status === "" ? "Unknown" : "Success",
        resultText: status || (failed ? "Failed" : "Unknown"),
        service: text(audit, "Workload") || text(item.record, "RecordType") || "Microsoft 365",
        resource: object || null,
        risk: riskOf(operation, audit),
        noise: ["FileAccessed", "MailItemsAccessed", "FilePreviewed", "PageViewed"].includes(operation),
        source: audit,
    });
}
function parse(content) {
    const document = readJsonDocument(content);
    if (document !== null) {
        return document.map(toEvent);
    }
    if (content.trimStart().startsWith("{")) {
        return readJsonLines(content, toEvent, "This line is not a valid audit record.");
    }
    const { records, lines } = csvRecords(content);
    return records.map((record, index) => toEvent({ record, raw: JSON.stringify(record), lineNumber: lines[index] }));
}
export const m365AuditParser = {
    id: "m365-audit",
    name: "Microsoft 365 audit log",
    description: "Microsoft 365 / Purview unified audit log (CSV export or JSON): Exchange, SharePoint, OneDrive, Entra ID admin actions.",
    demoFile: "/static/demo/m365-audit.csv",
    rawLabel: "Audit data",
    searchHint: "User, operation, IP, file…",
    timeNote: "Audit times are in UTC.",
    detect: sample => {
        const header = sample.split(/\r?\n/, 1)[0];
        if (/CreationDate/.test(header) && /AuditData/.test(header) && /Operation/.test(header)) {
            return 0.99;
        }
        return /"Operation"\s*:/.test(sample) && /"Workload"\s*:/.test(sample) && /"(RecordType|OrganizationId)"\s*:/.test(sample) ? 0.97 : 0;
    },
    parse,
    formatRaw: prettyJson,
    facets: cloudFacets([{ key: "operation", title: "Operation" }]),
    sourcePanel: CLOUD_SOURCE_PANEL,
    noise: { label: "File views and mail reads", hint: "FileAccessed and MailItemsAccessed are very frequent. Click to show them." },
    coverage: () => ({
        summary: "Every audit record is shown with its full AuditData. These operations get an explanation; forwarding rules, MFA changes, admin roles, app consent and disabled auditing are flagged.",
        groups: [{ title: "Operations", items: Object.entries(OPERATION_MEANINGS).map(([key, text]) => `${key} — ${text}`) }],
    }),
};
