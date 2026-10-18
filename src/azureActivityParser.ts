import type { Severity } from "./types.js";
import type { LogParser, ParsedEvent } from "./parserTypes.js";
import type { JsonItem, JsonRecord } from "./jsonRecords.js";
import { buildCloudEvent, CLOUD_SOURCE_PANEL, cloudFacets, type Risk } from "./cloudEvents.js";
import { csvRecords, object, prettyJson, readJsonEvents, text } from "./structured.js";

interface RiskRule {
    pattern: RegExp;
    risk: Risk;
}

const RISKS: RiskRule[] = [
    { pattern: /Microsoft\.Authorization\/elevateAccess\/action/i, risk: { name: "Global admin elevated access", reason: "A Global Administrator gave themselves control of ALL subscriptions.", severity: "CRITICAL" } },
    { pattern: /Microsoft\.Authorization\/roleAssignments\/write/i, risk: { name: "Role assigned", reason: "Someone got new permissions (check for Owner / Contributor).", severity: "WARNING" } },
    { pattern: /Microsoft\.Compute\/virtualMachines\/runCommand\/action|Microsoft\.Compute\/virtualMachines\/extensions\/write/i, risk: { name: "Command run on a VM", reason: "Run Command or a Custom Script extension executes code on the VM — used by attackers for lateral movement.", severity: "ERROR" } },
    { pattern: /Microsoft\.Network\/networkSecurityGroups\/securityRules\/write/i, risk: { name: "Firewall (NSG) rule changed", reason: "A network rule was added or changed. Check that it does not open RDP/SSH to the internet.", severity: "WARNING" } },
    { pattern: /Microsoft\.Storage\/storageAccounts\/listKeys\/action|Microsoft\.Storage\/storageAccounts\/regenerateKey/i, risk: { name: "Storage keys read", reason: "Storage keys give full access to all data in the account.", severity: "WARNING" } },
    { pattern: /Microsoft\.KeyVault\/vaults\/accessPolicies\/write|Microsoft\.KeyVault\/vaults\/write/i, risk: { name: "Key Vault access changed", reason: "Someone changed who can read secrets.", severity: "WARNING" } },
    { pattern: /Microsoft\.Insights\/diagnosticSettings\/delete|Microsoft\.Insights\/activityLogAlerts\/delete|Microsoft\.Security\/.*\/delete/i, risk: { name: "Logging or alerts removed", reason: "Deleting diagnostics or alerts hides future activity.", severity: "ERROR" } },
    { pattern: /Microsoft\.Authorization\/policyAssignments\/delete|Microsoft\.Authorization\/locks\/delete/i, risk: { name: "Policy or lock removed", reason: "Protection against changes or deletion was removed.", severity: "WARNING" } },
    { pattern: /\/delete$/i, risk: { name: "Resource deleted", reason: "A resource was deleted.", severity: "INFO" } },
];

const LEVELS: Readonly<Record<string, Severity>> = { Critical: "CRITICAL", Error: "ERROR", Warning: "WARNING", Informational: "INFO", Information: "INFO", Verbose: "DEBUG" };

function valueOf(record: JsonRecord, path: string): string {
    const nested = object(record, path);
    return nested ? text(nested, "value", "localizedValue") : text(record, path);
}

function toEvent(item: JsonItem): ParsedEvent {
    const record = item.record;
    const operation = valueOf(record, "operationName") || text(record, "OperationNameValue", "Operation name", "Operation");
    const status = valueOf(record, "status") || text(record, "resultType", "ActivityStatusValue", "Status");
    const time = text(record, "eventTimestamp", "time", "TimeGenerated", "Time");
    const caller = text(record, "caller", "Caller", "Event initiated by", "identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn");
    const ip = text(record, "httpRequest.clientIpAddress", "callerIpAddress", "CallerIpAddress");
    const resource = text(record, "resourceId", "ResourceId", "Resource");
    const failed = /^(failed|failure)$/i.test(status);
    const rule = RISKS.find(item => item.pattern.test(operation));
    const level = text(record, "level", "Level");
    const category = valueOf(record, "category") || text(record, "CategoryValue", "Category");
    const readable = text(record, "operationName.localizedValue", "OperationName");

    return buildCloudEvent({
        lineNumber: item.lineNumber,
        raw: item.raw,
        timeMs: Date.parse(/[zZ]|[+-]\d{2}:\d{2}$/.test(time) ? time.replace(/(\.\d{3})\d+/, "$1") : time + "Z"),
        timeText: time,
        operation,
        title: `${readable && readable !== operation ? readable : operation}${failed ? " (failed)" : ""}`,
        summary: [category, status].filter(Boolean).join(" · "),
        actor: caller || null,
        ip: ip || null,
        result: failed ? "Failure" : /succeeded|success|accepted|started/i.test(status) ? "Success" : "Unknown",
        resultText: status || "Unknown",
        service: operation.split("/")[0] || "Azure",
        resource: resource.split("/").slice(-2).join("/") || null,
        risk: rule?.risk ?? null,
        severity: rule ? undefined : LEVELS[level] ?? (failed ? "WARNING" : "INFO"),
        noise: /\/read$/i.test(operation) || /^(Started|Accepted)$/i.test(status),
        extraFacets: { category: category || "(not set)" },
        source: record,
    });
}

function parse(content: string): ParsedEvent[] {
    if (!content.trimStart().startsWith("{") && !content.trimStart().startsWith("[")) {
        const { records, lines } = csvRecords(content);
        return records.map((record, index) => toEvent({ record, raw: JSON.stringify(record), lineNumber: lines[index] }));
    }

    return readJsonEvents(content, toEvent, "This line is not a valid Azure activity record.");
}

export const azureActivityParser: LogParser = {
    id: "azure-activity",
    name: "Azure Activity Log",
    description: "Azure subscription activity log (JSON export, diagnostic settings or CSV): who changed what in Azure.",
    demoFile: "/static/demo/azure-activity.json",
    rawLabel: "Raw JSON",
    searchHint: "Operation, caller, resource, IP…",
    timeNote: "Azure activity times are in UTC.",
    detect: sample => {
        const azureOperation = /Microsoft\.[A-Za-z]+\/[A-Za-z]+/.test(sample);

        if (azureOperation && /"(eventTimestamp|operationName)"\s*:/.test(sample) && /"(caller|resourceId|subscriptionId)"\s*:/i.test(sample)) {
            return 0.97;
        }

        const header = sample.split(/\r?\n/, 1)[0];
        return azureOperation && /Operation name/.test(header) && /Event initiated by/.test(header) ? 0.97 : 0;
    },
    parse,
    formatRaw: prettyJson,
    facets: cloudFacets([{ key: "category", title: "Category" }]),
    sourcePanel: CLOUD_SOURCE_PANEL,
    noise: { label: "Read operations and started / accepted steps", hint: "Each change writes Started → Succeeded. Shown: the final result. Click to show the rest." },
    coverage: () => ({
        summary: "Every record is shown. These operations are flagged as risky:",
        groups: [{ title: "Risky operations", items: RISKS.map(rule => `${rule.risk.name} — ${rule.risk.reason}`) }],
    }),
};
