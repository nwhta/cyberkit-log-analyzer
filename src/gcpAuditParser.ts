import type { Severity } from "./types.js";
import type { LogParser, ParsedEvent } from "./parserTypes.js";
import type { JsonItem } from "./jsonRecords.js";
import { buildCloudEvent, CLOUD_SOURCE_PANEL, cloudFacets, type Risk } from "./cloudEvents.js";
import { object, prettyJson, readJsonEvents, text } from "./structured.js";

interface RiskRule {
    pattern: RegExp;
    risk: Risk;
}

const RISKS: RiskRule[] = [
    { pattern: /SetIamPolicy$/i, risk: { name: "IAM policy changed", reason: "Permissions changed. Check for new owners or public access (allUsers).", severity: "WARNING" } },
    { pattern: /CreateServiceAccountKey$/i, risk: { name: "Service account key created", reason: "A downloadable key lets anyone act as this service account — a common way to keep access.", severity: "ERROR" } },
    { pattern: /GenerateAccessToken$|SignBlob$|SignJwt$/i, risk: { name: "Service account impersonation", reason: "Someone acted as a service account.", severity: "WARNING" } },
    { pattern: /compute\.firewalls\.(insert|patch|update)/i, risk: { name: "Firewall rule changed", reason: "Check that it does not open SSH/RDP to 0.0.0.0/0.", severity: "WARNING" } },
    { pattern: /compute\.instances\.setMetadata|compute\.projects\.setCommonInstanceMetadata/i, risk: { name: "VM metadata changed", reason: "Metadata can add SSH keys or startup scripts to VMs.", severity: "WARNING" } },
    { pattern: /logging\.sinks\.delete|DeleteSink|UpdateSink|logging\.exclusions\.create/i, risk: { name: "Logging changed", reason: "Deleting or excluding logs can hide activity.", severity: "ERROR" } },
    { pattern: /storage\.setIamPermissions/i, risk: { name: "Bucket permissions changed", reason: "Check that the bucket is not public.", severity: "WARNING" } },
    { pattern: /DeleteProject|\.delete$/i, risk: { name: "Resource deleted", reason: "A resource was deleted.", severity: "INFO" } },
];

const STATUS_CODES: Readonly<Record<string, string>> = {
    "0": "OK", "3": "INVALID_ARGUMENT", "5": "NOT_FOUND", "6": "ALREADY_EXISTS", "7": "PERMISSION_DENIED", "16": "UNAUTHENTICATED", "8": "RESOURCE_EXHAUSTED",
};

const SEVERITIES: Readonly<Record<string, Severity>> = { EMERGENCY: "CRITICAL", ALERT: "CRITICAL", CRITICAL: "CRITICAL", ERROR: "ERROR", WARNING: "WARNING", NOTICE: "INFO", INFO: "INFO", DEBUG: "DEBUG", DEFAULT: "INFO" };

function shortMethod(method: string): string {
    const parts = method.split(".");
    const last = parts.pop() ?? method;
    return /^[a-z]/.test(last) && parts.length > 0 ? `${parts.pop()}.${last}` : last || method;
}

function toEvent(item: JsonItem): ParsedEvent {
    const record = item.record;
    const payload = object(record, "protoPayload") ?? {};
    const method = text(payload, "methodName");
    const code = text(payload, "status.code");
    const failed = code !== "" && code !== "0";
    const publicGrant = method.endsWith("SetIamPolicy") && /allUsers|allAuthenticatedUsers/.test(JSON.stringify(payload));
    const rule = RISKS.find(item => item.pattern.test(method));
    const risk: Risk | null = publicGrant ? { name: "Made public", reason: "allUsers / allAuthenticatedUsers got access — the resource is open to the internet.", severity: "CRITICAL" } : rule?.risk ?? null;
    const logName = decodeURIComponent(text(record, "logName"));
    const time = text(record, "timestamp", "receiveTimestamp");

    return buildCloudEvent({
        lineNumber: item.lineNumber,
        raw: item.raw,
        timeMs: Date.parse(time.replace(/(\.\d{3})\d+/, "$1")),
        timeText: time,
        operation: method || text(record, "jsonPayload.message", "textPayload") || "(no method)",
        title: `${shortMethod(method)}${failed ? ` (${STATUS_CODES[code] ?? "error " + code})` : ""}`,
        summary: [text(payload, "serviceName"), text(payload, "resourceName").split("/").slice(-2).join("/"), failed ? text(payload, "status.message") : ""].filter(Boolean).join(" · "),
        actor: text(payload, "authenticationInfo.principalEmail") || null,
        ip: text(payload, "requestMetadata.callerIp") || null,
        result: failed ? "Failure" : "Success",
        resultText: failed ? STATUS_CODES[code] ?? `code ${code}` : "OK",
        service: text(payload, "serviceName") || text(record, "resource.type"),
        resource: text(payload, "resourceName") || null,
        risk,
        severity: risk === null ? SEVERITIES[text(record, "severity")] ?? (failed ? "WARNING" : "INFO") : undefined,
        noise: logName.includes("data_access") && !failed && risk === null,
        extraFacets: { logType: logName.split("/").pop()?.replace("cloudaudit.googleapis.com", "audit") || "(not set)" },
        fields: [
            { name: "Method", value: method },
            { name: "Status", value: code === "" ? "OK" : `${code} ${STATUS_CODES[code] ?? ""}`.trim(), meaning: code === "7" ? "The caller did not have permission — repeated denials can mean someone is probing" : null, risky: failed },
            { name: "User agent", value: text(payload, "requestMetadata.callerSuppliedUserAgent") },
        ],
        source: record,
    });
}

export const gcpAuditParser: LogParser = {
    id: "gcp-audit",
    name: "Google Cloud audit logs",
    description: "Google Cloud Audit Logs (gcloud logging read --format=json): admin activity and data access.",
    demoFile: "/static/demo/gcp-audit.json",
    rawLabel: "Raw JSON",
    searchHint: "Method, principal, resource, IP…",
    timeNote: "Google Cloud times are in UTC.",
    detect: sample => /"protoPayload"\s*:/.test(sample) && /"methodName"\s*:/.test(sample) && /google\.cloud\.audit\.AuditLog|cloudaudit\.googleapis\.com/.test(sample) ? 0.98 : 0,
    parse: content => readJsonEvents(content, toEvent, "This line is not a valid Cloud Logging JSON entry."),
    formatRaw: prettyJson,
    facets: cloudFacets([{ key: "logType", title: "Audit log type" }]),
    sourcePanel: CLOUD_SOURCE_PANEL,
    noise: { label: "Successful data-access reads", hint: "Data access logs are very frequent. Shown: admin activity, failures and risky actions." },
    coverage: () => ({
        summary: "Every entry is shown. Permission denials and these risky methods are flagged:",
        groups: [{ title: "Risky methods", items: RISKS.map(rule => `${rule.risk.name} — ${rule.risk.reason}`) }],
    }),
};
