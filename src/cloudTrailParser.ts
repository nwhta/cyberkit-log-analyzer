import type { Severity } from "./types.js";
import type { EventField, LogParser, ParsedEvent } from "./parserTypes.js";
import { cleanIp, flattenObject, formatUtc, getPath, parseEpochOrDate, shorten, tryParseJsonObject } from "./parseHelpers.js";
import { SEVERITY_COLORS, SEVERITY_ORDER, isSeriousSeverity, severityColor } from "./severity.js";
import { readJsonLines, type JsonItem, type JsonRecord } from "./jsonRecords.js";

const NOT_SENSITIVE = "Not sensitive";

const SENSITIVE_ACTIONS: Readonly<Record<string, string>> = {
    StopLogging: "CloudTrail logging was stopped. Attackers do this to hide their actions.",
    DeleteTrail: "A CloudTrail trail was deleted. Attackers do this to hide their actions.",
    UpdateTrail: "CloudTrail settings were changed.",
    PutEventSelectors: "What CloudTrail records was changed.",
    DeleteFlowLogs: "VPC flow logs were deleted (less network visibility).",
    DeleteDetector: "GuardDuty threat detection was turned off.",
    DisableSecurityHub: "Security Hub was turned off.",
    CreateUser: "A new IAM user was created.",
    CreateAccessKey: "A new access key was created. Common persistence step after a compromise.",
    CreateLoginProfile: "Console password was set for a user.",
    UpdateLoginProfile: "Console password of a user was changed.",
    DeactivateMFADevice: "MFA was removed from a user.",
    DeleteVirtualMFADevice: "An MFA device was deleted.",
    AttachUserPolicy: "Permissions were attached to a user.",
    AttachRolePolicy: "Permissions were attached to a role.",
    AttachGroupPolicy: "Permissions were attached to a group.",
    PutUserPolicy: "Inline permissions were added to a user.",
    PutRolePolicy: "Inline permissions were added to a role.",
    AddUserToGroup: "A user was added to a group (may give new permissions).",
    UpdateAssumeRolePolicy: "Who can assume a role was changed.",
    CreateRole: "A new IAM role was created.",
    PutBucketPolicy: "S3 bucket policy changed. Check it did not make data public.",
    PutBucketAcl: "S3 bucket ACL changed. Check it did not make data public.",
    DeletePublicAccessBlock: "S3 public access protection was removed.",
    PutBucketPublicAccessBlock: "S3 public access settings were changed.",
    DeleteBucket: "An S3 bucket was deleted.",
    AuthorizeSecurityGroupIngress: "A firewall (security group) rule was opened for incoming traffic.",
    ModifyInstanceAttribute: "EC2 instance settings changed (can include user data / startup scripts).",
    DisableKey: "A KMS encryption key was disabled.",
    ScheduleKeyDeletion: "A KMS encryption key was scheduled for deletion.",
    GetSecretValue: "A secret was read from Secrets Manager.",
    ConsoleLogin: "Someone signed in to the AWS web console.",
};

function text(record: JsonRecord, path: string): string {
    const value = getPath(record, path);
    return value === undefined || value === null ? "" : typeof value === "string" ? value : JSON.stringify(value);
}

function identityName(record: JsonRecord): string {
    return text(record, "userIdentity.userName") ||
        text(record, "userIdentity.sessionContext.sessionIssuer.userName") ||
        text(record, "userIdentity.arn") ||
        text(record, "userIdentity.invokedBy") ||
        text(record, "userIdentity.type") ||
        "unknown identity";
}

function toEvent({ record, raw, lineNumber }: JsonItem): ParsedEvent {
    const eventName = text(record, "eventName");
    const eventSource = text(record, "eventSource");
    const timeMs = parseEpochOrDate(getPath(record, "eventTime"));
    const errorCode = text(record, "errorCode");
    const consoleResult = text(record, "responseElements.ConsoleLogin");
    const failed = errorCode !== "" || consoleResult === "Failure";
    const sourceIpText = text(record, "sourceIPAddress");
    const ip = /^[\d.:a-fA-F]+$/.test(sourceIpText) ? cleanIp(sourceIpText) : null;
    const identity = identityName(record);
    const identityType = text(record, "userIdentity.type") || "(not set)";
    const sensitive = SENSITIVE_ACTIONS[eventName] ?? null;
    const usedMfa = text(record, "additionalEventData.MFAUsed");
    const isRoot = identityType === "Root";

    let severity: Severity = "INFO";

    if (failed || sensitive !== null) {
        severity = "WARNING";
    }

    if (isRoot && eventName !== "") {
        severity = "ERROR";
    }

    const summaryParts = [`by ${identity}`];

    if (failed) {
        summaryParts.push(`FAILED: ${errorCode || "Failure"}${text(record, "errorMessage") ? ` — ${text(record, "errorMessage")}` : ""}`);
    }

    if (isRoot) {
        summaryParts.push("root account used");
    }

    const metadata = [formatUtc(timeMs), eventSource, text(record, "awsRegion")].filter(part => part !== "");

    if (sourceIpText !== "") {
        metadata.push(`from: ${sourceIpText}`);
    }

    return {
        lineNumber,
        raw,
        timeMs,
        timeText: text(record, "eventTime"),
        severity,
        title: `${eventName || "(no eventName)"}`,
        badge: failed ? "FAILED" : "OK",
        summary: shorten(summaryParts.join(" · ")),
        metadata,
        accent: SEVERITY_COLORS[severity],
        emphasis: isSeriousSeverity(severity) || failed,
        noise: false,
        ip,
        facets: {
            result: failed ? "Failed / denied" : "Succeeded",
            sensitive: sensitive === null ? NOT_SENSITIVE : "Sensitive action",
            service: eventSource.replace(".amazonaws.com", "") || "(not set)",
            identityType,
            region: text(record, "awsRegion") || "(not set)",
            identity,
            eventName,
        },
        details: () => {
            const fields: EventField[] = [];

            if (sensitive !== null) {
                fields.push({ name: "Why this matters", value: eventName, meaning: sensitive, risky: true });
            }

            if (isRoot) {
                fields.push({ name: "Root account", value: "yes", meaning: "The root user should almost never be used for daily work.", risky: true });
            }

            if (eventName === "ConsoleLogin") {
                fields.push({ name: "MFA used", value: usedMfa || "not recorded", meaning: usedMfa === "No" ? "Console sign-in without MFA." : null, risky: usedMfa === "No" });
            }

            for (const [name, value] of flattenObject(record)) {
                fields.push({ name, value });
            }

            return { fields };
        },
    };
}

function readRecords(content: string): ParsedEvent[] {
    const trimmed = content.trimStart();

    if (trimmed.startsWith("{") && !trimmed.slice(0, 2000).includes("\n{")) {
        try {
            const document = JSON.parse(content) as unknown;
            const records = getPath(document, "Records");

            if (Array.isArray(records)) {
                return records.map((record, index) => toEvent({
                    record: record as JsonRecord,
                    raw: JSON.stringify(record),
                    lineNumber: index + 1,
                }));
            }
        } catch {
        }
    }

    if (trimmed.startsWith("[")) {
        try {
            const records = JSON.parse(content) as unknown;

            if (Array.isArray(records)) {
                return records.map((record, index) => toEvent({
                    record: record as JsonRecord,
                    raw: JSON.stringify(record),
                    lineNumber: index + 1,
                }));
            }
        } catch {
        }
    }

    return readJsonLines(content, toEvent, "This line is not a valid CloudTrail JSON record.");
}

export const cloudTrailParser: LogParser = {
    id: "aws-cloudtrail",
    name: "AWS CloudTrail",
    description: "AWS CloudTrail JSON: who did what in an AWS account.",
    demoFile: "/static/demo/cloudtrail.json",
    rawLabel: "Raw JSON",
    searchHint: "Event name, user, IP, ARN…",
    timeNote: "CloudTrail times are in UTC.",
    detect: sample => {
        const hasCloudTrailKeys = sample.includes("\"eventSource\"") &&
            sample.includes("\"eventName\"") &&
            (sample.includes("\"awsRegion\"") || sample.includes("\"userIdentity\""));

        if (!hasCloudTrailKeys) {
            return 0;
        }

        return sample.includes("\"Records\"") || tryParseJsonObject(sample.split("\n")[0]) !== null ? 0.98 : 0.9;
    },
    parse: readRecords,
    formatRaw: raw => {
        try {
            return JSON.stringify(JSON.parse(raw), null, 2);
        } catch {
            return raw;
        }
    },
    facets: [
        { key: "result", title: "Result", color: value => value === "Succeeded" ? "#5dc98b" : SEVERITY_COLORS.ERROR },
        { key: "sensitive", title: "Sensitive action", color: value => value === NOT_SENSITIVE ? "#87909e" : SEVERITY_COLORS.ERROR },
        { key: "service", title: "AWS service" },
        { key: "identityType", title: "Identity type", color: value => value === "Root" ? SEVERITY_COLORS.ERROR : "#619aff" },
        { key: "region", title: "Region" },
    ],
    sourcePanel: {
        title: "Failed / denied calls by source IP",
        emptyText: "No failed calls from an IP address",
        subjectWord: ["identity", "identities"],
        select: event => event.facets.result === "Succeeded" || event.ip === null ? null : {
            ip: event.ip,
            subject: event.facets.identity,
            tag: event.facets.eventName === "ConsoleLogin" ? "console login" : null,
        },
        suspicion: stats => {
            if (stats.tags.size > 0 && stats.count >= 3) {
                return "possible console password guessing";
            }

            return stats.count >= 10 ? "many denied calls (permission probing)" : null;
        },
    },
};
