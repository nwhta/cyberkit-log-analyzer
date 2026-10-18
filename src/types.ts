export type Severity =
    | "INFO"
    | "WARNING"
    | "ERROR"
    | "CRITICAL"
    | "DEBUG"
    | "UNKNOWN";

export interface LogEntry {
    lineNumber: number;
    line: string;
    date: string;
    time: string;
    severity: Severity;
    ip: string | null;
    mac: string | null;
    message: string;
}

export type AuditResult = "SUCCESS" | "FAILURE" | "NONE";

export type SecurityCategory =
    | "LOGON"
    | "AUTHENTICATION"
    | "ACCOUNT"
    | "GROUP"
    | "PROCESS"
    | "SERVICE"
    | "SCHEDULED_TASK"
    | "AUDIT_POLICY"
    | "CREDENTIALS"
    | "PRIVILEGE_USE"
    | "OBJECT_ACCESS"
    | "NETWORK"
    | "SYSTEM"
    | "FILE"
    | "REGISTRY"
    | "WMI"
    | "OTHER";

export interface EventDataField {
    name: string;
    value: string;
}

export interface WindowsLogEntry extends LogEntry {
    eventId: string;
    provider: string;
    computer: string;
    channel: string;
    windowsLevel: string;
    keywords: string;
    timestamp: string;

    auditResult: AuditResult;
    category: SecurityCategory;

    subjectUser: string | null;

    targetUser: string | null;

    logonType: string | null;

    eventData: EventDataField[];

    renderedMessage: string;

    summary: string;

    alert: { name: string; reason: string } | null;

    isRoutine: boolean;

    timeMs: number;
}
