import { readJsonLines } from "./jsonRecords.js";
import { buildCloudEvent, CLOUD_SOURCE_PANEL, cloudFacets } from "./cloudEvents.js";
import { csvRecords, prettyJson, readJsonDocument, text } from "./structured.js";
const ERROR_CODES = {
    "0": "Success",
    "50126": "Wrong user name or password",
    "50053": "Account locked (too many wrong passwords, or sign-in from a known bad IP)",
    "50055": "Password expired",
    "50056": "No password stored for this user",
    "50057": "Account disabled",
    "50034": "User does not exist in this tenant",
    "50064": "Credential validation failed",
    "50076": "MFA required (new location or Conditional Access)",
    "50074": "Strong authentication (MFA) required",
    "50079": "User must register for MFA",
    "50072": "User must enroll in MFA",
    "500121": "MFA failed or was denied",
    "50158": "External security challenge not passed",
    "53003": "Blocked by Conditional Access",
    "53000": "Device not compliant (Conditional Access)",
    "53001": "Device not domain-joined (Conditional Access)",
    "530032": "Blocked by a security policy",
    "50105": "User is not assigned to this application",
    "65001": "User or admin has not consented to the app",
    "90094": "Admin consent required",
    "70044": "Session expired",
    "50133": "Session invalid: password changed or expired",
    "50140": "\"Stay signed in?\" prompt (interrupt, normal)",
    "50125": "Password reset or registration interrupt (normal)",
    "50199": "Extra confirmation for security (interrupt, normal)",
    "16000": "Account selection needed (interrupt, normal)",
    "16001": "Account selection needed (interrupt, normal)",
    "81010": "Seamless SSO failed: Kerberos ticket invalid",
    "50097": "Device authentication required",
    "700016": "Application not found in the directory",
    "7000218": "Client secret or assertion missing",
    "50173": "Grant expired (password changed)",
};
const INTERRUPTS = new Set(["50074", "50076", "50079", "50072", "50140", "50125", "50199", "16000", "16001", "50097"]);
const LEGACY_CLIENTS = /exchange activesync|imap|pop3|smtp|other clients|autodiscover|exchange online powershell|mapi over http|offline address book|outlook anywhere|reporting web services|exchange web services/i;
function fromJson(record) {
    const location = [text(record, "location.city", "LocationDetails.city"), text(record, "location.countryOrRegion", "LocationDetails.countryOrRegion")].filter(Boolean).join(", ");
    const code = text(record, "status.errorCode", "ResultType", "errorCode");
    return {
        time: text(record, "createdDateTime", "TimeGenerated", "time"),
        user: text(record, "userPrincipalName", "UserPrincipalName", "userDisplayName"),
        app: text(record, "appDisplayName", "AppDisplayName", "resourceDisplayName"),
        ip: text(record, "ipAddress", "IPAddress", "callerIpAddress"),
        location: location || text(record, "Location"),
        code: code || "0",
        reason: text(record, "status.failureReason", "ResultDescription", "status.additionalDetails"),
        clientApp: text(record, "clientAppUsed", "ClientAppUsed"),
        os: text(record, "deviceDetail.operatingSystem", "DeviceDetail.operatingSystem"),
        browser: text(record, "deviceDetail.browser", "DeviceDetail.browser"),
        conditionalAccess: text(record, "conditionalAccessStatus", "ConditionalAccessStatus"),
        risk: text(record, "riskLevelDuringSignIn", "RiskLevelDuringSignIn", "riskLevelAggregated"),
        mfa: text(record, "mfaDetail.authMethod", "MfaDetail.authMethod"),
        requirement: text(record, "authenticationRequirement", "AuthenticationRequirement"),
    };
}
function fromCsv(record) {
    return {
        time: text(record, "Date (UTC)", "Date"),
        user: text(record, "Username", "User"),
        app: text(record, "Application"),
        ip: text(record, "IP address"),
        location: text(record, "Location"),
        code: text(record, "Sign-in error code") || "0",
        reason: text(record, "Failure reason"),
        clientApp: text(record, "Client app"),
        os: text(record, "Operating System"),
        browser: text(record, "Browser"),
        conditionalAccess: text(record, "Conditional Access"),
        risk: text(record, "Risk level during sign-in", "Risk level (during sign-in)"),
        mfa: text(record, "Multifactor authentication auth method"),
        requirement: text(record, "Authentication requirement"),
    };
}
function riskOf(signIn) {
    if (/^(high|medium)$/i.test(signIn.risk)) {
        return { name: `Risky sign-in (${signIn.risk})`, reason: "Microsoft Entra ID Protection thinks this sign-in may not be the real user.", severity: /high/i.test(signIn.risk) ? "ERROR" : "WARNING" };
    }
    if (signIn.code === "50053") {
        return { name: "Account locked", reason: "Smart lockout after many wrong passwords, or the IP is known as malicious.", severity: "WARNING" };
    }
    if (LEGACY_CLIENTS.test(signIn.clientApp) && signIn.code === "0") {
        return { name: "Legacy authentication", reason: `${signIn.clientApp} cannot do MFA. Attackers use it to bypass MFA; block it with Conditional Access.`, severity: "WARNING" };
    }
    if (signIn.code === "500121") {
        return { name: "MFA denied", reason: "The password was right but MFA failed. If the user did not try to sign in, the password is probably stolen (MFA fatigue).", severity: "ERROR" };
    }
    return null;
}
function toEvent(signIn, item) {
    const result = signIn.code === "0" ? "Success" : INTERRUPTS.has(signIn.code) ? "Interrupted" : "Failure";
    const meaning = ERROR_CODES[signIn.code] ?? signIn.reason ?? `Error ${signIn.code}`;
    const severity = result === "Interrupted" ? "INFO" : undefined;
    return buildCloudEvent({
        lineNumber: item.lineNumber,
        raw: item.raw,
        timeMs: Date.parse(/[zZ]|[+-]\d{2}:\d{2}$/.test(signIn.time) ? signIn.time : signIn.time + "Z"),
        timeText: signIn.time,
        operation: "Sign-in",
        title: `${result === "Success" ? "Signed in" : result === "Interrupted" ? "Sign-in needs another step" : "Sign-in failed"} · ${signIn.user || "unknown user"} → ${signIn.app || "app"}`,
        summary: [result === "Success" ? "" : meaning, signIn.location, signIn.clientApp && signIn.clientApp !== "Browser" ? signIn.clientApp : ""].filter(Boolean).join(" · "),
        actor: signIn.user || null,
        ip: signIn.ip || null,
        result,
        resultText: signIn.code === "0" ? "SUCCESS" : result === "Interrupted" ? `STEP ${signIn.code}` : `ERROR ${signIn.code}`,
        service: signIn.app || "Microsoft Entra ID",
        resource: signIn.location || null,
        risk: riskOf(signIn),
        severity,
        extraFacets: {
            country: signIn.location.split(",").pop()?.trim() || "(unknown)",
            clientApp: signIn.clientApp || "(not set)",
            errorCode: signIn.code === "0" ? "0 Success" : `${signIn.code} ${ERROR_CODES[signIn.code] ?? ""}`.trim(),
        },
        fields: [
            { name: "Result code", value: signIn.code, meaning, risky: result === "Failure" },
            { name: "User", value: signIn.user },
            { name: "Application", value: signIn.app },
            { name: "IP address", value: signIn.ip },
            { name: "Location", value: signIn.location },
            { name: "Client app", value: signIn.clientApp, meaning: LEGACY_CLIENTS.test(signIn.clientApp) ? "Legacy authentication: cannot use MFA" : null, risky: LEGACY_CLIENTS.test(signIn.clientApp) },
            { name: "Operating system / browser", value: [signIn.os, signIn.browser].filter(Boolean).join(" / ") },
            { name: "Conditional Access", value: signIn.conditionalAccess, meaning: signIn.conditionalAccess === "notApplied" ? "No Conditional Access policy applied" : null },
            { name: "Authentication requirement", value: signIn.requirement, meaning: signIn.requirement === "singleFactorAuthentication" ? "Only a password was needed (no MFA)" : null },
            { name: "Risk during sign-in", value: signIn.risk },
        ].filter(field => field.value !== ""),
    });
}
function parse(content) {
    const document = readJsonDocument(content);
    if (document !== null) {
        return document.map(item => toEvent(fromJson(item.record), item));
    }
    if (content.trimStart().startsWith("{")) {
        return readJsonLines(content, item => toEvent(fromJson(item.record), item), "This line is not a valid sign-in JSON record.");
    }
    const { records, lines } = csvRecords(content);
    return records.map((record, index) => toEvent(fromCsv(record), { record, raw: Object.entries(record).map(([key, value]) => `${key}: ${value}`).join("\n"), lineNumber: lines[index] }));
}
export const entraSigninParser = {
    id: "entra-signin",
    name: "Microsoft Entra ID sign-in logs",
    description: "Azure AD / Entra ID sign-in logs (JSON or CSV download, Graph API, Log Analytics): Microsoft 365 logins.",
    demoFile: "/static/demo/entra-signins.json",
    rawLabel: "Raw record",
    searchHint: "User, IP, app, error code, country…",
    timeNote: "Entra ID times are in UTC.",
    detect: sample => {
        if (/"userPrincipalName"\s*:/.test(sample) && /"(appDisplayName|clientAppUsed|conditionalAccessStatus)"\s*:/.test(sample) && /"createdDateTime"|"status"/.test(sample)) {
            return 0.98;
        }
        if (/"UserPrincipalName"\s*:/.test(sample) && /"ResultType"\s*:/.test(sample) && /"AppDisplayName"/.test(sample)) {
            return 0.97;
        }
        const header = sample.split(/\r?\n/, 1)[0];
        return /Date \(UTC\)/.test(header) && /Sign-in error code|Username/.test(header) && /IP address/.test(header) ? 0.98 : 0;
    },
    parse,
    formatRaw: prettyJson,
    facets: cloudFacets([
        { key: "errorCode", title: "Result code" },
        { key: "country", title: "Country" },
        { key: "clientApp", title: "Client app", color: value => LEGACY_CLIENTS.test(value) ? "#e5b44b" : "#619aff" },
    ]),
    sourcePanel: CLOUD_SOURCE_PANEL,
    coverage: () => ({
        summary: "Every sign-in is shown. Error codes are explained; interrupts (MFA prompt, \"stay signed in?\") are not counted as failures. Risky sign-ins, legacy authentication, MFA denials and lockouts are flagged.",
        groups: [{ title: "Result codes", items: Object.entries(ERROR_CODES).map(([code, text]) => `${code} — ${text}`) }],
    }),
};
