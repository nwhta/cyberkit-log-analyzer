import { buildCloudEvent, CLOUD_SOURCE_PANEL, cloudFacets } from "./cloudEvents.js";
import { object, prettyJson, readJsonEvents, text } from "./structured.js";
const READ_VERBS = new Set(["get", "list", "watch"]);
function riskOf(verb, resource, subresource, user, body, code) {
    if (user === "system:anonymous" && code < 400) {
        return { name: "Anonymous access", reason: "An unauthenticated request was allowed. Anonymous access to the API server should be off.", severity: "ERROR" };
    }
    if (subresource === "exec" || subresource === "attach") {
        return { name: "Shell in a container", reason: "Someone opened a shell inside a running pod (kubectl exec).", severity: "WARNING" };
    }
    if (subresource === "portforward") {
        return { name: "Port forward", reason: "A pod port was forwarded to someone's computer.", severity: "INFO" };
    }
    if (resource === "secrets" && READ_VERBS.has(verb) && !user.startsWith("system:")) {
        return { name: "Secrets read", reason: "Secrets (passwords, tokens) were read by a person.", severity: "WARNING" };
    }
    if ((resource === "clusterrolebindings" || resource === "rolebindings") && (verb === "create" || verb === "update" || verb === "patch")) {
        return { name: "Permissions granted", reason: /cluster-admin/.test(body) ? "Someone was given cluster-admin." : "A role binding was created or changed.", severity: /cluster-admin/.test(body) ? "ERROR" : "WARNING" };
    }
    if (resource === "pods" && verb === "create" && /"privileged":\s*true|"hostPID":\s*true|"hostNetwork":\s*true|"hostPath"/.test(body)) {
        return { name: "Privileged pod", reason: "A pod with host access was created — it can take over the node.", severity: "ERROR" };
    }
    if (resource === "serviceaccounts" && subresource === "token") {
        return { name: "Token created", reason: "A service account token was created.", severity: "INFO" };
    }
    return null;
}
function toEvent(item) {
    const record = item.record;
    const verb = text(record, "verb");
    const ref = object(record, "objectRef") ?? {};
    const resource = text(ref, "resource");
    const subresource = text(ref, "subresource");
    const namespace = text(ref, "namespace");
    const name = text(ref, "name");
    const user = text(record, "user.username", "impersonatedUser.username");
    const code = Number(text(record, "responseStatus.code") || "0");
    const failed = code >= 400;
    const ips = record.sourceIPs;
    const ip = Array.isArray(ips) ? String(ips[0] ?? "") : "";
    const body = JSON.stringify(record.requestObject ?? "");
    const risk = riskOf(verb, resource, subresource, user, body, code);
    const time = text(record, "requestReceivedTimestamp", "stageTimestamp", "timestamp");
    const target = [resource + (subresource ? `/${subresource}` : ""), namespace && name ? `${namespace}/${name}` : namespace ? `in ${namespace}` : name].filter(Boolean).join(" ");
    const systemNoise = (user.startsWith("system:") && user !== "system:anonymous" && READ_VERBS.has(verb)) || (READ_VERBS.has(verb) && !failed && risk === null);
    return buildCloudEvent({
        lineNumber: item.lineNumber,
        raw: item.raw,
        timeMs: Date.parse(time.replace(/(\.\d{3})\d+/, "$1")),
        timeText: time,
        operation: `${verb} ${resource}${subresource ? "/" + subresource : ""}`,
        title: `${verb} ${target || text(record, "requestURI")}${failed ? ` → ${code}` : ""}`,
        summary: [text(record, "userAgent").split(" ")[0], String((object(record, "annotations") ?? {})["authorization.k8s.io/reason"] ?? "")].filter(Boolean).join(" · "),
        actor: user || null,
        ip: ip || null,
        result: failed ? "Failure" : code > 0 ? "Success" : "Unknown",
        resultText: code > 0 ? String(code) : text(record, "stage"),
        service: "Kubernetes API",
        resource: target || null,
        risk,
        severity: risk === null && (code === 401 || code === 403) ? "WARNING" : undefined,
        noise: systemNoise,
        extraFacets: { verb: verb || "(none)", namespace: namespace || "(cluster)" },
        fields: [
            { name: "Request URI", value: text(record, "requestURI") },
            { name: "Response code", value: code > 0 ? String(code) : "", meaning: code === 403 ? "Forbidden: the user has no permission" : code === 401 ? "Unauthenticated: bad or missing token" : null, risky: failed },
            { name: "Groups", value: Array.isArray(object(record, "user")?.groups) ? (object(record, "user")?.groups).join(", ") : "" },
        ],
        source: record,
    });
}
export const k8sAuditParser = {
    id: "k8s-audit",
    name: "Kubernetes audit log",
    description: "Kubernetes API server audit log (audit.k8s.io JSON lines): who did what in the cluster.",
    demoFile: "/static/demo/k8s-audit.jsonl",
    rawLabel: "Raw JSON",
    searchHint: "User, verb, pod, namespace, IP…",
    timeNote: "Kubernetes audit times are in UTC.",
    detect: sample => /"apiVersion"\s*:\s*"audit\.k8s\.io\//.test(sample) || (/"kind"\s*:\s*"Event"/.test(sample) && /"auditID"\s*:/.test(sample)) ? 0.98 : 0,
    parse: content => readJsonEvents(content, toEvent, "This line is not a valid Kubernetes audit event."),
    formatRaw: prettyJson,
    facets: cloudFacets([{ key: "verb", title: "Verb" }, { key: "namespace", title: "Namespace" }]),
    sourcePanel: CLOUD_SOURCE_PANEL,
    noise: { label: "Successful reads (get / list / watch)", hint: "Controllers read the API all the time. Shown: changes, failures and risky actions." },
    coverage: () => ({
        summary: "Every audit event is shown. Flagged: anonymous access, exec/attach into pods, secrets read by people, new cluster-admin bindings, privileged pods. 401/403 answers are shown as failures.",
        groups: [],
    }),
};
