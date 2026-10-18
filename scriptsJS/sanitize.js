const KEEP_IPS = new Set(["127.0.0.1", "0.0.0.0", "255.255.255.255", "::1", "::"]);
const KEEP_USERS = new Set([
    "root", "system", "nobody", "daemon", "www-data", "local service", "network service",
    "anonymous logon", "anonymous", "guest", "-", "n/a", "none", "null", "unknown",
]);
const NOT_USER_WORDS = /^(?:login|logon|logout|user|users|account|auth|failed|failure|success|session|invalid|unknown|from|by|for|to|the)$/i;
const KEEP_HOST_SUFFIXES = ["amazonaws.com", "amazon.com", "microsoft.com", "windowsupdate.com", "windows.net"];
const KNOWN_TLDS = new Set([
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "io", "co", "me", "app", "dev", "cloud",
    "online", "site", "xyz", "top", "local", "lan", "corp", "internal", "home", "intranet", "arpa", "example",
    "test", "invalid", "localdomain", "onion", "tech", "store", "shop", "pro", "name", "mobi", "asia",
]);
const NOT_TLDS = new Set([
    "js", "ts", "py", "sh", "rb", "pl", "go", "rs", "cs", "md", "db", "gz", "xz", "so", "ps", "hh", "cc", "vb", "ui",
]);
const SECRET_KEYS = "password|passwd|pwd|pass|secret|token|api[_-]?key|apikey|access[_-]?key|auth|authorization|session(?:[_-]?id)?|sessid|cookie|sig|signature";
const USER_KEYS = "user|username|user_name|usr|login|logname|acct|account|account_?name|uid_name|suser|duser|target_?user_?name|subject_?user_?name|user_?display_?name|display_?name";
const USER_PROSE = "for(?: invalid| illegal)? user|invalid user|illegal user|by user|(?:password|publickey|keyboard-interactive(?:/pam)?|none) for(?: invalid user)?";
const KEEP_DOMAINS = new Set(["AUTHORITY", "BUILTIN", "NT", "WORKGROUP", "MANAGER", "HOST"]);
const DOMAIN_USER = /(?<![\\:/\w])([A-Z][A-Z0-9-]{1,14})\\([\w.$-]{2,64})/g;
const RULES = [
    { kind: "SECRET", pattern: /\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]+/g },
    { kind: "SECRET", pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
    { kind: "SECRET", hasPrefix: true, pattern: new RegExp(`(\\b(?:${SECRET_KEYS})["']?\\s*[=:]\\s*["'<]?)(?!\\[)([^\\s"'&;,)>]{3,})`, "gi") },
    { kind: "EMAIL", pattern: /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g },
    { kind: "SID", pattern: /\bS-1-5-21(?:-\d+){3,4}\b/g },
    { kind: "ACCOUNT", hasPrefix: true, pattern: /(arn:aws[\w-]*:[\w-]*:[\w-]*:|account(?:Id)?["']?\s*[=:]\s*["']?)(\d{12})\b/gi },
    { kind: "MAC", pattern: /\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b/gi },
    {
        kind: "IP",
        pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b|(?<![\w:])(?=[0-9a-f:]*::|(?:[0-9a-f]{1,4}:){3})[0-9a-f]{0,4}(?::{1,2}[0-9a-f]{1,4}){1,7}(?:::)?(?![\w:])/gi,
        keep: isNotIp,
    },
    {
        kind: "HOST",
        pattern: /(?<![\w.@\\-])(?<!(?<!\/)\/)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b(?![\w-]*\()/gi,
        keep: isNotHostName,
    },
    {
        kind: "USER",
        hasPrefix: true,
        pattern: new RegExp(`(\\b(?:${USER_KEYS})["']?\\s*[=:]\\s*["'<]?)(?![\\[(])([\\w.$@-]{2,64})`, "gi"),
        keep: match => isWellKnownUser(match) || /^\d+$/.test(match),
    },
    {
        kind: "USER",
        hasPrefix: true,
        pattern: new RegExp(`(\\b(?:${USER_PROSE})\\s+["']?)(?!invalid\\b|illegal\\b|user\\b|\\[)([\\w.$@-]{2,64})`, "gi"),
        keep: match => isWellKnownUser(match) || /^\d+$/.test(match),
    },
];
const WORD_FIELD_KINDS = [
    [/^(?:subject |target )?domain(?: ?name)?$|DomainName$/i, "DOMAIN"],
    [/workstation|computer|host ?name|^host$|machine|device ?name|client ?name/i, "HOST"],
    [/user|account name|^account$|subject|logon name|principal|caller/i, "USER"],
];
let enabled = false;
let originalToToken = new Map();
let tokenToOriginal = new Map();
let counters = new Map();
let knownWords = new Map();
let knownWordsPattern = null;
let harvestedEvents = null;
const listeners = [];
function isNotIp(match) {
    if (KEEP_IPS.has(match)) {
        return true;
    }
    if (match.includes(".")) {
        return match.split(".").some(part => Number(part) > 255);
    }
    return !match.includes("::") && !/[a-f]/i.test(match);
}
function isNotHostName(match) {
    const lower = match.toLowerCase();
    const tld = lower.slice(lower.lastIndexOf(".") + 1);
    if (KEEP_HOST_SUFFIXES.some(suffix => lower === suffix || lower.endsWith("." + suffix))) {
        return true;
    }
    if (KNOWN_TLDS.has(tld)) {
        return false;
    }
    return tld.length !== 2 || NOT_TLDS.has(tld);
}
function isWellKnownUser(match) {
    return KEEP_USERS.has(match.toLowerCase()) || NOT_USER_WORDS.test(match) || match.endsWith("$") && match.length <= 2;
}
function tokenFor(kind, original) {
    const key = `${kind}\u0000${original.toLowerCase()}`;
    let token = originalToToken.get(key);
    if (token === undefined) {
        const next = (counters.get(kind) ?? 0) + 1;
        counters.set(kind, next);
        token = `[${kind}-${next}]`;
        originalToToken.set(key, token);
        tokenToOriginal.set(token.toLowerCase(), original);
    }
    return token;
}
function escapeRegExp(text) {
    return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function rememberWord(kind, value) {
    const word = value.trim();
    if (word.length < 2 || word.length > 64 || /\s/.test(word) || /^[\d.:-]+$/.test(word) || word.startsWith("[")) {
        return;
    }
    if (isWellKnownUser(word)) {
        return;
    }
    if (!knownWords.has(word.toLowerCase())) {
        knownWords.set(word.toLowerCase(), kind);
    }
}
function collectFromText(text) {
    for (const match of text.matchAll(DOMAIN_USER)) {
        if (!KEEP_DOMAINS.has(match[1])) {
            rememberWord("DOMAIN", match[1]);
            rememberWord("USER", match[2]);
        }
    }
    for (const rule of RULES) {
        if (rule.kind !== "USER") {
            continue;
        }
        for (const match of text.matchAll(rule.pattern)) {
            const value = rule.hasPrefix ? match[2] : match[0];
            if (!rule.keep?.(value)) {
                rememberWord(rule.kind, value);
            }
        }
    }
}
function collectFromFields(event) {
    let fields;
    try {
        fields = event.details().fields;
    }
    catch {
        return;
    }
    for (const field of fields) {
        const name = field.name.split(".").pop() ?? field.name;
        if (/agent|type|id$/i.test(name)) {
            continue;
        }
        const kind = WORD_FIELD_KINDS.find(([pattern]) => pattern.test(name))?.[1];
        if (kind === undefined || field.value === "") {
            continue;
        }
        const parts = field.value.split("\\");
        if (parts.length === 2) {
            rememberWord("DOMAIN", parts[0]);
            rememberWord("USER", parts[1]);
        }
        else {
            rememberWord(kind, field.value);
        }
    }
}
function harvest(events) {
    if (harvestedEvents === events) {
        return;
    }
    harvestedEvents = events;
    knownWords = new Map();
    for (const event of events) {
        collectFromText(event.raw);
        collectFromFields(event);
    }
    const words = [...knownWords.keys()].sort((a, b) => b.length - a.length).map(escapeRegExp);
    knownWordsPattern = words.length === 0 ? null : new RegExp(`(?<![\\w.\\[-])(?:${words.join("|")})(?![\\w.\\]-])`, "gi");
}
export function resetSanitizer() {
    originalToToken = new Map();
    tokenToOriginal = new Map();
    counters = new Map();
    knownWords = new Map();
    knownWordsPattern = null;
    harvestedEvents = null;
}
export function prepareSanitizer(events) {
    if (enabled) {
        harvest(events);
    }
}
function maskDomainUser(match, domain, user) {
    if (KEEP_DOMAINS.has(domain)) {
        return match;
    }
    return `${tokenFor("DOMAIN", domain)}\\${isWellKnownUser(user) ? user : tokenFor("USER", user)}`;
}
export function maskAlways(text) {
    let result = text.replace(DOMAIN_USER, maskDomainUser);
    for (const rule of RULES) {
        result = result.replace(rule.pattern, (match, prefix, value) => {
            if (rule.hasPrefix && typeof prefix === "string" && typeof value === "string") {
                return rule.keep?.(value) ? match : prefix + tokenFor(rule.kind, value);
            }
            return rule.keep?.(match) ? match : tokenFor(rule.kind, match);
        });
    }
    if (knownWordsPattern !== null) {
        result = result.replace(knownWordsPattern, match => tokenFor(knownWords.get(match.toLowerCase()) ?? "USER", match));
    }
    return result;
}
export function mask(text) {
    return enabled && text !== "" ? maskAlways(text) : text;
}
export function unmaskQuery(text) {
    if (!enabled) {
        return text;
    }
    return text.replace(/\[[a-z]+-\d+\]/gi, token => tokenToOriginal.get(token.toLowerCase()) ?? token);
}
export function isSanitizing() {
    return enabled;
}
export function setSanitizing(value, events) {
    enabled = value;
    if (enabled) {
        harvest(events);
    }
    for (const listener of listeners) {
        listener();
    }
}
export function onSanitizeChange(listener) {
    listeners.push(listener);
}
