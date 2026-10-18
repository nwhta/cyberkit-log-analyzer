const SCANNERS = [
    [/sqlmap/i, "sqlmap"],
    [/nikto/i, "Nikto"],
    [/nmap/i, "Nmap"],
    [/masscan/i, "masscan"],
    [/zgrab/i, "ZGrab"],
    [/nuclei/i, "Nuclei"],
    [/wpscan/i, "WPScan"],
    [/gobuster/i, "Gobuster"],
    [/dirbuster|dirb\b/i, "DirBuster"],
    [/ffuf/i, "ffuf"],
    [/acunetix/i, "Acunetix"],
    [/nessus/i, "Nessus"],
    [/openvas/i, "OpenVAS"],
    [/hydra/i, "Hydra"],
    [/censys/i, "Censys"],
    [/shodan/i, "Shodan"],
    [/l9explore|leakix/i, "LeakIX"],
];
const SCRIPTS = [
    [/^curl\//i, "curl"],
    [/^wget\//i, "wget"],
    [/python-requests|python-urllib|aiohttp|httpx/i, "Python"],
    [/go-http-client/i, "Go"],
    [/^java\/|okhttp|apache-httpclient/i, "Java"],
    [/libwww-perl/i, "Perl"],
    [/powershell/i, "PowerShell"],
    [/node-fetch|axios|undici/i, "Node.js"],
];
const BOTS = [
    [/googlebot/i, "Googlebot"],
    [/bingbot/i, "Bingbot"],
    [/yandex/i, "Yandex"],
    [/duckduckbot/i, "DuckDuckBot"],
    [/baiduspider/i, "Baidu"],
    [/applebot/i, "Applebot"],
    [/ahrefsbot/i, "AhrefsBot"],
    [/semrushbot/i, "SemrushBot"],
    [/gptbot|chatgpt|claudebot|anthropic|ccbot|perplexity/i, "AI crawler"],
    [/bot\b|crawler|spider/i, "Other bot"],
];
function findIn(list, userAgent) {
    for (const [pattern, name] of list) {
        if (pattern.test(userAgent)) {
            return name;
        }
    }
    return null;
}
export function classifyUserAgent(userAgent) {
    if (userAgent === null || userAgent.trim() === "" || userAgent === "-") {
        return { kind: "Empty user agent", name: null };
    }
    const scanner = findIn(SCANNERS, userAgent);
    if (scanner !== null) {
        return { kind: "Security scanner", name: scanner };
    }
    const script = findIn(SCRIPTS, userAgent);
    if (script !== null) {
        return { kind: "Script / CLI tool", name: script };
    }
    const bot = findIn(BOTS, userAgent);
    if (bot !== null) {
        return { kind: "Bot / crawler", name: bot };
    }
    if (/mozilla\/|opera\//i.test(userAgent)) {
        return { kind: "Browser", name: null };
    }
    return { kind: "Other client", name: null };
}
export function explainClient(info) {
    const name = info.name === null ? "" : ` (${info.name})`;
    switch (info.kind) {
        case "Security scanner":
            return `Known attack/scanning tool${name}. Someone is probing this server.`;
        case "Script / CLI tool":
            return `Request made by a program, not a person in a browser${name}.`;
        case "Bot / crawler":
            return `Automated crawler${name}. The user agent can be faked.`;
        case "Empty user agent":
            return "No user agent sent. Real browsers always send one, so this is usually a script.";
        case "Browser":
            return "Looks like a normal web browser. The user agent can be faked.";
        default:
            return "Unknown client type.";
    }
}
export function listKnownScanners() {
    return SCANNERS.map(([, name]) => name);
}
