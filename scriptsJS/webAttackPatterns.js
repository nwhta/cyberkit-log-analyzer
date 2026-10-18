import { safeDecode } from "./parseHelpers.js";
export const NO_ATTACK = "None detected";
const ATTACK_RULES = [
    {
        name: "Log4Shell",
        explanation: "JNDI lookup string used to exploit Log4j (CVE-2021-44228).",
        pattern: /\$\{(?:jndi|\$\{[^}]*\}|lower|upper|env|sys)[^}]{0,80}/i,
    },
    {
        name: "Path traversal",
        explanation: "\"../\" sequences try to climb out of the web folder and read other files.",
        pattern: /(?:\.\.[\\/]){1,}|%2e%2e(?:%2f|%5c|\/|\\)/i,
    },
    {
        name: "Sensitive file probe",
        explanation: "Request for a file that should never be public: passwords, keys, configs, source control.",
        pattern: /\/(?:etc\/(?:passwd|shadow|hosts)|\.env(?:\.\w+)?\b|\.git\/|\.svn\/|\.htpasswd|\.htaccess|wp-config\.php|id_rsa|\.aws\/credentials|\.DS_Store|web\.config|server-status|phpinfo\.php)/i,
    },
    {
        name: "SQL injection",
        explanation: "SQL keywords or quote tricks that try to change a database query.",
        pattern: /(?:union(?:\s|\/\*.*?\*\/)+(?:all\s+)?select|select\s.+\sfrom\s|'\s*or\s+['"\d]|\bor\s+1\s*=\s*1|sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|information_schema|waitfor\s+delay|xp_cmdshell)/i,
    },
    {
        name: "XSS",
        explanation: "HTML/JavaScript injected into the request to run in someone's browser (cross-site scripting).",
        pattern: /(?:<script|javascript:|onerror\s*=|onload\s*=|<svg[^>]*on\w+\s*=|alert\s*\(|document\.cookie)/i,
    },
    {
        name: "Command injection",
        explanation: "Shell commands appended to the request to run them on the server.",
        pattern: /(?:[;|`]\s*(?:wget|curl|bash|sh|nc|ncat|python\d?|perl|chmod|rm)\b|\$\((?:wget|curl|id|whoami|uname)|\bcmd(?:\.exe)?\s*\/c\b|\/bin\/(?:ba)?sh)/i,
    },
    {
        name: "Web shell",
        explanation: "Request to a web shell: a backdoor script that runs commands on the server.",
        pattern: /(?:\/(?:shell|cmd|c99|r57|wso|webshell|b374k)\.(?:php|aspx?|jsp)|\.(?:php|aspx?|jsp)\?(?:cmd|exec|command|c)=)/i,
    },
    {
        name: "Admin panel probe",
        explanation: "Automated search for common admin pages and known vulnerable apps.",
        pattern: /\/(?:wp-login\.php|xmlrpc\.php|wp-admin|phpmyadmin|pma\/|admin\.php|manager\/html|actuator\b|solr\/admin|cgi-bin\/|boaform|HNAP1|vendor\/phpunit)/i,
    },
];
export function detectWebAttack(text) {
    if (text === "") {
        return null;
    }
    const decoded = safeDecode(safeDecode(text));
    for (const rule of ATTACK_RULES) {
        const match = rule.pattern.exec(decoded) ?? rule.pattern.exec(text);
        if (match) {
            return { name: rule.name, explanation: rule.explanation, matched: match[0] };
        }
    }
    return null;
}
export function listAttackPatterns() {
    return ATTACK_RULES.map(rule => `${rule.name} — ${rule.explanation}`);
}
