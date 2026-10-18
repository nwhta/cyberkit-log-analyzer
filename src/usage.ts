// PUBLIC VERSION (stub).
// The hosted site at https://logs.cyberkit.me sends an anonymous counter
// ("which log format was analyzed") to its own server.
// This public version has no server-side statistics, so these functions
// do nothing. They keep the same names and types as the hosted version,
// so the rest of the code (logParse.ts) works without any changes.

export type UsageKind = "analyze" | "demo" | "unknown";

export function reportUsage(_kind: UsageKind, _formatId: string): void {
    // Intentionally empty: nothing is sent anywhere.
}

export function reportUnknownFormat(_fileName: string): void {
    // Intentionally empty: nothing is sent anywhere.
}
