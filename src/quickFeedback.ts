// PUBLIC VERSION (stub).
// On the hosted site a small "Was this analysis useful?" popup sends a rating
// to the server. This public version has no feedback server, so the popup is
// turned off. The exported function keeps its name, so logParse.ts can call it
// exactly as in the hosted version.
//
// Feedback for this project: https://github.com/nwhta/cyberkit-log-analyzer/issues

export function showQuickFeedback(): void {
    // Intentionally empty: no popup, nothing is sent.
}
