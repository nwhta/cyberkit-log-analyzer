import { windowsParser } from "./windowsParser.js";
import { webAccessParser } from "./webAccessParser.js";
import { nginxErrorParser } from "./nginxErrorParser.js";
import { apacheErrorParser } from "./apacheErrorParser.js";
import { iisParser } from "./iisParser.js";
import { cefParser } from "./cefParser.js";
import { suricataParser } from "./suricataParser.js";
import { cloudTrailParser } from "./cloudTrailParser.js";
import { zeekParser } from "./zeekParser.js";
import { jsonLogParser } from "./jsonLogParser.js";
import { syslogParser } from "./syslogParser.js";
import { journaldParser } from "./journaldParser.js";
import { auditdParser } from "./auditdParser.js";
import { fail2banParser } from "./fail2banParser.js";
import { windowsFirewallParser } from "./windowsFirewallParser.js";
import { snortFastParser } from "./snortFastParser.js";
import { leefParser } from "./leefParser.js";
import { pfsenseParser } from "./pfsenseParser.js";
import { ciscoAsaParser } from "./ciscoAsaParser.js";
import { fortigateParser } from "./fortigateParser.js";
import { paloAltoParser } from "./paloAltoParser.js";
import { awsVpcFlowParser } from "./awsVpcFlowParser.js";
import { awsAlbParser } from "./awsAlbParser.js";
import { windowsDnsParser } from "./windowsDnsParser.js";
import { bindQueryParser } from "./bindQueryParser.js";
import { dnsmasqParser } from "./dnsmasqParser.js";
import { openvpnParser } from "./openvpnParser.js";
import { postgresParser } from "./postgresParser.js";
import { mysqlParser } from "./mysqlParser.js";
import { entraSigninParser } from "./entraSigninParser.js";
import { m365AuditParser } from "./m365AuditParser.js";
import { azureActivityParser } from "./azureActivityParser.js";
import { gcpAuditParser } from "./gcpAuditParser.js";
import { k8sAuditParser } from "./k8sAuditParser.js";
import { wazuhParser } from "./wazuhParser.js";
const SAMPLE_LENGTH = 64 * 1024;
const MIN_CONFIDENCE = 0.5;
export const PARSERS = [
    windowsParser,
    syslogParser,
    auditdParser,
    journaldParser,
    fail2banParser,
    iisParser,
    windowsFirewallParser,
    snortFastParser,
    leefParser,
    pfsenseParser,
    ciscoAsaParser,
    fortigateParser,
    paloAltoParser,
    awsVpcFlowParser,
    awsAlbParser,
    windowsDnsParser,
    bindQueryParser,
    dnsmasqParser,
    openvpnParser,
    postgresParser,
    mysqlParser,
    entraSigninParser,
    m365AuditParser,
    azureActivityParser,
    gcpAuditParser,
    k8sAuditParser,
    wazuhParser,
    zeekParser,
    cloudTrailParser,
    suricataParser,
    cefParser,
    webAccessParser,
    nginxErrorParser,
    apacheErrorParser,
    jsonLogParser,
];
export function detectParser(content) {
    let sample = content.slice(0, SAMPLE_LENGTH);
    if (content.length > SAMPLE_LENGTH && sample.lastIndexOf("\n") > 0) {
        sample = sample.slice(0, sample.lastIndexOf("\n"));
    }
    let best = null;
    for (const parser of PARSERS) {
        let confidence = 0;
        try {
            confidence = parser.detect(sample);
        }
        catch {
            confidence = 0;
        }
        if (best === null || confidence > best.confidence) {
            best = { parser, confidence };
        }
    }
    return best !== null && best.confidence >= MIN_CONFIDENCE ? best : null;
}
export function supportedFormatNames() {
    return PARSERS.map(parser => parser.name);
}
