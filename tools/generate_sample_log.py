import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.sax.saxutils import escape

random.seed(42)


NS = "http://schemas.microsoft.com/win/2004/08/events/event"
SECURITY = ("Microsoft-Windows-Security-Auditing", "{54849625-5478-4994-A5BA-3E3B0328C30D}")
EVENTLOG = ("Microsoft-Windows-Eventlog", "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}")

DOMAIN = "CORP"
DOMAIN_FQDN = "CORP.LOCAL"
DC = "DC01.corp.local"
DOMAIN_SID = "S-1-5-21-3623811015-3361044348-30300820"

AUDIT_SUCCESS = "0x8020000000000000"
AUDIT_FAILURE = "0x8010000000000000"

USERS = {
    "alice": (1104, "10.0.0.21", "WS-ALICE"),
    "bob": (1105, "10.0.0.22", "WS-BOB"),
    "carol": (1106, "10.0.0.23", "WS-CAROL"),
    "dave": (1107, "10.0.0.24", "WS-DAVE"),
    "helpdesk": (1110, "10.0.0.30", "WS-IT01"),
    "administrator": (500, "10.0.0.5", "ADM-PC"),
    "svc_sql": (1120, "10.0.0.40", "SQL01"),
}
WORKSTATIONS = ["WS-ALICE", "WS-BOB", "WS-CAROL", "WS-DAVE", "WS-IT01", "SQL01", "FS01"]

ATTACKER_RDP_IP = "203.0.113.45"
ATTACKER_SPRAY_IP = "198.51.100.23"

ADMIN_PRIVILEGES = "\n\t\t\t".join([
    "SeSecurityPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege",
    "SeDebugPrivilege", "SeSystemEnvironmentPrivilege", "SeLoadDriverPrivilege",
    "SeImpersonatePrivilege", "SeDelegateSessionUserImpersonatePrivilege", "SeEnableDelegationPrivilege",
])
SYSTEM_PRIVILEGES = "\n\t\t\t".join([
    "SeAssignPrimaryTokenPrivilege", "SeTcbPrivilege", "SeSecurityPrivilege", "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeDebugPrivilege",
    "SeAuditPrivilege", "SeSystemEnvironmentPrivilege", "SeImpersonatePrivilege",
    "SeDelegateSessionUserImpersonatePrivilege",
])

MESSAGES = {
    "4624": "An account was successfully logged on.",
    "4625": "An account failed to log on.",
    "4634": "An account was logged off.",
    "4647": "User initiated logoff:",
    "4648": "A logon was attempted using explicit credentials.",
    "4672": "Special privileges assigned to new logon.",
    "4673": "A privileged service was called.",
    "4688": "A new process has been created.",
    "4697": "A service was installed in the system.",
    "4698": "A scheduled task was created.",
    "4720": "A user account was created.",
    "4722": "A user account was enabled.",
    "4724": "An attempt was made to reset an account's password.",
    "4728": "A member was added to a security-enabled global group.",
    "4732": "A member was added to a security-enabled local group.",
    "4740": "A user account was locked out.",
    "4741": "A computer account was created.",
    "4767": "A user account was unlocked.",
    "4768": "A Kerberos authentication ticket (TGT) was requested.",
    "4769": "A Kerberos service ticket was requested.",
    "4771": "Kerberos pre-authentication failed.",
    "4776": "The computer attempted to validate the credentials for an account.",
    "4778": "A session was reconnected to a Window Station.",
    "4779": "A session was disconnected from a Window Station.",
    "4798": "A user's local group membership was enumerated.",
    "4799": "A security-enabled local group membership was enumerated.",
    "4800": "The workstation was locked.",
    "4801": "The workstation was unlocked.",
    "4825": "A user was denied the access to Remote Desktop.",
    "4964": "Special groups have been assigned to a new logon.",
    "5379": "Credential Manager credentials were read.",
    "5061": "Cryptographic operation.",
    "4662": "An operation was performed on an object.",
    "4656": "A handle to an object was requested.",
    "4663": "An attempt was made to access an object.",
    "4660": "An object was deleted.",
    "4657": "A registry value was modified.",
    "5136": "A directory service object was modified.",
    "5140": "A network share object was accessed.",
    "5145": "A network share object was checked to see whether client can be granted desired access.",
    "5156": "The Windows Filtering Platform has permitted a connection.",
    "5157": "The Windows Filtering Platform has blocked a connection.",
    "4946": "A change has been made to Windows Firewall exception list. A rule was added.",
    "4719": "System audit policy was changed.",
    "4616": "The system time was changed.",
    "4608": "Windows is starting up.",
    "4609": "Windows is shutting down.",
    "4826": "Boot Configuration Data loaded.",
    "6416": "A new external device was recognized by the system.",
    "4985": "The state of a transaction has changed.",
    "1102": "The audit log was cleared.",
    "1100": "The event logging service has shut down.",
}


events: list[tuple[datetime, str, str, dict[str, str], str, str | None]] = []

DAY = datetime(2026, 10, 13, tzinfo=timezone.utc)


def at(hour: int, minute: int = 0, second: int = 0) -> datetime:
    return DAY + timedelta(hours=hour, minutes=minute, seconds=second)


def add(time: datetime, event_id: int, data: dict, failure: bool = False,
        provider=SECURITY, user_data: str | None = None) -> None:
    keywords = AUDIT_FAILURE if failure else AUDIT_SUCCESS
    events.append((time, str(event_id), keywords, data, provider, user_data))


def sid(user: str) -> str:
    return f"{DOMAIN_SID}-{USERS[user][0]}"


def logon_id() -> str:
    return hex(random.randint(0x100000, 0xFFFFFFF))


def subject_system() -> dict:
    return {"SubjectUserSid": "S-1-5-18", "SubjectUserName": "DC01$",
            "SubjectDomainName": DOMAIN, "SubjectLogonId": "0x3e7"}


def subject_user(user: str) -> dict:
    return {"SubjectUserSid": sid(user), "SubjectUserName": user,
            "SubjectDomainName": DOMAIN, "SubjectLogonId": logon_id()}


def logon_success(time, user, logon_type, ip, process="-", auth="Kerberos", elevated=False):
    add(time, 4624, {
        **subject_system(),
        "TargetUserSid": sid(user) if user in USERS else "S-1-5-18",
        "TargetUserName": user, "TargetDomainName": DOMAIN, "TargetLogonId": logon_id(),
        "LogonType": str(logon_type), "LogonProcessName": "User32" if logon_type in (2, 10) else auth,
        "AuthenticationPackageName": "Negotiate" if logon_type in (2, 10) else auth,
        "WorkstationName": USERS.get(user, (0, "", "-"))[2], "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
        "TransmittedServices": "-", "LmPackageName": "-", "KeyLength": "0",
        "ProcessId": "0x0", "ProcessName": process, "IpAddress": ip, "IpPort": str(random.randint(49152, 65535)),
        "ImpersonationLevel": "%%1833", "RestrictedAdminMode": "-",
        "VirtualAccount": "%%1843", "ElevatedToken": "%%1842" if elevated else "%%1843",
    })


def logon_failure(time, user, logon_type, ip, sub_status, workstation="-"):
    add(time, 4625, {
        "SubjectUserSid": "S-1-0-0", "SubjectUserName": "-", "SubjectDomainName": "-", "SubjectLogonId": "0x0",
        "TargetUserSid": "S-1-0-0", "TargetUserName": user, "TargetDomainName": DOMAIN,
        "Status": "0xc000006d" if sub_status in ("0xc000006a", "0xc0000064") else sub_status,
        "FailureReason": "%%2313", "SubStatus": sub_status,
        "LogonType": str(logon_type), "LogonProcessName": "NtLmSsp", "AuthenticationPackageName": "NTLM",
        "WorkstationName": workstation, "TransmittedServices": "-", "LmPackageName": "-", "KeyLength": "0",
        "ProcessId": "0x0", "ProcessName": "-", "IpAddress": ip, "IpPort": str(random.randint(49152, 65535)),
    }, failure=True)


def tgt(time, account, ip, status="0x0"):
    add(time, 4768, {
        "TargetUserName": account, "TargetDomainName": DOMAIN_FQDN,
        "TargetSid": sid(account) if account in USERS else f"{DOMAIN_SID}-{random.randint(2000, 2100)}",
        "ServiceName": "krbtgt", "ServiceSid": f"{DOMAIN_SID}-502", "TicketOptions": "0x40810010",
        "Status": status, "TicketEncryptionType": "0x12" if status == "0x0" else "0xffffffff",
        "PreAuthType": "2", "IpAddress": f"::ffff:{ip}", "IpPort": str(random.randint(49152, 65535)),
    }, failure=status != "0x0")


def service_ticket(time, account, service, ip, encryption="0x12"):
    add(time, 4769, {
        "TargetUserName": f"{account}@{DOMAIN_FQDN}", "TargetDomainName": DOMAIN_FQDN,
        "ServiceName": service, "ServiceSid": f"{DOMAIN_SID}-{random.randint(1200, 1300)}",
        "TicketOptions": "0x40810000", "TicketEncryptionType": encryption,
        "IpAddress": f"::ffff:{ip}", "IpPort": str(random.randint(49152, 65535)),
        "Status": "0x0", "LogonGuid": "{" + f"{random.getrandbits(128):032x}" + "}", "TransmittedServices": "-",
    })


def process(time, user, path, parent, command_line=""):
    add(time, 4688, {
        **subject_user(user), "NewProcessId": hex(random.randint(0x1000, 0xFFFF)), "NewProcessName": path,
        "TokenElevationType": "%%1936", "ProcessId": hex(random.randint(0x1000, 0xFFFF)),
        "CommandLine": command_line, "TargetUserSid": "S-1-0-0", "TargetUserName": "-",
        "ParentProcessName": parent, "MandatoryLabel": "S-1-16-12288",
    })


add(at(7, 58), 4608, {})
add(at(7, 58, 1), 4826, {"LoadOptions": "-", "AdvancedOptions": "%%1843", "ConfigAccessPolicy": "%%1846",
                         "RemoteEventLogging": "%%1843", "KernelDebug": "%%1843", "VsmLaunchType": "%%1848",
                         "TestSigning": "%%1843", "FlightSigning": "%%1843", "DisableIntegrityChecks": "%%1843",
                         "HypervisorLaunchType": "%%1848", "HypervisorDebug": "%%1843"})


minute = 0
while minute < 24 * 60 - 20:
    t = at(8) + timedelta(minutes=minute, seconds=random.randint(0, 50))
    logon_success(t, "SYSTEM", 5, "-", process="C:\\Windows\\System32\\services.exe")
    add(t + timedelta(milliseconds=5), 4672, {**subject_system(), "SubjectUserName": "SYSTEM",
                                              "SubjectDomainName": "NT AUTHORITY", "PrivilegeList": SYSTEM_PRIVILEGES})
    station = random.choice(WORKSTATIONS)
    station_ip = f"10.0.0.{random.randint(50, 90)}"
    tgt(t + timedelta(seconds=7), f"{station}$", station_ip)
    service_ticket(t + timedelta(seconds=8), f"{station}$", "DC01$", station_ip)
    if minute % 60 == 0:
        add(t + timedelta(seconds=20), 5061, {**subject_system(), "ProviderName": "Microsoft Software Key Storage Provider",
                                               "AlgorithmName": "RSA", "KeyName": "TSSecKeySet1", "KeyType": "%%2499",
                                               "Operation": "%%2480", "ReturnCode": "0x0"})
        add(t + timedelta(seconds=25), 4985, {**subject_system(), "TransactionId": "{" + f"{random.getrandbits(128):032x}" + "}",
                                               "NewState": "52", "ResourceManager": "{00000000-0000-0000-0000-000000000000}",
                                               "ProcessId": "0x2e8", "ProcessName": "C:\\Windows\\System32\\svchost.exe"})
    minute += 6


for user, start in [("alice", at(8, 31)), ("bob", at(8, 47)), ("carol", at(9, 5)), ("dave", at(9, 12)),
                    ("helpdesk", at(8, 20))]:
    _, ip, station = USERS[user]
    tgt(start, user, ip)
    service_ticket(start + timedelta(seconds=1), user, "LDAP/DC01.corp.local", ip)
    service_ticket(start + timedelta(seconds=2), user, "cifs/FS01.corp.local", ip)
    logon_success(start + timedelta(seconds=3), user, 3, ip)
    add(start + timedelta(seconds=4), 5140, {**subject_user(user), "ObjectType": "File", "IpAddress": ip,
                                              "IpPort": str(random.randint(49152, 65535)),
                                              "ShareName": "\\\\*\\SYSVOL", "ShareLocalPath": "\\??\\C:\\Windows\\SYSVOL\\sysvol",
                                              "AccessMask": "0x1", "AccessList": "%%4416"})
    add(start + timedelta(minutes=2), 4798, {"TargetUserName": user, "TargetDomainName": DOMAIN,
                                              "TargetSid": sid(user), **subject_user(user),
                                              "CallerProcessId": "0x1a2c", "CallerProcessName": "C:\\Windows\\explorer.exe"})
    add(at(12, random.randint(0, 20)), 4800, {"TargetUserSid": sid(user), "TargetUserName": user,
                                               "TargetDomainName": DOMAIN, "TargetLogonId": logon_id(), "SessionId": "2"})
    add(at(12, random.randint(40, 59)), 4801, {"TargetUserSid": sid(user), "TargetUserName": user,
                                                "TargetDomainName": DOMAIN, "TargetLogonId": logon_id(), "SessionId": "2"})
    end = at(18, random.randint(0, 40))
    add(end, 4634, {"TargetUserSid": sid(user), "TargetUserName": user, "TargetDomainName": DOMAIN,
                    "TargetLogonId": logon_id(), "LogonType": "3"})

logon_success(at(9, 30), "administrator", 10, "10.0.0.5", process="C:\\Windows\\System32\\svchost.exe", elevated=True)
add(at(9, 30, 1), 4672, {**subject_user("administrator"), "PrivilegeList": ADMIN_PRIVILEGES})
add(at(9, 30, 1), 4964, {"LogonGuid": "{00000000-0000-0000-0000-000000000000}", "TargetUserName": "administrator",
                         "TargetDomainName": DOMAIN, "TargetUserSid": sid("administrator"), "TargetLogonId": logon_id(),
                         "SidList": f"%{{{DOMAIN_SID}-512}}"})
add(at(9, 31), 5379, {**subject_user("administrator"), "TargetName": "Domain:target=TERMSRV/FS01",
                      "Type": "1", "CountOfCredentialsReturned": "1", "ReadOperation": "%%8100", "ReturnCode": "0"})
add(at(11, 40), 4779, {"AccountName": "administrator", "AccountDomain": DOMAIN, "LogonID": logon_id(),
                       "SessionName": "RDP-Tcp#3", "ClientName": "ADM-PC", "ClientAddress": "10.0.0.5"})
add(at(12, 55), 4778, {"AccountName": "administrator", "AccountDomain": DOMAIN, "LogonID": logon_id(),
                       "SessionName": "RDP-Tcp#5", "ClientName": "ADM-PC", "ClientAddress": "10.0.0.5"})
add(at(10, 5), 4741, {"TargetUserName": "WS-NEW01$", "TargetDomainName": DOMAIN, "TargetSid": f"{DOMAIN_SID}-1130",
                      **subject_user("administrator"), "SamAccountName": "WS-NEW01$", "DnsHostName": "WS-NEW01.corp.local"})
add(at(10, 20), 6416, {**subject_system(), "DeviceId": "USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00",
                       "DeviceDescription": "SanDisk Ultra USB Device", "ClassId": "{4d36e967-e325-11ce-bfc1-08002be10318}",
                       "ClassName": "DiskDrive", "VendorIds": "USBSTOR\\DiskSanDisk_", "CompatibleIds": "USBSTOR\\Disk",
                       "LocationInformation": "-"})
add(at(10, 40), 4825, {"AccountName": "bob", "AccountDomain": DOMAIN, "LogonID": logon_id(),
                       "ClientAddress": "10.0.0.22"}, failure=True)


add(at(10, 15), 4771, {"TargetUserName": "bob", "TargetSid": sid("bob"), "ServiceName": f"krbtgt/{DOMAIN}",
                       "TicketOptions": "0x40810010", "Status": "0x18", "PreAuthType": "2",
                       "IpAddress": "::ffff:10.0.0.22", "IpPort": "50211"}, failure=True)
tgt(at(10, 15, 40), "bob", "10.0.0.22")


for i in range(5):
    add(at(11, 0, i * 12), 4771, {"TargetUserName": "carol", "TargetSid": sid("carol"), "ServiceName": f"krbtgt/{DOMAIN}",
                                   "TicketOptions": "0x40810010", "Status": "0x18", "PreAuthType": "2",
                                   "IpAddress": "::ffff:10.0.0.23", "IpPort": str(50300 + i)}, failure=True)
add(at(11, 1), 4740, {"TargetUserName": "carol", "TargetDomainName": "WS-CAROL", "TargetSid": sid("carol"),
                      **subject_system()})
tgt(at(11, 2), "carol", "10.0.0.23", status="0x12")
add(at(11, 10), 4767, {"TargetUserName": "carol", "TargetDomainName": DOMAIN, "TargetSid": sid("carol"),
                       **subject_user("helpdesk")})
add(at(11, 11), 4724, {"TargetUserName": "carol", "TargetDomainName": DOMAIN, "TargetSid": sid("carol"),
                       **subject_user("helpdesk")})
tgt(at(11, 13), "carol", "10.0.0.23")

for t, user, code in [(at(9, 50), "dave", "0xc0000071"),
                      (at(9, 55), "old_intern", "0xc0000072"),
                      (at(11, 20), "carol", "0xc0000234"),
                      (at(19, 30), "alice", "0xc000006f"),
                      (at(16, 0), "dave", "0xc000015b")]:
    logon_failure(t, user, 3, USERS.get(user, (0, "10.0.0.99", "-"))[1], code)


for i in range(3):
    add(at(12, 5 + i), 4673, {**subject_user("alice"), "ObjectServer": "Security", "Service": "-",
                              "PrivilegeList": "SeProfileSingleProcessPrivilege", "ProcessId": "0x2f1c",
                              "ProcessName": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"}, failure=True)


spray_users = list(USERS.keys()) + [f"user{i:02d}" for i in range(1, 19)]
for i, user in enumerate(spray_users):
    t = at(13, 0) + timedelta(seconds=i * 9)
    code = "0xc000006a" if user in USERS else "0xc0000064"
    logon_failure(t, user, 3, ATTACKER_SPRAY_IP, code, workstation="KALI")
    add(t + timedelta(milliseconds=200), 4776, {"PackageName": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
                                                 "TargetUserName": user, "Workstation": "KALI", "Status": code},
        failure=True)


for i in range(40):
    logon_failure(at(14, 0) + timedelta(seconds=i * 6), "administrator", 10, ATTACKER_RDP_IP, "0xc000006a",
                  workstation="WIN-ATTACK")
for i in range(6):
    logon_failure(at(14, 4) + timedelta(seconds=i * 5), "svc_sql", 10, ATTACKER_RDP_IP, "0xc000006a",
                  workstation="WIN-ATTACK")
logon_success(at(14, 5), "svc_sql", 10, ATTACKER_RDP_IP, process="C:\\Windows\\System32\\svchost.exe", elevated=True)
add(at(14, 5, 1), 4672, {**subject_user("svc_sql"), "PrivilegeList": ADMIN_PRIVILEGES})


recon = [("C:\\Windows\\System32\\whoami.exe", "whoami /all"),
         ("C:\\Windows\\System32\\net.exe", "net group \"Domain Admins\" /domain"),
         ("C:\\Windows\\System32\\nltest.exe", "nltest /dclist:corp.local"),
         ("C:\\Windows\\System32\\net.exe", "net user /domain")]
for i, (path, cmd) in enumerate(recon):
    process(at(14, 20, i * 20), "svc_sql", path, "C:\\Windows\\System32\\cmd.exe", cmd)
for group in ["Administrators", "Remote Desktop Users", "Backup Operators"]:
    add(at(14, 22), 4799, {"TargetUserName": group, "TargetDomainName": "Builtin", "TargetSid": "S-1-5-32-544",
                           **subject_user("svc_sql"), "CallerProcessId": "0x1f00",
                           "CallerProcessName": "C:\\Windows\\System32\\net.exe"})


for i, spn in enumerate(["MSSQLSvc/SQL01.corp.local:1433", "HTTP/intranet.corp.local", "CIFS/BACKUP01.corp.local",
                         "MSSQLSvc/SQL02.corp.local:1433", "FTP/files.corp.local", "HTTP/crm.corp.local"]):
    service_ticket(at(14, 30, i * 3), "svc_sql", spn, ATTACKER_RDP_IP, encryption="0x17")


for right in ["{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}", "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"]:
    add(at(14, 40), 4662, {**subject_user("svc_sql"), "ObjectServer": "DS", "ObjectType": "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}",
                           "ObjectName": "%{" + f"{random.getrandbits(128):032x}" + "}", "OperationType": "Object Access",
                           "HandleId": "0x0", "AccessList": "%%7688", "AccessMask": "0x100",
                           "Properties": f"%%7688\n\t\t{right}\n\t{{19195a5b-6da0-11d0-afd3-00c04fd930c9}}",
                           "AdditionalInfo": "-", "AdditionalInfo2": ""})


add(at(14, 45), 4720, {"TargetUserName": "helpdesk_tmp", "TargetDomainName": DOMAIN, "TargetSid": f"{DOMAIN_SID}-1150",
                       **subject_user("svc_sql"), "SamAccountName": "helpdesk_tmp", "DisplayName": "%%1793",
                       "UserPrincipalName": "-", "PasswordLastSet": "%%1794", "AccountExpires": "%%1794"})
add(at(14, 45, 2), 4722, {"TargetUserName": "helpdesk_tmp", "TargetDomainName": DOMAIN,
                          "TargetSid": f"{DOMAIN_SID}-1150", **subject_user("svc_sql")})
add(at(14, 45, 10), 4728, {"MemberName": "CN=helpdesk_tmp,CN=Users,DC=corp,DC=local", "MemberSid": f"{DOMAIN_SID}-1150",
                           "TargetUserName": "Domain Admins", "TargetDomainName": DOMAIN, "TargetSid": f"{DOMAIN_SID}-512",
                           **subject_user("svc_sql")})
add(at(14, 45, 12), 4732, {"MemberName": "-", "MemberSid": f"{DOMAIN_SID}-1150", "TargetUserName": "Administrators",
                           "TargetDomainName": "Builtin", "TargetSid": "S-1-5-32-544", **subject_user("svc_sql")})
add(at(14, 46), 5136, {"OpCorrelationID": "{" + f"{random.getrandbits(128):032x}" + "}", **subject_user("svc_sql"),
                       "DSName": "corp.local", "DSType": "%%14676",
                       "ObjectDN": "CN=AdminSDHolder,CN=System,DC=corp,DC=local", "ObjectGUID": "{-}",
                       "ObjectClass": "container", "AttributeLDAPDisplayName": "nTSecurityDescriptor",
                       "AttributeSyntaxOID": "2.5.5.15", "AttributeValue": "O:DAG:DAD:(A;;GA;;;S-1-5-21-...-1150)",
                       "OperationType": "%%14674"})
add(at(14, 47), 4698, {**subject_user("svc_sql"), "TaskName": "\\Microsoft\\Windows\\Update\\WinUpdateCheck",
                       "TaskContent": "<Task><Actions><Exec><Command>powershell.exe</Command>"
                                      "<Arguments>-nop -w hidden -enc SQBFAFgA...</Arguments></Exec></Actions></Task>"})
add(at(14, 48), 4697, {**subject_user("svc_sql"), "ServiceName": "PSEXESVC",
                       "ServiceFileName": "%SystemRoot%\\PSEXESVC.exe", "ServiceType": "0x10",
                       "ServiceStartType": "3", "ServiceAccount": "LocalSystem"})
add(at(14, 49), 4946, {"ProfileChanged": "All", "RuleId": "{" + f"{random.getrandbits(128):032x}" + "}",
                       "RuleName": "Windows Update Helper (TCP-Out 4444)"})
add(at(14, 50), 4657, {**subject_user("svc_sql"),
                       "ObjectName": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                       "ObjectValueName": "WinUpdate", "HandleId": "0x2a4", "OperationType": "%%1904",
                       "OldValueType": "-", "OldValue": "-", "NewValueType": "%%1873",
                       "NewValue": "C:\\Users\\Public\\upd.exe", "ProcessId": "0x1f44",
                       "ProcessName": "C:\\Windows\\System32\\reg.exe"})


add(at(15, 0), 4648, {**subject_user("svc_sql"), "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
                      "TargetUserName": "helpdesk_tmp", "TargetDomainName": DOMAIN,
                      "TargetLogonGuid": "{00000000-0000-0000-0000-000000000000}", "TargetServerName": "FS01.corp.local",
                      "TargetInfo": "FS01.corp.local", "ProcessId": "0x4", "ProcessName": "C:\\Windows\\System32\\cmd.exe",
                      "IpAddress": "-", "IpPort": "-"})
add(at(15, 1), 5140, {**subject_user("svc_sql"), "ObjectType": "File", "IpAddress": ATTACKER_RDP_IP, "IpPort": "51022",
                      "ShareName": "\\\\*\\ADMIN$", "ShareLocalPath": "\\??\\C:\\Windows", "AccessMask": "0x3",
                      "AccessList": "%%4416\n\t\t\t\t%%4417"})
add(at(15, 1, 5), 5145, {**subject_user("svc_sql"), "ObjectType": "File", "IpAddress": ATTACKER_RDP_IP, "IpPort": "51022",
                         "ShareName": "\\\\*\\ADMIN$", "ShareLocalPath": "\\??\\C:\\Windows", "RelativeTargetName": "PSEXESVC.exe",
                         "AccessMask": "0x2", "AccessList": "%%4417", "AccessReason": "-"})


add(at(15, 10), 4663, {**subject_user("svc_sql"), "ObjectServer": "Security", "ObjectType": "File",
                       "ObjectName": "C:\\Shares\\Finance\\salaries_2026.xlsx", "HandleId": "0x1c4",
                       "AccessList": "%%4416", "AccessMask": "0x1", "ProcessId": "0x1f00",
                       "ProcessName": "C:\\Windows\\explorer.exe", "ResourceAttributes": "-"})
add(at(15, 12), 4656, {**subject_user("svc_sql"), "ObjectServer": "Security", "ObjectType": "File",
                       "ObjectName": "C:\\Windows\\NTDS\\ntds.dit", "HandleId": "0x0", "TransactionId": "{-}",
                       "AccessList": "%%1538\n\t\t\t\t%%4416", "AccessReason": "-", "AccessMask": "0x20001",
                       "PrivilegeList": "-", "RestrictedSidCount": "0", "ProcessId": "0x2210",
                       "ProcessName": "C:\\Windows\\System32\\cmd.exe", "ResourceAttributes": "-"}, failure=True)
add(at(15, 14), 4663, {**subject_user("svc_sql"), "ObjectServer": "Security", "ObjectType": "File",
                       "ObjectName": "C:\\Shares\\Finance\\audit_trail.log", "HandleId": "0x1d0",
                       "AccessList": "%%1537", "AccessMask": "0x10000", "ProcessId": "0x1f00",
                       "ProcessName": "C:\\Windows\\explorer.exe", "ResourceAttributes": "-"})
add(at(15, 14, 1), 4660, {**subject_user("svc_sql"), "ObjectServer": "Security", "HandleId": "0x1d0",
                          "ProcessId": "0x1f00", "ProcessName": "C:\\Windows\\explorer.exe", "TransactionId": "{-}"})


add(at(15, 20), 5156, {"ProcessID": "4", "Application": "System", "Direction": "%%14592",
                       "SourceAddress": "10.0.0.10", "SourcePort": "445", "DestAddress": ATTACKER_RDP_IP,
                       "DestPort": "51022", "Protocol": "6", "FilterRTID": "0", "LayerName": "%%14610", "LayerRTID": "44"})
for i in range(4):
    add(at(15, 30, i * 30), 5157, {"ProcessID": "8724",
                                    "Application": "\\device\\harddiskvolume2\\users\\public\\upd.exe",
                                    "Direction": "%%14593", "SourceAddress": "10.0.0.10",
                                    "SourcePort": str(55000 + i), "DestAddress": ATTACKER_RDP_IP, "DestPort": "4444",
                                    "Protocol": "6", "FilterRTID": "0", "LayerName": "%%14611", "LayerRTID": "48"},
        failure=True)


add(at(15, 40), 4719, {**subject_system(), "CategoryId": "%%8274", "SubcategoryId": "%%12801",
                       "SubcategoryGuid": "{0cce9215-69ae-11d9-bed3-505054503030}", "AuditPolicyChanges": "%%8448, %%8450"})
add(at(15, 41), 4616, {**subject_user("svc_sql"), "PreviousTime": "2026-10-13T15:41:00.0000000Z",
                       "NewTime": "2026-10-13T11:00:00.0000000Z", "ProcessId": "0x1f00",
                       "ProcessName": "C:\\Windows\\System32\\cmd.exe"})
add(at(15, 42), 1102, {}, provider=EVENTLOG,
    user_data='<LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">'
              f'<SubjectUserSid>{sid("svc_sql")}</SubjectUserSid><SubjectUserName>svc_sql</SubjectUserName>'
              f'<SubjectDomainName>{DOMAIN}</SubjectDomainName><SubjectLogonId>0x8a4f2</SubjectLogonId></LogFileCleared>')


add(at(23, 50), 4647, {"TargetUserSid": sid("administrator"), "TargetUserName": "administrator",
                       "TargetDomainName": DOMAIN, "TargetLogonId": logon_id()})
add(at(23, 51), 4609, {})
add(at(23, 51, 2), 1100, {}, provider=EVENTLOG,
    user_data='<ServiceShutdown xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog"/>')


def render(index: int, time: datetime, event_id: str, keywords: str, data: dict,
           provider: tuple[str, str], user_data: str | None) -> str:
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S.") + f"{time.microsecond * 10 + random.randint(0, 9):07d}Z"
    level = "4" if provider is EVENTLOG else "0"

    if user_data is not None:
        body = f"<UserData>{user_data}</UserData>"
    else:
        fields = "".join(f'<Data Name="{name}">{escape(str(value))}</Data>' for name, value in data.items())
        body = f"<EventData>{fields}</EventData>" if fields else "<EventData/>"

    message_lines = [MESSAGES.get(event_id, "")]
    message_lines += [f"\t{name}:\t{value}" for name, value in list(data.items())[:8]]
    message = escape("\n".join(message_lines))

    return (
        f'<Event xmlns="{NS}"><System>'
        f'<Provider Name="{provider[0]}" Guid="{provider[1]}"/>'
        f"<EventID>{event_id}</EventID><Version>0</Version><Level>{level}</Level>"
        f"<Task>12544</Task><Opcode>0</Opcode><Keywords>{keywords}</Keywords>"
        f'<TimeCreated SystemTime="{timestamp}"/><EventRecordID>{184000 + index}</EventRecordID>'
        f'<Correlation/><Execution ProcessID="784" ThreadID="{random.randint(800, 9000)}"/>'
        f"<Channel>Security</Channel><Computer>{DC}</Computer><Security/></System>"
        f"{body}"
        f'<RenderingInfo Culture="en-US"><Message>{message}</Message>'
        f"<Level>Information</Level><Task>Logon</Task><Opcode>Info</Opcode>"
        f"<Channel>Security</Channel><Provider>Microsoft Windows security auditing.</Provider>"
        f"<Keywords><Keyword>{'Audit Failure' if keywords == AUDIT_FAILURE else 'Audit Success'}</Keyword></Keywords>"
        f"</RenderingInfo></Event>"
    )


events.sort(key=lambda item: item[0])

output = Path(__file__).resolve().parent.parent / "samples" / "sample_dc_full.xml"
output.parent.mkdir(exist_ok=True)

with output.open("w", encoding="utf-8") as file:
    file.write('<?xml version="1.0" encoding="UTF-8"?>\n<Events>\n')
    for index, event in enumerate(events):
        file.write(render(index, *event) + "\n")
    file.write("</Events>\n")

print(f"Written {len(events)} events to {output}")
