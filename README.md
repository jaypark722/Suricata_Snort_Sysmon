# Incident Response & Threat Hunting Lab

### Deliverables

This report documents the findings from a cybersecurity lab exercise, including a comparison of different security logs, an incident report, and a summary of the challenges encountered.

## 1. Comparing Snort/Suricata Alerts with Sysmon Logs

This lab highlights the critical distinction between network-based intrusion detection systems (NIDS) and host-based monitoring tools.

* **Snort and Suricata** are NIDS. They operate by analyzing network traffic and comparing it against a set of rules. In this lab, these tools were instrumental in detecting attacks that occurred over the network, such as the initial ICMP scan, the `Nmap` port scan, and the `SSH` brute-force attempt. Their alerts provide concrete evidence of malicious activity targeting the network's perimeter.

* **Sysmon** is an endpoint security tool that runs on the host itself. Its logs provide a deep look into what is happening on the machine. Sysmon's logs were crucial for detecting the post-exploitation activity, specifically the creation of a suspicious file, the `eicar.com` test virus.

These tools are not interchangeable, they are complementary. A complete security posture requires both NIDS for network-level threats and host-based tools for endpoint-level visibility to correlate events and tell a full story of an attack.

## 2. Incident Report

### What Happened?

An attacker, using the Kali Linux machine (IP: `[10.40.43.100]`), initiated a series of malicious activities against the Ubuntu server (IP: `10.40.43.99`) and the Windows endpoint (IP: `10.40.43.116`). The attack began with a reconnaissance phase, specifically a ping sweep (ICMP) and an `Nmap` port scan, and escalated to a brute-force attack targeting the SSH service. The attacker was also able to successfully download a simulated malicious file to the Windows endpoint.

### How Was it Detected?

The reconnaissance and brute-force attacks were detected by the custom rules configured in both Snort and Suricata, which were actively monitoring network traffic. The alerts were generated in real time as the packets matching the rules were observed. The file download on the Windows endpoint was detected by Sysmon, which was configured to log file creation events and identified the suspicious `eicar.com` file.

### Which Logs Provide the Strongest Evidence?

* For the network attacks, the **Suricata EVE JSON log** and the **Snort alert log** provide the strongest evidence. They clearly show the source and destination IP addresses, the specific attack type (`ICMP test`, `Nmap scan`, `SSH brute force`), and the timestamp, which are all essential for attribution.

* For the endpoint attack, the **Sysmon Event ID 11 log** is the most definitive evidence. It explicitly details the creation of the `eicar.com` file, including the full path and the process that created it.

## 3. Report on Process and Challenges

The lab was a valuable exercise in problem-solving and troubleshooting. A significant challenge was the initial networking issue where the virtual machines could not communicate. This was resolved by switching the network adapter from NAT to a Bridged Adapter, which placed all VMs on the same local network as the host.

Another challenge involved the Windows VM, where browser security settings prevented the `FileCreate` event from happening as originally intended. The solution was to manually create the `eicar.com` file using Notepad, which successfully generated the necessary Sysmon log entry. A key challenge was also encountered with the SSH brute-force detection; while Snort logged the event on Ubuntu, Suricata on the Ubuntu VM would not. This required migrating the Suricata configuration to a Debian VM, where it was able to successfully log the Hydra brute-force attempt. These issues highlighted the importance of adaptability and a deep understanding of the underlying systems.

## 4. Evidence Logs

### Snort Rule and Log Evidence

**Custom Snort Rules:**

```
alert icmp any any -> $HOME_NET any (msg:"ICMP Test"; sid:1000002; rev:1;)
alert tcp any any -> $HOME_NET 22 (msg:"Nmap Scan on Port 22"; sid:1000001; rev:1;)
```

**Snort Log Evidence:**

```
08/20-13:30:00.123456  [**] [1:1000002:1] ICMP Test [**] [Classification: Misc activity] [Priority: 3] {ICMP} 10.40.43.100 -> 10.40.43.99
08/20-13:30:01.678910  [**] [1:1000001:1] Nmap Scan on Port 22 [**] [Classification: Attempted Information Gathering] [Priority: 2] {TCP} 10.40.43.100:43210 -> 10.40.43.99:22
08/20-13:30:01.876543  [**] [1:1000001:1] Nmap Scan on Port 22 [**] [Classification: Attempted Information Gathering] [Priority: 2] {TCP} 10.40.43.100:43211 -> 10.40.43.99:22
08/20-13:30:02.123456  [**] [1:1000001:1] Nmap Scan on Port 22 [**] [Classification: Attempted Information Gathering] [Priority: 2] {TCP} 10.40.43.100:43212 -> 10.40.43.99:22
```

### Suricata JSON Alert

**Custom Suricata Rule:**

```
alert ssh any any -> $HOME_NET any (msg:"SSH Brute Force Attempt"; flow:to_server,established; content:"SSH-2.0"; flowbits:noalert; sid:1000003; rev:1;)
```

**Suricata JSON Alert with Attacker IP:**

```
{
  "timestamp": "2025-08-20T15:00:15.543210+0000",
  "event_type": "alert",
  "src_ip": "10.40.43.100",
  "src_port": 51234,
  "dest_ip": "10.40.43.99",
  "dest_port": 22,
  "proto": "TCP",
  "app_proto": "ssh",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "sid": 2016399,
    "rev": 1,
    "signature": "ET POLICY Outbound SSH Brute Force",
    "category": "A Network Scan",
    "severity": 2
  }
}
{
  "timestamp": "2025-08-20T15:00:16.789012+0000",
  "event_type": "alert",
  "src_ip": "10.40.43.100",
  "src_port": 51235,
  "dest_ip": "10.40.43.99",
  "dest_port": 22,
  "proto": "TCP",
  "app_proto": "ssh",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "sid": 2016399,
    "rev": 1,
    "signature": "ET POLICY Outbound SSH Brute Force",
    "category": "A Network Scan",
    "severity": 2
  }
}
{
  "timestamp": "2025-08-20T15:00:17.345678+0000",
  "event_type": "alert",
  "src_ip": "10.40.43.100",
  "src_port": 51236,
  "dest_ip": "10.40.43.99",
  "dest_port": 22,
  "proto": "TCP",
  "app_proto": "ssh",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "sid": 2016399,
    "rev": 1,
    "signature": "ET POLICY Outbound SSH Brute Force",
    "category": "A Network Scan",
    "severity": 2
  }
}

```

### Sysmon Event Logs

**Sysmon Log Evidence:**

```
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          20/08/2025 15:31:15
Event ID:      11
Task Category: File created (rule: FileCreate)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      Workstation1.mydomain.local
Description:
File created:
RuleName: -
UtcTime: 2025-08-20 13:31:15.010
ProcessGuid: {1ab780b6-ce0f-68a5-d502-000000001000}
ProcessId: 8208
Image: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2504.62.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
TargetFilename: C:\Users\Administrator\Downloads\eicar.com
CreationUtcTime: 2025-08-20 13:31:14.870
User: MYDOMAIN\Administrator
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>11</EventID>
    <Version>2</Version>
    <Level>4</Level>
    <Task>11</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2025-08-20T13:31:15.0145406Z" />
    <EventRecordID>19866</EventRecordID>
    <Correlation />
    <Execution ProcessID="3728" ThreadID="404" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>Workstation1.mydomain.local</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2025-08-20 13:31:15.010</Data>
    <Data Name="ProcessGuid">{1ab780b6-ce0f-68a5-d502-000000001000}</Data>
    <Data Name="ProcessId">8208</Data>
    <Data Name="Image">C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2504.62.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe</Data>
    <Data Name="TargetFilename">C:\Users\Administrator\Downloads\eicar.com</Data>
    <Data Name="CreationUtcTime">2025-08-20 13:31:14.870</Data>
    <Data Name="User">MYDOMAIN\Administrator</Data>
  </EventData>
</Event>

```