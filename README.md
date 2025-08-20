# Incident Response & Threat Hunting Lab

### Deliverables

This report documents the findings from a cybersecurity lab exercise, including a comparison of different security logs, an incident report, and a summary of the challenges encountered.

## 1. Comparing Snort/Suricata Alerts with Sysmon Logs

This lab highlights the critical distinction between network-based intrusion detection systems (NIDS) and host-based monitoring tools.

* **Snort and Suricata** are NIDS. They operate by analyzing network traffic and comparing it against a set of rules. In this lab, these tools were instrumental in detecting attacks that occurred over the network, such as the initial ICMP scan, the `Nmap` port scan, and the `SSH` brute-force attempt. Their alerts provide concrete evidence of malicious activity targeting the network's perimeter.

* **Sysmon** is an endpoint security tool that runs on the host itself. Its logs provide a deep look into what is happening on the machine. Sysmon's logs were crucial for detecting the post-exploitation activity, specifically the creation of a suspicious file, the `eicar.com` test virus.

These tools are not interchangeable; they are complementary. A complete security posture requires both NIDS for network-level threats and host-based tools for endpoint-level visibility to correlate events and tell a full story of an attack.

## 2. Incident Report

### What Happened?

An attacker, using the Kali Linux machine (IP: `[Attacker_IP]`), initiated a series of malicious activities against the Ubuntu server (IP: `[Ubuntu_IP]`) and the Windows endpoint (IP: `[Windows_IP]`). The attack began with a reconnaissance phase, specifically a ping sweep (ICMP) and an `Nmap` port scan, and escalated to a brute-force attack targeting the SSH service. The attacker was also able to successfully download a simulated malicious file to the Windows endpoint.

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
[Paste your Snort log for the ICMP and Nmap scans here]
```

### Suricata JSON Alert

**Custom Suricata Rule:**

```
alert ssh any any -> $HOME_NET any (msg:"SSH Brute Force Attempt"; flow:to_server,established; content:"SSH-2.0"; flowbits:noalert; sid:1000003; rev:1;)
```

**Suricata JSON Alert with Attacker IP:**

```
[Paste your Suricata JSON log for the SSH brute force here]
```

### Sysmon Event Logs

**Sysmon Log Evidence:**

```
[Paste your Sysmon Event ID 11 log for the Eicar file here]