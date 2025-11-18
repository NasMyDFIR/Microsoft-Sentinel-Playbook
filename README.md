# Azure Honeypot & Microsoft Sentinel End-to-End Lab

**Linux (Cowrie) + Windows (RDP) Honeypots • Log Analytics • KQL • Sentinel • Automation (AbuseIPDB)**

This project demonstrates the complete deployment, ingestion, analysis, visualization, and automation pipeline for a multi-platform honeypot environment in Microsoft Azure.

It includes:

* A **Linux honeypot (Cowrie)**
* A **Windows honeypot**
* **Log Analytics ingestion & schema creation**
* **KQL queries, functions, and alerts**
* **Microsoft Sentinel workbooks & playbooks**
* **IP enrichment automation with AbuseIPDB**

# Part 1-Linux Honeypot (Cowrie) Deployment on Azure

This section covers deploying the Cowrie Linux honeypot on Ubuntu in Azure to capture attacker activity.

## Overview

* Deploy an Ubuntu VM
* Install and configure Cowrie
* Generate attacker activity
* Extract honeypot logs
* Prepare for SIEM ingestion

Cowrie mimics a vulnerable Linux system and logs attacker commands, malware drops, login attempts, and network activity.

## 1. Azure Setup

**Register Microsoft.Insights**

```
Subscriptions → Your Subscription → Resource Providers → Microsoft.Insights → Register
```

## 2. Create Resource Group

```
Name: project  
Region: closest to your location
```

## 3. Deploy Linux VM

```
Name: LinuxHoneypot  
Image: Ubuntu Server 20.04 LTS  
Size: B1s  
Security Type: Standard  
Auth: Password
```

Azure auto-creates VNet, NIC, NSG, Public IP.

## 4. Restrict Initial SSH Access

Edit NSG rule → SSH → Source = *My IP Address*

## 5. SSH into the VM

```
ssh <username>@<publicIP>
```

## 6. Update Ubuntu

```
sudo apt-get update && sudo apt-get upgrade -y
```

## 7. Install Cowrie Dependencies

Install packages per Cowrie GitHub instructions.
```
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt install python3.12 python3.12-dev python3.12-venv
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1
python3 --version
sudo apt-get install git python3-virtualenv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind virtualenv python3.8-venv
```

## 8. Create Cowrie User

```
sudo adduser --disabled-password cowrie
sudo su cowrie
cd /home/cowrie
```

## 9. Download Cowrie

```
git clone <http://github.com/cowrie/cowrie>
cd cowrie
```

## 10. Python Virtual Environment

```
python3 -m venv cowrie-env
source cowrie-env/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e .
```

## 11. Enable Telnet (optional)

```
cd etc
nano cowrie.cfg
[telnet]
enabled = true
```

## 12. Start Cowrie

```
cd /home/cowrie
cowrie start
```

Cowrie now listens on:

* **SSH:** 2222
* **Telnet:** if enabled

## 13. View Cowrie Logs

```
cd /home/cowrie/cowrie/var/log/cowrie
cat cowrie.json
```

## 14. Simulate Attacker Activity

Allow NSG inbound: 22, 2222

Failed SSH:

```
ssh bob@<publicIP> -p 2222
```

Successful login (Cowrie always accepts root):

```
ssh root@<publicIP> -p 2222
```

## 15. Extract Logs

Run simple server:

```
python3 -m http.server 9999
```

Download via browser:

```
http://<publicIP>:9999
```

Cowrie honeypot fully operational and logging attacker activity.

---

# Part 2 - Azure Log Analytics Configuration for Cowrie Logs

This section covers creating the custom log table and ingestion pipeline. There will be a slight change in this part because Microsoft Monitoring Agent (MMA) no longer parses structured JSON (RawData) fields from uploaded files like it used to. This means if you upload cowrie.json, you will likely see empty values under the RawData column.

## What You Should Do Instead
- Upload cowrie.log instead of cowrie.json

Stick with everything else in the walkthrough, but upload the plain text cowrie.log file (not the JSON version). It still contains all the relevant SSH activity just in a different format.

Default location: /home/cowrie/cowrie/var/log/cowrie/cowrie.log
- Use Regex to Parse Key Fields

Since the data isn’t in JSON anymore, you’ll need to use regular expressions (regex) to pull out fields like IP, username, and password.

Here’s a sample query that works with cowrie.log please feel free to use it as a starting point.

```
// name of table - uncomment this line and replace with your table name
| where RawData has "login attempt" and RawData has "succeeded"
| extend 
    SourceIP = extract(@"\[HoneyPotSSHTransport,\d+,([\d\.]+)\]", 1, RawData),
    Username = extract(@"login attempt \[b'([^']+)'", 1, RawData),
    Password = extract(@"\/b'([^']+)'\]", 1, RawData)
| extend 
    ip_location = geo_info_from_ip_address(SourceIP)
| extend country = ip_location.country
| extend latitude = ip_location.latitude
| extend longitude = ip_location.longitude
| summarize count() by tostring(country), Username, SourceIP
| top 10 by count_
```

## 1. Create Log Analytics Workspace

```
Name: project-honeypot
Group: project
```

## 2. Create Custom Table for Cowrie

Upload `cowrie.json` → Create Custom Log.

```
Name: cowrie_json
Type: Custom Log (Classic)
```

Switch to manual schema management.

## 3. Create Data Collection Endpoint (DCE)

```
Name: LinuxMachine
```

## 4. Create Data Collection Rule (DCR)

```
Name: CollectCowrie  
Type: Linux  
DCE: LinuxMachine  
Resource: LinuxHoneypot VM  
Source: Custom JSON Logs  
Table: cowrie_json_CL  
```

## 6. Query the Logs

```
cowrie_json_CL
| take 50
```

# Part 3 - KQL Queries, Functions & Alerts for Cowrie Honeypot

## 1. Generate New Events

Failed SSH & Successful SSH (root login).

## 2. Basic Query

```
cowrie_json_CL | take 10
```

## 3. Add Columns with extend

```
| extend src_ip = tostring(parse_json(RawData).source_ip)
| extend username = tostring(parse_json(RawData).username)
| extend eventID  = tostring(parse_json(RawData).eventid)
| extend message = tostring(parse_json(RawData).message)
```

## 4. Clean Dataset with project

```
| project TimeGenerated, username, src_ip, eventID, message
```

Save as **cowrie-events**.

## 5. Alert Rule — Successful SSH Login

Filter for:

```
| where eventid == "cowrie.login.success"
```

Create alert by:
1. Click New Alert Rule.
2. Signal Type: Custom log search.
3. Condition:
- Threshold operator: >
- Threshold value: 0
- Loopback window: 5 minutes
4. Action Group:
- Create new
- Region: East US
- Notification type: Email/SMS/Push/Voice
- Add your email
5. Alert Details:
- Severity: Informational
- Name: Network-T1078-SSH-Successful-Login
- Description: Successful login :(

Create the rule.

## 6. Expose Honeypot Globally

NSG → Allow All inbound → VM.

Here is the clean, markdown-ready GitHub README section based on your content.

# Part 4 — Windows RDP Honeypot, Event Filtering, Parsing & Sentinel Integration

This section covers the deployment of a Windows-based RDP honeypot, configuration of Azure Data Collection (DCE/DCR), XPath filtering for Security Events 4624/4625, XML parsing using KQL, and integration with Microsoft Sentinel for detections and analytics.

## 1. Deploy the Windows Honeypot VM

1. Azure Portal → **Virtual Machines** → Create  
2. Resource Group: `project`  
3. VM Name: `WindowsHoneypot`  
4. Image: **Windows Server 2019**  
5. Size: `Standard_B2s`  
6. Create admin credentials  
7. Security Type: **Standard** (no Trusted Launch)  
8. Deploy and record Public IP  
9. Connect using RDP (`mstsc`)

## 2. Prepare Log Analytics for Event Ingestion

You will configure:

- **Data Collection Endpoint (DCE)**
- **Data Collection Rule (DCR)**
- Mapping to workspace: `projecthoneypot`

## 3. Create the Data Collection Endpoint (DCE)

1. Azure Portal → **Data Collection Endpoints** → Create  
2. Resource Group: `project`  
3. Name: `WindowsPC`  
4. Region: same as workspace  
5. Review + Create  

## 4. Create the Data Collection Rule (DCR)

1. Azure Portal → **Data Collection Rules** → Create  
2. Name: `RDPLogs`  
3. Resource Group: `project`  
4. Platform: **Windows**  
5. Select DCE: `WindowsPC`  
6. Add Resource → select `select the resource group you created`
7. Data Sources → Windows Event Logs → **Custom**  
8. Log name: `Security`  
9. Add XPath filters (below)  
10. Destination: **Azure Monitor Logs → projecthoneypot**  
11. Create  

## 5. XPath Filters (RDP Events Only)

**Successful RDP Logons — Event ID 4624 (LogonType 7 or 10)**

*[System[(EventID=4624)]] and *[EventData[Data[@Name=‘LogonType’]=‘10’ or Data[@Name=‘LogonType’]=‘7’]]

**Failed RDP Logons — Event ID 4625**

*[System[(EventID=4625)]]

> Some Azure interfaces may require prefixing with `Security!`

## 6. Validate XPath Locally (Optional)

```powershell
$xpath = '*[System[(EventID=4624)]] and *[EventData[Data[@Name="LogonType"]="10" or Data[@Name="LogonType"]="7"]]'
Get-WinEvent -LogName Security -FilterXPath $xpath | FL
```

## 7. Confirm Log Ingestion

Run in Log Analytics:

```KQL
Event
| where EventLog == "Security"
| take 20
```

## 8. Parse Windows Event XML with KQL

Example — 4624 Logon Parsing (indexes could change with dataset)

```KQL
Event 
| where EventID == 4624
| extend Event = parse_xml(EventData)
| extend src_ip = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(Event.DataItem)).EventData)).Data))[18].["#text"])
| extend username = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(Event.DataItem)).EventData)).Data))[5].["#text"])
| extend logontype = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(Event.DataItem)).EventData)).Data))[8].["#text"])
| project TimeGenerated,Computer,username,src_ip,logontype
```

## 9. Save Queries for Reuse

Suggested saved queries:
	•	Windows-Successful-Logons
	•	Windows-Failed-Logons

## 10. Enable Microsoft Sentinel
	1.	Azure Portal → Microsoft Sentinel
	2.	Select workspace: ProjectHoneypot
	3.	Click Add to enable
