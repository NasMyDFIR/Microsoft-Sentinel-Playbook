# Microsoft-Sentinel-Playbook

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

# Part 1 Complete

Cowrie honeypot fully operational and logging attacker activity.

---

# ⸻

# 🧩 Part 2 — Azure Log Analytics Configuration for Cowrie Logs

This section covers creating the custom log table and ingestion pipeline.

---

## 📘 1. Create Log Analytics Workspace

```
Name: project-honeypot
Group: project
```

---

## 📄 2. Create Custom Table for Cowrie

Upload `cowrie.json` → Create Custom Log.

```
Name: cowrie_json
Type: Custom Log (Classic)
```

Switch to manual schema management.

---

## 🌐 3. Create Data Collection Endpoint (DCE)

```
Name: linux-machine
```

---

## 🎯 4. Create Data Collection Rule (DCR)

```
Name: collect-cowrie  
Type: Linux  
DCE: linux-machine  
Resource: LinuxHoneypot VM  
Source: Custom JSON Logs  
Table: cowrie_json_CL  
```

---

## 🔍 6. Query the Logs

```
cowrie_json_CL
| take 50
```

---

# ⸻

# 🧩 Part 3 — KQL Queries, Functions & Alerts for Cowrie Honeypot

---

## 🔐 1. Generate New Events

Failed SSH & Successful SSH (root login).

---

## 📊 2. Basic Query

```
cowrie_json_CL | take 10
```

---

## 🛠️ 3. Add Columns with extend

```
| extend sourceIP = RawData.source_ip
| extend username = RawData.username
| extend eventID  = RawData.eventid
```

---

## 📁 4. Clean Dataset with project

```
| project TimeGenerated, username, sourceIP, eventID, message
```

Save as **cowrie-events**.

---

## 🚨 5. Alert Rule — Successful SSH Login

Filter for:

```
eventid == "cowrie.login.success"
```

Create alert with:

```
Name: Network-T1078-SSH-Successful-Login
Severity: Informational
```

---

## ⚙️ 6. Save Full KQL Parsing Function

```
cowrie
```

Saved as a Function in category "honeypot".

---

## 🌍 7. Expose Honeypot Globally

NSG → Allow All inbound → VM.

---

# ⸻

# 🪟 Part 4 — Windows RDP Honeypot + Event Filtering + Sentinel Integration

---

## 1. Deploy Windows Honeypot VM

```
Name: WindowsHoneypot
Image: Windows Server 2019
Size: B2s
Auth: Username + Password
```

---

## 2–4. DCE + DCR Setup

Create:

* **DCE: WindowsPC**
* **DCR: RDP-logs**
* Add **WindowsHoneypot**
* Configure Windows Event Logs with **XPath filters**

---

## 5. XPath Filtering

**Successful RDP (4624)**
**Failed RDP (4625)**
With LogonType `10` or `7`.

---

## 7. Validate Ingestion

```
Event
| where EventLog == "Security"
| take 20
```

---

## 8. Parse Windows Events with KQL

Example:

```
parse_xml(EventData)
```

Extract fields:

* sourceIP
* username
* logonType

---

## 10. Enable Sentinel

Attach to **project-honeypot** workspace.

---

# ⸻

# 📊 Part 5 — Microsoft Sentinel Workbook (External Authentication Activity)

Visualizations for:

* Linux SSH failed / success
* Windows RDP failed / success
* User/IP summaries
* Geo-location heatmaps

Includes queries for map views and tables.

---

# ⸻

# 🤖 Part 6 — Automation & Playbooks (AbuseIPDB IP Enrichment)

Automatically enrich IP addresses from Sentinel incidents.

---

## 🎯 Goal

A Logic App that:

* Extracts IP entities
* Calls AbuseIPDB API
* Parses results
* Posts enrichment back to incident comments

---

## 🔧 Requirements

* AbuseIPDB API Key
* Sentinel automation permissions

---

## 1. Create Automation Rule

Trigger → Incident creation → Run playbook.

---

## 2. Logic App — Extract IPs

Use:

```
Microsoft Sentinel → Get entities → Get IPs
```

---

## 3. HTTP Call to AbuseIPDB

Inside **For each** loop:

```
GET https://api.abuseipdb.com/api/v2/check?ipAddress=<IP>&maxAgeInDays=90&verbose=true
```

---

# ✅ Full Six-Part README Description Complete

If you'd like, I can also generate:

### ✅ A polished top-level root README.md

### ✅ Folder structure + navigation

### ✅ Architecture diagram (Mermaid or PNG)

### ✅ JSON for Sentinel Analytic Rules

### ✅ Terraform/Bicep for full environment deployment

Just tell me!
