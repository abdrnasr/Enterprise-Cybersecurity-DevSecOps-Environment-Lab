# 🔐 Enterprise Cybersecurity & DevSecOps Environment Project – Phase 4: Attack Simulation & Detection

## 🧩 Overview

In Phase 4, we move into **active attack simulation** to validate the resilience of our environment and the effectiveness of our monitoring stack.  We will launch **different types of attacks** from the Kali attacker VM against various components of the lab and evaluate:

- How well the environment reacts to each attack
- How quickly and easily the attacks can be detected
- Which security layers respond effectively, and which need improvement

This phase represents the **"red team vs. blue team"** part of the lab, testing the security controls we’ve built across earlier phases.

---

## 🧱 Virtual Machines Involved

| VM Name              | Role                        |
|----------------------|-----------------------------|
| **Kali Attacker**    | Launches simulated attacks  |
| **Firewall VM**      | Filters & routes   |
| **DMZ VM**           | SSH jump host & reverse proxy target |
| **Internal App VM**  | Next.js app + database      |
| **IAM VM**           | Keycloak authentication    |
| **Monitoring VM**    | Wazuh Manager, Indexer & Dashboard |

---

## 🎯 Phase Goals

By the end of this phase:
- We will have a **detection map** for common network, service, and application-level attacks
- We will know **which layers** in our architecture provide the fastest and clearest alerts
- We will have documented **improvement areas** for future security hardening

---

## 🛠️ Attack Scenarios

### 🔹 Network Layer
- **Port scanning** (e.g., `nmap`, `masscan`) against DMZ and internal assets
- **Firewall bypass attempts** — for example, after adding a new firewall rule, verify immediately that:
  - The intended traffic is blocked or allowed
  - Monitoring systems register the change

### 🔹 Service Layer
- **Launching a new unauthorized service** on DMZ or internal servers
  - Verify whether Wazuh detects the new process/service
  - Check if alerts are generated for unusual listening ports
- **Brute-force SSH attacks** using `hydra` or `medusa`
  - Measure how quickly Wazuh raises an alert

### 🔹 Web Application Layer
- **Vulnerability scanning** using `nikto`, `wpscan`, or `Arachni`
- **SQL Injection** attempts against the Next.js app API 
- **XSS (Cross-Site Scripting)** in form fields or query parameters
- **Auth bypass** attempts against Keycloak login

---

## 🔍 Detection & Response Goals

For each simulated attack, we will:
- **Verify detection** in the monitoring stack (Wazuh → ELK/Kibana, Prometheus/Grafana)
- Assess **alert clarity** — was the event easy to identify and interpret?
- Check **time-to-detection** — how long did it take for the alert to appear?
- Identify **blind spots** — events that were missed or unclear
- Document **log sources** and the rule IDs triggered

---

## 🧪 Example Evaluation Questions

- When a firewall rule is modified, does the monitoring system:
  - Log the change?
  - Alert the admin in real time?
- If a new unauthorized service is started, how is it detected?
- When a brute-force login occurs, is it caught early or only after multiple failed attempts?
- Are all attack attempts traceable to their source in the logs?

---


## ✅ Next Step

In **Phase 5**, we will start working with DevOps & DevSecOps portion of the lab.