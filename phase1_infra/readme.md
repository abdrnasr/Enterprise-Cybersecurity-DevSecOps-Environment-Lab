# 🔐 Enterprise Cybersecurity & DevSecOps Environment Lab – Phase 1: Core Network Infrastructure

## 🧩 Overview

In Phase 1, we build the foundational infrastructure of our cybersecurity lab using **3 virtual machines**. This setup mimics a basic segmented enterprise environment with a firewall, DMZ, and an external attacker.

---

## 🧱 Virtual Machines Used

| VM Name       | Role                | Description                                                                 |
|---------------|---------------------|-----------------------------------------------------------------------------|
| **Kali Attacker** | External Attacker   | A standard Kali Linux VM used to simulate real-world attacks from the internet. |
| **Firewall VM**   | Network Gateway     | A basic Linux VM with IP forwarding and routing enabled. It segments the external network from the DMZ and internal networks. |
| **DMZ VM**        | Public-facing Server| Hosts two core services: an **SSH beacon** for admin access and a **reverse proxy (NGINX)** to expose internal websites externally. |

---

## 🛠️ Services Setup

- **Firewall VM**
  - IP forwarding enabled
  - Routes traffic between the external attacker and DMZ
  - No additional services hosted (firewall only)

- **DMZ VM**
  - **SSH Server**: Allows external admins to securely connect and manage internal systems (jump host model)
  - **NGINX Reverse Proxy**: Forwards HTTP/S requests to future internal web applications

- **Kali Attacker VM**
  - Used to simulate real-world external attacks, e.g., SSH brute-force, port scanning, etc.

---

## 🎯 Phase Goals

By the end of this phase, we will have:

- All 3 VMs up and running with network connectivity established.
- Proper routing and segmentation configured using the firewall VM.
- A working reverse proxy and SSH beacon exposed to the attacker VM.
- A demonstration of current **infrastructure vulnerabilities** due to **lack of monitoring**, including:
  - No visibility into SSH brute-force attacks
  - No detection or alerting capabilities
  - No centralized logging or SIEM

---

## ⚠️ Known Limitations (to be addressed in future phases)

- No monitoring/logging (Wazuh/ELK will be introduced in Phase 2)
- SSH login attempts and web access are **not** logged or analyzed
- Attack simulation will show how intrusions go undetected

---

## ✅ Next Step

In **Phase 2**, we will introduce a **monitoring VM** running **Wazuh + ELK Stack** to provide detection and visibility into the attacks simulated from the Kali machine.

