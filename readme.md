#  Enterprise Cybersecurity & DevSecOps Environment Lab 🔐
## 📚 Content

- [🔐 Overview](#overview)
- [🏗️ Architecture](#architecture)
- [📅 Project Phases](#project-phases)
  - [Phase 1 – Core Network Infrastructure](phase1_infra/README.md)
  - [Phase 2 – Internal Web App + IAM](phase2_app_iam/README.md)
  - [Phase 3 – Monitoring & Visibility](phase3_monitoring/README.md)
  - [Phase 4 – GitLab & Secrets Management Setup](phase4_gitlab_vault/README.md)
  - [Phase 5 – Secure CI/CD Pipeline](phase5_secure_pipeline/README.md)
  - [Phase 6 – Secrets Management & Access Control](phase6_secrets_access/README.md)
  - [Phase 7 – Attack Simulation & Detection](phase7_attack_simulation/README.md)
- [⚙️ Lab Requirements](#lab-requirements)
- [🎯 Lab Goals](#lab-goals)
- [🚀 How to Use This Repository](#how-to-use-this-repository)
  - [Non-Technical Readers](#non-technical-readers)
  - [Technical Readers](#technical-readers)
- [📜 License](#license)

<a id="overview"></a>

## 📌 Overview

This repository documents a complete, multi-phase **Cybersecurity and DevSecOps lab** designed to simulate a realistic enterprise environment. The lab covers:

- Network segmentation
- Secure service deployment
- IAM (Identity and Access Management)
- Centralized monitoring
- Secure CI/CD
- Secrets management
- Attack simulation

---

**Primary purposes of this repository:**

- **Showcase, hone, and improve** my skills in **cybersecurity**, **software engineering**, and **DevSecOps**.
- Provide **non-technical viewers** with clear lab results and overall outcomes.
- Enable **technical audiences** to follow along step-by-step through the lab build process.
- Serve as an **aspiration and learning resource** for other aspiring cybersecurity professionals.
- Offer a **clear blueprint** for building a comprehensive, realistic, and security-focused lab environment.
- **Demonstrate the cybersecurity mindset** — for example, when deploying a firewall, consider:
  - What traffic should be allowed or denied
  - How rules affect internal vs. external access
  - How logging and alerting will be handled
  - How this control integrates with the overall security architecture
---

<a id="architecture"></a>

## 🏗️ Architecture

<p align="center">
  <img width=500 src="repo_resources/Network_Setup.png" alt="Project Logo" >
</p>

This architecture represents a balanced approach between simplicity and security, making it practical and effective for the scope of this project.

It uses three segmented networks — External, DMZ, and Internal — with a firewall VM at the center to control traffic flow. The design is straightforward enough to be easily managed, while still enforcing a layered security model:

- The External Network handles administrative access and potential simulated threats.
- The DMZ Network isolates public-facing services, reducing the risk of direct exposure to the internal systems.
- The Internal Network securely hosts core applications, IAM services, CI/CD pipelines, and monitoring tools, ensuring critical resources remain protected.

By separating functions and limiting cross-network communication through defined interfaces, this setup achieves the necessary security for testing and operations without overcomplicating deployment or management. It’s lean, functional, and purpose-built for this project’s goals.

---

<a id="project-phases"></a>

## 📅 Project Phases

| Phase | Title | Description |
|-------|-------|-------------|
| [**Phase 1**](phase1_infra/README.md) | Core Network Infrastructure | Set up 3 VMs: Firewall, DMZ, and Kali attacker. Configure SSH beacon and reverse proxy in DMZ. |
| [**Phase 2**](phase2_app_iam/README.md) | Internal Web App + IAM | Deploy internal Next.js app with database and Keycloak IAM server, accessible via DMZ reverse proxy. |
| [**Phase 3**](phase3_monitoring/README.md) | Monitoring & Visibility | Deploy Wazuh + ELK Stack for SIEM, with optional Prometheus/Grafana for metrics. Agents installed on all key VMs. |
| [**Phase 4**](phase4_gitlab_vault/README.md) | GitLab & Secrets Management Setup | Install and configure GitLab CE for source control and CI/CD. Optional: Deploy HashiCorp Vault for secure secret storage. |
| [**Phase 5**](phase5_secure_pipeline/README.md) | Secure CI/CD Pipeline | Build a GitLab CI/CD pipeline integrating SAST, DAST, dependency scanning, and secret scanning for the Next.js app. |
| [**Phase 6**](phase6_secrets_access/README.md) | Secrets Management & Access Control | Integrate Vault (or GitLab secrets) into CI/CD. Implement RBAC, audit logging, and secure deployment workflows. |
| [**Phase 7**](phase7_attack_simulation/README.md) | Attack Simulation & Detection | Use Kali to simulate real-world attacks and validate detection and alerting in Wazuh, Kibana, and Grafana dashboards. |

---

<a id="lab-requirements"></a>

## ⚙️ Lab Requirements

- Virtualization software: VirtualBox, VMware, or Proxmox
- Minimum hardware recommendation:
  - **CPU:** 8 cores
  - **RAM:** 16 GB (32 GB preferred for smoother multi-VM operation)
  - **Disk:** 200 GB free space
- Networking: Ability to configure host-only, NAT, and bridged adapters
- Internet access for package installations

---
<a id="lab-goals"></a>

## 🎯 Lab Goals

- Build a **realistic enterprise security architecture** in a controlled lab
- Implement **segmented networks** with DMZ and internal zones
- Deploy **IAM** for user authentication and authorization
- Implement **centralized logging and monitoring**
- Secure **software delivery pipelines** using DevSecOps practices
- Protect and manage **secrets** in CI/CD and infrastructure
- Simulate and detect **real-world cyberattacks**

---

<a id="how-to-use-this-repository"></a>

## 🚀 How to Use This Repository

<a id="non-technical-readers"></a>

### Non-Technical Readers
In each section of the lab, you will find a summary of **outcomes and results** that demonstrate the impact of the work done in that phase.   You don’t need to follow the technical steps — instead, focus on:
- The **before vs. after** state of the environment
- The **problems addressed** in each phase
- The **improvements in security posture**
- Any **visual results** such as dashboard screenshots, architecture diagrams, or attack/detection examples

This will give you a clear understanding of **why** each phase matters and how it contributes to building a secure, enterprise-like environment.


---
<a id="technical-readers"></a>

### Technical Readers
1. Start from **Phase 1** and follow the README in each phase folder.
2. Each phase README includes:
   - Overview and objectives
   - VM/service setup
   - Configuration details, such as:
        - Commands
        - Software installs
        - Code Files
   - Testing scenarios
3. Document your own changes, improvements, and findings.

---
<a id="license"></a>
## 📜 License

This project is for educational and research purposes. Use responsibly and do not deploy insecure configurations to production environments.

