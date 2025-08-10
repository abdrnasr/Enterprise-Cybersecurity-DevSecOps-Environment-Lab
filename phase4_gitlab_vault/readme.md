# 🔐 Enterprise Cybersecurity & DevSecOps Environment Lab – Phase 4: GitLab CI/CD & Secret Management

## 🧩 Overview

In Phase 4, we introduce the infrastructure required for implementing **DevSecOps workflows**, starting with the installation and configuration of **GitLab CE** for source control and CI/CD, and optionally **HashiCorp Vault** for secure secret storage.

This phase does not yet implement a CI/CD pipeline, but prepares the necessary tools and services to support secure software development and delivery in future phases.

---

## 🧱 Virtual Machines Used

| VM Name          | Role                   | Description                                                                  |
|------------------|------------------------|------------------------------------------------------------------------------|
| **GitLab VM**    | Code Hosting & CI/CD   | Hosts GitLab CE (Community Edition). Provides source control, CI/CD engine, runner management, and container registry. |
| **Vault VM (Optional)** | Secret Management        | Hosts HashiCorp Vault for centralized management of application secrets, tokens, and credentials. |

---

## 🛠️ Services Setup

### ✅ GitLab CE (Core)
- GitLab Community Edition installed and accessible internally (via reverse proxy)
- Hosted in the internal network, accessible via:
  - `https://gitlab.lab.local` or similar via DMZ NGINX reverse proxy
- Features to enable:
  - Projects and repositories
  - GitLab Runners (to be configured later)
  - Container registry (optional)
  - CI/CD templates and integrations

### 🌟 Optional: HashiCorp Vault
- Centralized secrets storage system
- Secures environment variables, SSH keys, API tokens, and credentials
- Access controlled via tokens, policies, and optional LDAP integration
- Can be integrated later with GitLab pipelines

---

## 🔒 Security Design

| Feature                         | Description                                                                 |
|----------------------------------|-----------------------------------------------------------------------------|
| Internal-only access             | GitLab and Vault are only accessible through the DMZ reverse proxy         |
| Admin access via SSH             | SSH into the GitLab/Vault VMs is only possible via the DMZ jump host       |
| HTTPS enabled (via NGINX)        | All GitLab and Vault endpoints served securely over HTTPS                  |
| Vault unsealed manually          | Vault initialized and unsealed by admin only, never exposed to public keys |

---

## 🎯 Phase Goals

By the end of this phase:

- **GitLab CE** is fully installed, configured, and reachable
- Reverse proxy routes `/gitlab` traffic to the GitLab VM
- Optional: **Vault** is installed and initialized
- All systems are ready to begin building secure CI/CD pipelines in the next phase
- Architecture now supports:
  - Secure source code management
  - Secrets lifecycle management
  - Separation of code, config, and credentials

---

## 🧪 Testing Scenarios

- Access GitLab from Kali or internal systems via: `https://dmz.lab.local/gitlab`
- Create test GitLab projects and repositories
- (Optional) Create and retrieve test secrets from Vault using `vault kv` commands
- Verify all services are reachable through the DMZ proxy and **not directly exposed**

---

## ✅ Next Step

In **Phase 5**, we will implement secure CI/CD pipelines using GitLab, integrating:
- SAST (Static Application Security Testing)
- DAST (Dynamic Application Security Testing)
- Secret injection (via GitLab or Vault)
- Deployment automation to internal app environments

