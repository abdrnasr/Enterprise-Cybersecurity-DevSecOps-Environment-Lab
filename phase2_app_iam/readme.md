# 🔐 Enterprise Cybersecurity & DevSecOps Environment Lab – Phase 2: Internal Web App + IAM Integration

## 🧩 Overview

In Phase 2, we expand the lab environment by introducing two new **internal virtual machines**. These VMs represent realistic internal services commonly found in enterprise infrastructures:

- A **web application** (Next.js) with a backend database
- An **Identity and Access Management (IAM)** server (Keycloak)

This setup gives our infrastructure something real to protect and monitor in the future phases. It also lays the groundwork for exploring secure authentication, authorization, and access control.

---

## 🧱 Virtual Machines Used

| VM Name             | Role                        | Description                                                                 |
|---------------------|-----------------------------|-----------------------------------------------------------------------------|
| **Internal App VM** | Web App + Database          | Hosts a **Next.js** application and a **PostgreSQL** database to simulate a modern full-stack app. |
| **IAM Server VM**   | Identity Management         | Hosts **Keycloak**, an enterprise-grade open-source IAM system. Provides authentication, role-based access, and token issuance. |

> These two VMs reside in the **internal network**, behind the firewall and DMZ, and are **not directly accessible** from the internet.

---

## 🛠️ Services Setup

- **Internal App VM**
  - **Next.js** frontend served via Node.js
  - **PostgreSQL** database for storing application data
  - Will be accessed externally via the **NGINX reverse proxy** in the DMZ
  - Will integrate authentication via Keycloak (OAuth2 / OpenID Connect)

- **IAM Server VM**
  - **Keycloak** installed to manage:
    - User accounts
    - Login flows
    - Role-based access control
    - Token issuance and validation
  - Will also be routed externally via the reverse proxy

- **DMZ Reverse Proxy (from Phase 1)**
  - Forwards:
    - `/app` → Internal App VM
    - `/auth` → IAM Server VM (Keycloak)

---

## 🔒 Security Design

- Internal services are **never directly exposed** to the public internet.
- External access is restricted to:
  - **HTTP/HTTPS** forwarded by NGINX (DMZ)
  - **SSH** via the DMZ jump host (admin use only)
- Future monitoring (Phase 3) will detect:
  - Unauthorized login attempts
  - Web vulnerability scans
  - Brute-force and abnormal access patterns

---

## 🎯 Phase Goals

By the end of this phase, we will have:

- A deployed **Next.js app** that simulates user interactions
- A working **PostgreSQL** database for storing app data
- An installed and configured **Keycloak** IAM server
- Functional **SSO login integration** between the app and Keycloak
- Reverse proxy routing properly configured via NGINX in the DMZ
- Clear separation of duties between app, auth, and data layers

---

## 🧪 Testing Scenarios

- Simulate user login and token issuance via Keycloak
- Access protected app routes using OAuth2 tokens
- Attempt unauthorized access or failed login to prepare for monitoring
- Test reverse proxy routing from the Kali VM:
  - `http://dmz.lab.local/app`
  - `http://dmz.lab.local/auth`

---

## ✅ Next Step

In **Phase 3**, we will deploy a centralized **Monitoring VM** running **Wazuh + ELK Stack**, which will:
- Monitor all agent-connected VMs (app, IAM, etc.)
- Detect brute-force SSH attacks, suspicious HTTP requests, and file tampering
- Visualize logs and alerts using Kibana dashboards

