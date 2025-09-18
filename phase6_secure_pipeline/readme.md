# 🔐 Enterprise Cybersecurity & DevSecOps Environment Project – Phase 6: Secure CI/CD Pipeline

## 🧩 Overview

In Phase 6, we implement a **secure Continuous Integration / Continuous Deployment (CI/CD) pipeline** using **GitLab CI**, focused on integrating **security testing and analysis** into the software development lifecycle (SDLC). This phase leverages the GitLab instance deployed in Phase 5 and targets the **Next.js app** hosted internally. This phase also introduces **basic secrets handling** via `GitLab` CI/CD variables to keep sensitive values (DB passwords, API keys, tokens) out of code.

---

## 🛠️ Services Involved

| Component         | Role                                | Tools Used                          |
|------------------|--------------------------------------|-------------------------------------|
| **GitLab CI/CD** | Automates build, test, and deploy    | GitLab Runners, `.gitlab-ci.yml`    |
| **SAST Tools**   | Static code analysis                 | **SonarQube**, **ESLint**, **Bandit** (optional) |
| **Dependency Scanning** | Check vulnerabilities in packages | **npm audit**, **Trivy**, **Snyk CLI**           |
| **DAST Tools**   | External scanning of live app        | **OWASP ZAP CLI**, **Nikto**        |
| **Secrets Scanning** | Detect leaked secrets in code     | **Gitleaks**, **truffleHog**        |
| **Deployment**   | Push to internal app server          | SCP or SSH to App VM                |

---

## 🔐 CI/CD Pipeline Stages

| Stage         | Description                                              | Tools                     |
|---------------|----------------------------------------------------------|---------------------------|
| `build`       | Install dependencies, build the Next.js app              | `npm ci`, `npm run build` |
| `sast`        | Analyze source code for vulnerabilities                  | `SonarQube`, `ESLint`     |
| `depscan`     | Check for vulnerable packages/dependencies               | `npm audit`, `Trivy`, `Snyk` |
| `secretscan`  | Detect secrets accidentally committed to the codebase    | `Gitleaks`, `truffleHog`  |
| `dast`        | Run external scans on deployed app endpoints             | `OWASP ZAP CLI`, `Nikto`  |
| `deploy`      | Push to internal app server over SSH                     | `scp`, `rsync`, `ssh`     |

---

## 🎯 Phase Goals

By the end of this phase:

- Every Git push triggers a **secure CI/CD pipeline**
- Static code issues are detected and flagged automatically
- Third-party dependency vulnerabilities are identified
- Secrets leakage is prevented before deployment
- The app is deployed to the internal server **only when clean**
- This setup emulates enterprise-grade DevSecOps practices

---

## 🔒 Security Design

| Security Layer         | Description                                          |
|------------------------|------------------------------------------------------|
| Secrets injection      | Uses GitLab CI/CD variables or Vault (Phase 6)       |
| Isolated runners       | Ensures CI jobs are sandboxed                        |
| Approved dependencies  | Requires clean audit reports to proceed to deploy    |
| Deployment over SSH    | Ensures secure transport into internal network       |

---

## 🧪 Testing Scenarios

- Push a clean commit → expect full pipeline success and deployment
- Introduce a secret (e.g., AWS key) → blocked by `gitleaks`
- Add a vulnerable dependency → flagged by `npm audit` or `Trivy`
- Simulate brute-force or scan → detected in DAST stage

---

## ✅ Next Step

In **Phase 7**, we will enhance security by:
- Configuring access policies for environment-specific secrets
- Logging, alerting, and reporting from CI/CD security scans

