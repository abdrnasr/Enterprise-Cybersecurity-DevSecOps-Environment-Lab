# 🔐 Enterprise Cybersecurity & DevSecOps Environment Project – Phase 7: Operational Observability (ELK Actualization)

## 🧩 Overview

In Phase 7, we **activate** the `ELK stack` (set up in Phase 3) as the **observability backbone** of the environment. The focus is on **operational monitoring**, not security (that’s Wazuh’s job). Logs, metrics, and traces from the `Next.js` app, **CI/CD pipelines**, `GitLab`, `Nginx` DMZ, and hosts are ingested into `Elasticsearch`, visualized in `Kibana`, and used to define Service Level Objectives (SLOs) and alerts.

---

## 🛠️ Services Involved

- **Next.js App**: Structured logs (Pino) + Elastic APM (traces, errors, latency)
- **GitLab & Runners**: Pipeline logs, job duration, failure rates, runner queue metrics
- **Nginx Reverse Proxy**: JSON access/error logs for traffic, upstream latency, error rates
- **Hosts & Services**: Metricbeat for CPU/mem/disk/net + Heartbeat for uptime checks
- **Dashboards & Alerts**: Kibana visualizations for App, Pipeline, DMZ, Infra health
---


## 🎯 Phase Goals

By the end of this phase:
- Move ELK from “dummy server” to live observability platform.
- Central dashboards for:
    - App health (latency, error rates, top failing routes)
    - Pipeline health (success/failure trends, build duration, runner load)
    - Reverse proxy (traffic by host, 4xx/5xx spikes, latency heatmap)
    - Infrastructure (CPU, disk, uptime checks)
- Define and enforce SLIs/SLOs (availability, latency, error budgets).
- Alerts for pipeline failures, latency violations, disk exhaustion, service downtime.

---
