# Enterprise Cybersecurity & DevSecOps Environment Project – Phase 7: Operational Observability (ELK Actualization)

## Overview

In Phase 7, we focus on **observability**, proving that each new release of the internal app works correctly after deployment. The goal is to make sure every update runs smoothly, without hidden performance issues.

Using the ELK stack, we monitor the web application's response time and error rate for each version right after it goes live. This helps detect problems early and take quick action if something goes wrong.

---

## Phase Goals

By the end of this phase:
- Confirm each new release is healthy by watching key performance indicators.
- Automatically collect logs from the app and CI pipeline into ELK.
- Display real-time data in a simple dashboard showing version, latency, and error trends.
- Set up two alerts: one for slow response time and one for sudden error increases.
- Keep a short rollback/hotfix guide for quick action.
- Ensure visibility into each deploy within 30–60 minutes.

## Testing Scenarios

- Deploy a normal (healthy) release and verify it appears in the dashboard with stable latency and no alerts.
- Deploy a faulty version that intentionally increases latency or causes errors to confirm alerts trigger correctly.
- Use the rollback procedure to switch back to the previous stable version and confirm metrics return to normal.

## Demo & Results – Non-Technical Overview 

Complete Later.

---

## **For Technical Readers:**  
See **[Lab Steps – Phase 7](lab-steps-phase-7.md)** for detailed VM setup, network configuration, and service installation instructions.

---

## Next Steps

Now that the full pipeline is operational, this marks a significant milestone in building a **complete enterprise-grade cybersecurity** and **DevSecOps environment**. You have successfully moved from foundational network architecture to automated, secure software delivery, integrating security, observability, and resilience into every layer.

At this stage, you should have gained a practical understanding of how real-world organizations integrate security engineering into their development and deployment workflows. You have seen how individual components, from IAM and monitoring to CI/CD and attack simulation, cooperate to form a cohesive, secure system.

While this project now stands as a fully functional ecosystem, there are several meaningful ways to extend and refine it:
- **Enhance automation**: Introduce Infrastructure-as-Code (IaC) using tools like `Terraform` or `Ansible` to provision and manage the environment more efficiently.
- **Advance observability**: Expand the `ELK` integration with real-time tracing and synthetic monitoring to capture user experience metrics.
- **Extend CI/CD security**: Add container image scanning (e.g., `Trivy`) and policy enforcement using Open Policy Agent (OPA) or `GitLab's Compliance Framework`.
- **Integrate cloud services**: Migrate parts of the setup to a public cloud (`AWS`, `Azure`, or `GCP`) to simulate hybrid architectures and cloud-native security controls.
- **Automate response**: Connect `Wazuh` alerts with remediation scripts or ticketing tools to demonstrate a closed-loop detection-and-response workflow.
- **Document and share**: Transform this repository into a portfolio or internal training resource. Adding summaries, diagrams, and walkthrough videos can help others learn from your work.

Completing this journey means you have built, secured, and operated a miniature version of a real enterprise infrastructure. Whether you continue expanding this lab or adapt its principles in professional settings, you now possess a solid foundation in designing, defending, and delivering modern secure systems.