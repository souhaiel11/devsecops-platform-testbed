# DevSecOps Platform Testbed

A deliberately controlled QA application for end-to-end validation of a DevSecOps orchestration platform.

**Important:** `main` is the control/baseline branch. Defects live on isolated `scenario/*` branches. Do not merge scenario branches together unless running the dedicated mixed scenario.

The external ground truth is intentionally not tracked in this repository. Keep the `ground-truth/` directory from the delivered package outside the Git repository used by the platform.

## Runtime
- Java 21
- Spring Boot 3.5.16
- HTTP port 8080
- Health endpoint: `/healthz`

## Scenario branches
See the external QA plan delivered with this repository.
