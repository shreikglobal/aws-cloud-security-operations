# AWS Cloud Security Operations Platform

## Overview

This project implements a mini Cloud Security Operations platform on AWS.

The solution continuously monitors the AWS environment for security threats and configuration issues, aggregates findings, supports threat hunting, prioritises risks, and provides automated remediation for high-confidence security issues.

## Objectives

- Continuous security monitoring
- Centralised security findings
- Threat hunting across security data
- Risk-based finding prioritisation
- Automated remediation for high-confidence issues
- Preventive controls against recurring misconfigurations
- Security posture measurement and reporting

## AWS Services Used

- Amazon GuardDuty
- AWS Security Hub
- AWS Config
- AWS CloudTrail
- Amazon VPC Flow Logs
- Amazon Security Lake
- Amazon Athena
- Amazon EventBridge
- AWS Lambda
- Amazon S3
- Amazon CloudWatch

## Architecture

AWS Security Sources
        |
        v
Security Hub / Security Lake
        |
        v
Athena Threat Hunting
        |
        v
Risk Prioritisation
        |
        v
EventBridge
        |
        v
Lambda Remediation
        |
        v
AWS Resource
        |
        v
Security Control Re-check

## Detection

The platform uses AWS security services to detect threats and configuration drift.

Security Hub provides the central security posture and finding view, while AWS Config continuously evaluates resource configuration.

## Threat Hunting

Amazon Security Lake collects security telemetry which is queried using Amazon Athena.

The hunting query library covers:

- Security findings
- VPC Flow Logs
- S3 data events
- Suspicious or unusual activity
- Cross-source investigation

## Risk Prioritisation

Findings are prioritised using:

Risk Score = Severity × Exposure × Resource Sensitivity

This provides additional context beyond the raw finding severity.

## Automated Remediation

High-confidence S3 security findings are handled through:

Security Hub
    ↓
EventBridge
    ↓
Lambda
    ↓
S3 security control
    ↓
Verification

The remediation workflow includes safety checks before making changes.

## Preventive Controls

Amazon S3 Block Public Access is used as a preventive control to reduce the possibility of public S3 exposure being introduced.

AWS Config and Security Hub provide detective controls.

EventBridge and Lambda provide the corrective remediation path.

## Posture Assessment

The initial CSPM posture score recorded during the exercise was:

42%

A later posture assessment recorded:

75%

The posture score is used as a measurable indicator of security posture improvement.

## Evidence

Screenshots and supporting evidence are available under:

/screenshots/aws-evidence/

## Runbook

The incident response and remediation procedure is available under:

/runbooks/

## Project Structure

- detection/ - detection configuration
- threat-hunting/ - Athena hunting queries
- remediation/ - Lambda and EventBridge remediation
- infrastructure/ - infrastructure-as-code
- architecture/ - architecture diagram
- runbooks/ - incident response procedures
- docs/ - project documentation and report
- screenshots/ - AWS evidence

## Safety

This project uses test resources and controlled security scenarios.

Secrets, credentials and sensitive information should not be committed to the repository.

## Project Status

Detection: Completed
Threat Hunting: Completed
Risk Prioritisation: Completed
Automated Remediation: Completed
Preventive Controls: Completed
Posture Reporting: Completed
Documentation: Completed
