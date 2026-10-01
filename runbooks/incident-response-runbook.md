# Incident Response Runbook

## 1. Detect

Review the Security Hub finding and identify:

- Finding severity
- Affected resource
- Finding type
- AWS account
- AWS region
- Detection source

## 2. Validate

Confirm that the finding represents an actual security issue and is not an approved exception.

## 3. Contain

Apply the appropriate containment action.

For an S3 public-access issue, verify and enable Block Public Access.

## 4. Capture Evidence

Record:

- Finding details
- Resource details
- Detection timestamp
- Relevant security logs
- Configuration state before remediation

## 5. Remediate

Apply the approved corrective action.

## 6. Verify

Re-check the affected AWS resource and Security Hub finding.

## 7. Close

Record the remediation completion time and update the security posture report.

## Escalation

IAM, encryption, logging and application-sensitive changes should be reviewed before automated modification.
