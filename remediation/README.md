# Automated Remediation

## Workflow

Security Hub Finding
→ EventBridge Rule
→ Lambda Remediator
→ AWS API Change
→ Control Re-check

## S3 Remediation

For an approved high-confidence S3 security finding, the remediation workflow can enable S3 Block Public Access controls.

## Safety

The remediation workflow should not blindly modify resources.

Protected resources and business-sensitive changes should be reviewed before automated remediation.
