import boto3

s3 = boto3.client("s3")


def lambda_handler(event, context):

    print("Received Security Hub event:")
    print(event)

    # ---------------------------------------------------------
    # 1. Read Security Hub finding
    # ---------------------------------------------------------
    finding = event.get("detail", {}).get("findings", [{}])[0]

    severity = finding.get("Severity", {}).get("Label", "")
    status = finding.get("Workflow", {}).get("Status", "")

    # ---------------------------------------------------------
    # 2. Safety guard - only act on NEW critical findings
    # ---------------------------------------------------------
    if severity != "CRITICAL":
        print("Finding is not Critical. No remediation performed.")
        return {
            "statusCode": 200,
            "message": "Skipped - finding is not Critical"
        }

    if status not in ["NEW", "NOTIFIED"]:
        print("Finding is not in an actionable state.")
        return {
            "statusCode": 200,
            "message": "Skipped - finding status is not actionable"
        }

    # ---------------------------------------------------------
    # 3. Find S3 bucket resource
    # ---------------------------------------------------------
    resources = finding.get("Resources", [])

    bucket_name = None

    for resource in resources:

        resource_type = resource.get("Type", "")
        resource_id = resource.get("Id", "")

        if resource_type == "AwsS3Bucket":

            # Security Hub normally provides:
            # arn:aws:s3:::bucket-name
            bucket_name = resource_id.split(":::")[-1]

            break

    if not bucket_name:
        print("No S3 bucket resource found.")
        return {
            "statusCode": 200,
            "message": "Skipped - no S3 bucket found"
        }

    print(f"S3 bucket identified: {bucket_name}")

    # ---------------------------------------------------------
    # 4. Safety guard - protected resource tag
    # ---------------------------------------------------------
    try:

        tagging = s3.get_bucket_tagging(
            Bucket=bucket_name
        )

        tags = {
            tag["Key"]: tag["Value"]
            for tag in tagging.get("TagSet", [])
        }

        if tags.get("CSPM-Remediation") == "false":
            print(
                f"Bucket {bucket_name} is protected "
                "by CSPM-Remediation=false"
            )

            return {
                "statusCode": 200,
                "message": "Skipped - protected resource"
            }

    except s3.exceptions.NoSuchTagSet:

        print("No bucket tags found. Continuing.")

    except Exception as e:

        print(f"Unable to read bucket tags: {str(e)}")

        return {
            "statusCode": 500,
            "message": "Unable to verify protection tag"
        }

    # ---------------------------------------------------------
    # 5. Enable all four S3 Block Public Access settings
    # ---------------------------------------------------------
    try:

        response = s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        )

        print(
            f"Block Public Access enabled for {bucket_name}"
        )

        # -----------------------------------------------------
        # 6. Verify the configuration
        # -----------------------------------------------------
        verification = s3.get_public_access_block(
            Bucket=bucket_name
        )

        print("Verification result:")
        print(verification)

        return {
            "statusCode": 200,
            "bucket": bucket_name,
            "remediation": "completed",
            "public_access_block": verification[
                "PublicAccessBlockConfiguration"
            ]
        }

    except Exception as e:

        print(
            f"Remediation failed for {bucket_name}: {str(e)}"
        )

        return {
            "statusCode": 500,
            "bucket": bucket_name,
            "remediation": "failed",
            "error": str(e)
        }
