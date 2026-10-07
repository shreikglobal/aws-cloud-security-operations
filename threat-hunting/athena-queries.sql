-- ============================================================
-- CSPM Threat Hunting Query Library
-- Region: ap-south-1
-- ============================================================


-- HUNT 1: Rare / Unusual API Calls
-- Identifies API actions performed very rarely.

SELECT
    record.eventName,
    record.eventSource,
    COUNT(*) AS event_count
FROM cloudtrail_management_raw
CROSS JOIN UNNEST(Records) AS t(record)
WHERE record.userIdentity.arn NOT LIKE '%AWSServiceRole%'
GROUP BY
    record.eventName,
    record.eventSource
HAVING COUNT(*) <= 2
ORDER BY event_count ASC, record.eventName
LIMIT 20;


-- HUNT 2: Console Login IP Analysis
-- Identifies source IPs used for AWS Console logins.

SELECT
    record.sourceIPAddress,
    COUNT(*) AS login_count,
    MIN(record.eventTime) AS first_seen,
    MAX(record.eventTime) AS last_seen
FROM cloudtrail_management_raw
CROSS JOIN UNNEST(Records) AS t(record)
WHERE record.eventName = 'ConsoleLogin'
GROUP BY record.sourceIPAddress
ORDER BY first_seen DESC;


-- HUNT 3: AccessDenied Spikes
-- Identifies principals generating repeated AccessDenied events.

SELECT
    record.userIdentity.arn AS user_arn,
    COUNT(*) AS denied_count
FROM cloudtrail_management_raw
CROSS JOIN UNNEST(Records) AS t(record)
WHERE record.errorCode = 'AccessDenied'
GROUP BY record.userIdentity.arn
ORDER BY denied_count DESC
LIMIT 20;


-- HUNT 4: Root Account Usage
-- Detects API activity performed by the AWS root account.

SELECT
    record.eventTime,
    record.eventName,
    record.eventSource,
    record.sourceIPAddress,
    record.awsRegion
FROM cloudtrail_management_raw
CROSS JOIN UNNEST(Records) AS t(record)
WHERE record.userIdentity.arn = 'arn:aws:iam::547641909662:root'
ORDER BY record.eventTime DESC
LIMIT 50;


-- HUNT 5: IAM Access Key Creation
-- Detects newly created IAM access keys.

SELECT
    record.eventTime,
    record.userIdentity.arn AS user_arn,
    record.sourceIPAddress,
    record.eventName,
    record.eventSource
FROM cloudtrail_management_raw
CROSS JOIN UNNEST(Records) AS t(record)
WHERE record.eventName = 'CreateAccessKey'
ORDER BY record.eventTime DESC
LIMIT 50;


-- HUNT 6: Cross-Source CloudTrail + VPC Flow Correlation
-- Correlates CloudTrail activity with VPC network traffic
-- using source IP and a 30-minute time window.

SELECT
    c.event_time,
    c.event_name,
    c.event_source,
    c.user_arn,
    c.source_ip,
    v.time_dt AS flow_time,
    v.src_endpoint.ip AS flow_src_ip,
    v.dst_endpoint.ip AS flow_dst_ip,
    v.dst_endpoint.port AS dst_port,
    v.action,
    v.disposition
FROM (
    SELECT
        from_iso8601_timestamp(record.eventTime) AS event_time,
        record.eventName AS event_name,
        record.eventSource AS event_source,
        record.sourceIPAddress AS source_ip,
        record.userIdentity.arn AS user_arn
    FROM cloudtrail_management_raw
    CROSS JOIN UNNEST(Records) AS t(record)
    WHERE record.userIdentity.arn NOT LIKE '%AWSServiceRole%'
) c
JOIN amazon_security_lake_table_ap_south_1_vpc_flow_2_0 v
    ON v.src_endpoint.ip = c.source_ip
   AND v.time_dt BETWEEN c.event_time - INTERVAL '30' MINUTE
                      AND c.event_time + INTERVAL '30' MINUTE
ORDER BY c.event_time DESC
LIMIT 50;
