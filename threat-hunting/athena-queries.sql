-- Security Hub Findings
SELECT *
FROM amazon_security_lake_table_ap_south_1_sh_findings_2_0
LIMIT 10;


-- VPC Flow Logs
SELECT *
FROM amazon_security_lake_table_ap_south_1_vpc_flow_2_0
LIMIT 10;


-- S3 Data Events
SELECT
    time_dt,
    operation,
    name,
    ip
FROM amazon_security_lake_table_ap_south_1_s3_data_2_0
WHERE operation = 'PutObject'
ORDER BY time_dt DESC
LIMIT 10;
