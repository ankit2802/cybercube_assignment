from datetime import datetime, timedelta
import requests
import json
import pandas as pd
from sqlalchemy import create_engine, types
import mysql.connector


# Define the API endpoints
nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
history_api_url_template = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0/?changeStartDate={}&changeEndDate={}"

# Define the date range
end_date = datetime(2024, 5, 1)
start_date = datetime(2024, 1, 1)
max_days = 120

# Initialize lists to store all vulnerabilities and CVE history changes
all_vulnerabilities = []
all_cve_changes = []

# Function to make API calls for a given date range for NVD data
def fetch_vulnerabilities(start_date, end_date):
    start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    end_date_str = end_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    params = {
        "resultsPerPage": 2000,
        "startIndex": 0,
        "pubStartDate": start_date_str,
        "pubEndDate": end_date_str,
        "lastModStartDate": start_date_str,
        "lastModEndDate": end_date_str
    }

    while True:
        response = requests.get(nvd_api_url, params=params)

        if response.status_code == 200:
            try:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                print(f"Fetched {len(vulnerabilities)} vulnerabilities from {start_date_str} to {end_date_str}")

                if not vulnerabilities:
                    break

                all_vulnerabilities.extend(vulnerabilities)
                params['startIndex'] += params['resultsPerPage']

            except json.JSONDecodeError as e:
                print("Failed to parse JSON response:", e)
                break
        else:
            print(f"Failed to retrieve data: {response.status_code}")
            print("Response content:", response.content)
            break

# Function to fetch CVE changes
def fetch_cve_changes(start_date, end_date):
    start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    end_date_str = end_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    url = history_api_url_template.format(start_date_str.replace("+", "%2B"), end_date_str.replace("+", "%2B"))

    params = {
        "resultsPerPage": 5000,
        "startIndex": 0
    }

    while True:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            try:
                data = response.json()
                cve_changes = data.get('cveChanges', [])
                print(f"Fetched {len(cve_changes)} CVE changes from {start_date_str} to {end_date_str}.")

                if not cve_changes:
                    break

                all_cve_changes.extend(cve_changes)
                params['startIndex'] += params['resultsPerPage']

            except json.JSONDecodeError as e:
                print("Failed to parse JSON response:", e)
                break
        else:
            print(f"Failed to retrieve data: {response.status_code}")
            print("Response content:", response.content)
            break

# Loop through the date range in chunks of 120 days for NVD data
current_start_date = start_date
while current_start_date < end_date:
    current_end_date = min(current_start_date + timedelta(days=max_days - 1), end_date)
    fetch_vulnerabilities(current_start_date, current_end_date)
    fetch_cve_changes(current_start_date, current_end_date)
    current_start_date = current_end_date + timedelta(days=1)

# Function to extract relevant details from the NVD vulnerabilities JSON response
def extract_vulnerability_data(vulnerabilities):
    extracted_data = []

    for vulnerability in vulnerabilities:
        cve = vulnerability.get('cve', {})
        cve_id = cve.get('id', '')
        source_identifier = cve.get('sourceIdentifier', '')
        published = cve.get('published', '')
        last_modified = cve.get('lastModified', '')
        vuln_status = cve.get('vulnStatus', '')

        descriptions = cve.get('descriptions', [])
        description_en = next((desc['value'] for desc in descriptions if desc['lang'] == 'en'), None)

        cvss_data = cve.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('cvssData', {})
        base_score = cvss_data.get('baseScore', '')
        access_vector = cvss_data.get('accessVector', '')
        confidentiality_impact = cvss_data.get('confidentialityImpact', '')
        integrity_impact = cvss_data.get('integrityImpact', '')
        availability_impact = cvss_data.get('availabilityImpact', '')

        base_severity = cve.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('baseSeverity', '')
        exploitability_score = cve.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('exploitabilityScore', '')
        impact_score = cve.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('impactScore', '')

        weaknesses = cve.get('weaknesses', [])
        weakness_description = next((desc['value'] for w in weaknesses for desc in w.get('description', []) if desc['lang'] == 'en'), None)

        configurations = cve.get('configurations', [])
        configuration_criteria = [c['criteria'] for config in configurations for node in config.get('nodes', []) for c in node.get('cpeMatch', [])]

        references = cve.get('references', [])
        reference_urls = [ref['url'] for ref in references]

        config_criteria_str = json.dumps(configuration_criteria)
        ref_urls_str = json.dumps(reference_urls)
        if len(config_criteria_str) > 4000:
            config_criteria_str = config_criteria_str[:3999] + '…'
        if len(ref_urls_str) > 4000:
            ref_urls_str = ref_urls_str[:3999] + '…'

        extracted_data.append({
            'CVE_ID': cve_id,
            'SOURCE_IDENTIFIER': source_identifier,
            'PUBLISHED_DATE': published,
            'LAST_MODIFIED_DATE': last_modified,
            'VULNERABILITY_STATUS': vuln_status,
            'DESCRIPTION_EN': description_en,
            'CVSS_BASE_SCORE': base_score,
            'ACCESS_VECTOR': access_vector,
            'CONFIDENTIALITY_IMPACT': confidentiality_impact,
            'INTEGRITY_IMPACT': integrity_impact,
            'AVAILABILITY_IMPACT': availability_impact,
            'BASE_SEVERITY': base_severity,
            'EXPLOITABILITY_SCORE': exploitability_score,
            'IMPACT_SCORE': impact_score,
            'WEAKNESS_DESCRIPTION': weakness_description,
            'CONFIGURATION_CRITERIA': config_criteria_str,
            'REFERENCE_URLS': ref_urls_str,
            'RECORD_ADDED_DATE': datetime.now().date()  # Add current date
        })

    return extracted_data

# Function to extract relevant details from the CVE changes JSON response
def extract_cve_change_data(cve_changes):
    extracted_data = []

    for change_entry in cve_changes:
        change = change_entry.get('change', {})
        cve_id = change.get('cveId', '')
        event_name = change.get('eventName', '')
        cve_change_id = change.get('cveChangeId', '')
        source_identifier = change.get('sourceIdentifier', '')
        created = change.get('created', '')

        extracted_data.append({
            'CVE_ID': cve_id,
            'EVENT_NAME': event_name,
            'CVE_CHANGE_ID': cve_change_id,
            'SOURCE_IDENTIFIER': source_identifier,
            'CREATED_DATE': created,
            'RECORD_ADDED_DATE': datetime.now().date()  # Add current date
        })

    return extracted_data

# Call the function to extract data
vulnerability_data = extract_vulnerability_data(all_vulnerabilities)
cve_change_data = extract_cve_change_data(all_cve_changes)

# Specify column names for DataFrames
vulnerability_columns = [
    'CVE_ID', 'SOURCE_IDENTIFIER', 'PUBLISHED_DATE', 'LAST_MODIFIED_DATE', 'VULNERABILITY_STATUS',
    'DESCRIPTION_EN', 'CVSS_BASE_SCORE', 'ACCESS_VECTOR', 'CONFIDENTIALITY_IMPACT', 'INTEGRITY_IMPACT',
    'AVAILABILITY_IMPACT', 'BASE_SEVERITY', 'EXPLOITABILITY_SCORE', 'IMPACT_SCORE', 'WEAKNESS_DESCRIPTION',
    'CONFIGURATION_CRITERIA', 'REFERENCE_URLS', 'RECORD_ADDED_DATE'
]

cve_change_columns = [
    'CVE_ID', 'EVENT_NAME', 'CVE_CHANGE_ID', 'SOURCE_IDENTIFIER', 'CREATED_DATE', 'RECORD_ADDED_DATE'
]

# Convert extracted data to DataFrames
df_vulnerabilities = pd.DataFrame(vulnerability_data)
df_cve_changes = pd.DataFrame(cve_change_data)

# Replace empty strings with None in the specified columns
for col in ['CVSS_BASE_SCORE', 'EXPLOITABILITY_SCORE', 'IMPACT_SCORE']:
    df_vulnerabilities[col] = df_vulnerabilities[col].replace('', None)

# Define the connection parameters
user = 'root'
password = 'admin'
host = 'localhost'
database_name = 'cybercube'
table_name_vulnerabilities = 'dwextract.vulnerabilities'
table_name_cve_changes = 'dwextract.cve_changes'

# Establish MySQL connection
conn = mysql.connector.connect(
    host=host,
    user=user,
    password=password,
    database=database_name
)
cur = conn.cursor()

# Create the dwtransform schema and tables if they don't exist
cur.execute("CREATE SCHEMA IF NOT EXISTS dwextract")
cur.execute("USE dwextract")

# Create table script for vulnerabilities
create_table_vulnerabilities = f"""
CREATE TABLE IF NOT EXISTS {table_name_vulnerabilities} (
    CVE_ID NVARCHAR(255),
    SOURCE_IDENTIFIER NVARCHAR(255),
    PUBLISHED_DATE DATETIME,
    LAST_MODIFIED_DATE DATETIME,
    VULNERABILITY_STATUS NVARCHAR(255),
    DESCRIPTION_EN TEXT,
    CVSS_BASE_SCORE DECIMAL(4, 2),
    ACCESS_VECTOR NVARCHAR(255),
    CONFIDENTIALITY_IMPACT NVARCHAR(255),
    INTEGRITY_IMPACT NVARCHAR(255),
    AVAILABILITY_IMPACT NVARCHAR(255),
    BASE_SEVERITY NVARCHAR(255),
    EXPLOITABILITY_SCORE DECIMAL(4, 2),
    IMPACT_SCORE DECIMAL(4, 2),
    WEAKNESS_DESCRIPTION NVARCHAR(2000),
    CONFIGURATION_CRITERIA TEXT,
    REFERENCE_URLS TEXT,
    RECORD_ADDED_DATE DATE
)
"""
cur.execute(create_table_vulnerabilities)
cur.execute("truncate table dwextract.vulnerabilities")
# Create table script for CVE changes
create_table_cve_changes = f"""
CREATE TABLE IF NOT EXISTS {table_name_cve_changes} (
    CVE_ID NVARCHAR(255),
    EVENT_NAME NVARCHAR(255),
    CVE_CHANGE_ID NVARCHAR(255),
    SOURCE_IDENTIFIER NVARCHAR(255),
    CREATED_DATE DATETIME,
    RECORD_ADDED_DATE DATE
)
"""
cur.execute(create_table_cve_changes)
cur.execute("truncate table dwextract.cve_changes")

# Define the data types for each column
dtype_vulnerabilities = {
    'CVE_ID': types.NVARCHAR(length=255),
    'SOURCE_IDENTIFIER': types.NVARCHAR(length=255),
    'PUBLISHED_DATE': types.DATETIME,
    'LAST_MODIFIED_DATE': types.DATETIME,
    'VULNERABILITY_STATUS': types.NVARCHAR(length=255),
    'DESCRIPTION_EN': types.TEXT,
    'CVSS_BASE_SCORE': types.DECIMAL(4, 2),
    'ACCESS_VECTOR': types.NVARCHAR(length=255),
    'CONFIDENTIALITY_IMPACT': types.NVARCHAR(length=255),
    'INTEGRITY_IMPACT': types.NVARCHAR(length=255),
    'AVAILABILITY_IMPACT': types.NVARCHAR(length=255),
    'BASE_SEVERITY': types.NVARCHAR(length=255),
    'EXPLOITABILITY_SCORE': types.DECIMAL(4, 2),
    'IMPACT_SCORE': types.DECIMAL(4, 2),
    'WEAKNESS_DESCRIPTION': types.NVARCHAR(length=2000),
    'CONFIGURATION_CRITERIA': types.TEXT,
    'REFERENCE_URLS': types.TEXT,
    'RECORD_ADDED_DATE': types.DATE
}

dtype_cve_changes = {
    'CVE_ID': types.NVARCHAR(length=255),
    'EVENT_NAME': types.NVARCHAR(length=255),
    'CVE_CHANGE_ID': types.NVARCHAR(length=255),
    'SOURCE_IDENTIFIER': types.NVARCHAR(length=255),
    'CREATED_DATE': types.DATETIME,
    'RECORD_ADDED_DATE': types.DATE
}

# Insert data into SQL tables with error handling
try:
    # Insert vulnerability data
    for index, row in df_vulnerabilities.iterrows():
        sql = f"""
            INSERT INTO {table_name_vulnerabilities} 
            (CVE_ID, SOURCE_IDENTIFIER, PUBLISHED_DATE, LAST_MODIFIED_DATE, VULNERABILITY_STATUS, DESCRIPTION_EN, 
            CVSS_BASE_SCORE, ACCESS_VECTOR, CONFIDENTIALITY_IMPACT, INTEGRITY_IMPACT, AVAILABILITY_IMPACT, BASE_SEVERITY, 
            EXPLOITABILITY_SCORE, IMPACT_SCORE, WEAKNESS_DESCRIPTION, CONFIGURATION_CRITERIA, REFERENCE_URLS, RECORD_ADDED_DATE) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        cur.execute(sql, tuple(row))

    # Insert CVE changes data
    for index, row in df_cve_changes.iterrows():
        sql = f"""
            INSERT INTO {table_name_cve_changes} 
            (CVE_ID, EVENT_NAME, CVE_CHANGE_ID, SOURCE_IDENTIFIER, CREATED_DATE, RECORD_ADDED_DATE) 
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        cur.execute(sql, tuple(row))

    # Commit the transaction
    conn.commit()

    print("Data inserted into SQL tables successfully.")
except Exception as e:
    print(f"Failed to insert data into SQL tables: {e}")
    # Rollback the transaction in case of error
    conn.rollback()
finally:
    # Close cursor and connection
    cur.close()
    conn.close()
