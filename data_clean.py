import pandas as pd
import re
from IPython.display import display
import mysql.connector
from datetime import date

# Define MySQL connection parameters
mysql_host = 'localhost'
mysql_user = 'root'
mysql_password = 'admin'
mysql_database = 'cybercube'

# Create a connection to the MySQL database
conn = mysql.connector.connect(host=mysql_host, user=mysql_user, password=mysql_password, database=mysql_database)
cursor = conn.cursor()

# Create schema and tables
schema_creation_query = """
CREATE SCHEMA IF NOT EXISTS dwclean;
"""
cursor.execute(schema_creation_query)

table_creation_query_vulnerabilities = """
CREATE TABLE IF NOT EXISTS dwextract.vulnerabilities (
    CVE_ID VARCHAR(50),
    SOURCE_IDENTIFIER VARCHAR(255),
    PUBLISHED_DATE DATETIME,
    LAST_MODIFIED_DATE DATETIME,
    VULNERABILITY_STATUS VARCHAR(50),
    DESCRIPTION_EN TEXT,
    CVSS_BASE_SCORE DECIMAL(4,2),
    ACCESS_VECTOR VARCHAR(50),
    CONFIDENTIALITY_IMPACT VARCHAR(50),
    INTEGRITY_IMPACT VARCHAR(50),
    AVAILABILITY_IMPACT VARCHAR(50),
    BASE_SEVERITY VARCHAR(50),
    EXPLOITABILITY_SCORE DECIMAL(4,2),
    IMPACT_SCORE DECIMAL(4,2),
    WEAKNESS_DESCRIPTION VARCHAR(2000),
    CONFIGURATION_CRITERIA TEXT,
    REFERENCE_URLS TEXT,
    RECORD_ADDED_DATE DATE
);
"""
cursor.execute(table_creation_query_vulnerabilities)
cursor.execute("truncate table dwclean.vulnerabilities")


table_creation_query_cve_changes = """
CREATE TABLE IF NOT EXISTS dwextract.cve_changes (
    CVE_ID VARCHAR(30),
    EVENT_NAME VARCHAR(255),
    CVE_CHANGE_ID VARCHAR(50),
    SOURCE_IDENTIFIER VARCHAR(255),
    CREATED_DATE DATETIME,
    RECORD_ADDED_DATE DATE
);
"""
cursor.execute(table_creation_query_cve_changes)
cursor.execute("truncate table dwclean.cve_changes")

table_creation_query_dwclean_vulnerabilities = """
CREATE TABLE IF NOT EXISTS dwclean.vulnerabilities (
    CVE_ID VARCHAR(50),
    SOURCE_IDENTIFIER VARCHAR(255),
    PUBLISHED_DATE DATETIME,
    LAST_MODIFIED_DATE DATETIME,
    VULNERABILITY_STATUS VARCHAR(50),
    DESCRIPTION_EN TEXT,
    CVSS_BASE_SCORE DECIMAL(4,2),
    ACCESS_VECTOR VARCHAR(50),
    CONFIDENTIALITY_IMPACT VARCHAR(50),
    INTEGRITY_IMPACT VARCHAR(50),
    AVAILABILITY_IMPACT VARCHAR(50),
    BASE_SEVERITY VARCHAR(50),
    EXPLOITABILITY_SCORE DECIMAL(4,2),
    IMPACT_SCORE DECIMAL(4,2),
    WEAKNESS_DESCRIPTION VARCHAR(2000),
    CONFIGURATION_CRITERIA TEXT,
    REFERENCE_URLS TEXT,
    RECORD_ADDED_DATE DATE
);
"""
cursor.execute(table_creation_query_dwclean_vulnerabilities)

table_creation_query_dwclean_cve_changes = """
CREATE TABLE IF NOT EXISTS dwclean.cve_changes (
    CVE_ID VARCHAR(30),
    EVENT_NAME VARCHAR(255),
    CVE_CHANGE_ID VARCHAR(50),
    SOURCE_IDENTIFIER VARCHAR(255),
    CREATED_DATE DATETIME,
    RECORD_ADDED_DATE DATE
);
"""
cursor.execute(table_creation_query_dwclean_cve_changes)

# Function to process the vulnerabilities table
def process_vulnerabilities_table():
    mysql_table = 'dwextract.vulnerabilities'

    # Load the data from the MySQL table into a DataFrame
    cursor.execute(f'SELECT * FROM {mysql_table}')
    data = cursor.fetchall()
    columns = [i[0] for i in cursor.description]
    df = pd.DataFrame(data, columns=columns)

    # Define the regex pattern for valid CVE IDs (CVE-YYYY-XXXX or CVE-YYYY-XXXXX)
    cve_pattern = r'^CVE-\d{4}-\d+$'

    # Filter the DataFrame for valid CVE IDs
    filtered_df = df[df['CVE_ID'].astype(str).str.match(cve_pattern)].copy()

    # Fill default values for missing data
    default_values = {
        'SOURCE_IDENTIFIER': 'NA',
        'PUBLISHED_DATE': '1900-01-01T01:01:01.001',
        'LAST_MODIFIED_DATE': '1900-01-01T01:01:01.001',
        'VULNERABILITY_STATUS': 'NA',
        'DESCRIPTION_EN': 'NA',
        'CVSS_BASE_SCORE': 0.0,
        'ACCESS_VECTOR': 'NA',
        'CONFIDENTIALITY_IMPACT': 'NA',
        'INTEGRITY_IMPACT': 'NA',
        'AVAILABILITY_IMPACT': 'NA',
        'BASE_SEVERITY': 'NA',
        'EXPLOITABILITY_SCORE': 0.0,
        'IMPACT_SCORE': 0.0,
        'WEAKNESS_DESCRIPTION': 'NA',
        'CONFIGURATION_CRITERIA': 'NA',
        'REFERENCE_URLS': 'NA'
    }

    # Apply default values for empty fields and empty strings
    for column, default_value in default_values.items():
        if column in ['CVSS_BASE_SCORE', 'EXPLOITABILITY_SCORE', 'IMPACT_SCORE']:
            filtered_df[column] = filtered_df[column].fillna(0.0).replace('', 0.0)
        else:
            filtered_df[column] = filtered_df[column].fillna(default_value).replace('', default_value)

    # Apply additional validations and corrections
    score_columns = ['CVSS_BASE_SCORE', 'IMPACT_SCORE', 'EXPLOITABILITY_SCORE']
    for column in score_columns:
        filtered_df[column] = filtered_df[column].apply(lambda x: x if 0 <= x <= 10 else 0.0)

    valid_vulnerability_statuses = {'analyzed', 'awaiting analysis', 'modified', 'rejected', 'undergoing analysis'}
    filtered_df['VULNERABILITY_STATUS'] = filtered_df['VULNERABILITY_STATUS'].str.lower().apply(lambda x: x if x in valid_vulnerability_statuses else 'ND')

    valid_access_vectors = {'adjacent_network', 'local', 'network', 'na'}
    filtered_df['ACCESS_VECTOR'] = filtered_df['ACCESS_VECTOR'].str.lower().apply(lambda x: x if x in valid_access_vectors else 'ND')

    valid_confidentiality_impacts = {'complete', 'partial', 'na'}
    filtered_df['CONFIDENTIALITY_IMPACT'] = filtered_df['CONFIDENTIALITY_IMPACT'].str.lower().apply(lambda x: x if x in valid_confidentiality_impacts else 'ND')

    valid_integrity_impacts = {'complete', 'partial', 'na'}
    filtered_df['INTEGRITY_IMPACT'] = filtered_df['INTEGRITY_IMPACT'].str.lower().apply(lambda x: x if x in valid_integrity_impacts else 'ND')

    valid_availability_impacts = {'complete', 'none', 'partial', 'na'}
    filtered_df['AVAILABILITY_IMPACT'] = filtered_df['AVAILABILITY_IMPACT'].str.lower().apply(lambda x: x if x in valid_availability_impacts else 'ND')

    valid_base_severities = {'high', 'medium', 'na'}
    filtered_df['BASE_SEVERITY'] = filtered_df['BASE_SEVERITY'].str.lower().apply(lambda x: x if x in valid_base_severities else 'ND')

    # Print the filtered DataFrame with default values filled
    print("Filtered Vulnerabilities DataFrame with default values and validations applied:")
    display(filtered_df)

    # Remove duplicate records based on all columns
    filtered_df.drop_duplicates(inplace=True)

    # Print the filtered DataFrame with default values filled
    print("Filtered Vulnerabilities DataFrame with default values, validations applied, and duplicates removed:")
    display(filtered_df)

    # Add RECORD_ADDED_DATE column with the current date
    filtered_df['RECORD_ADDED_DATE'] = date.today()

    # Insert the filtered DataFrame into the dwclean.vulnerabilities table
    vulnerabilities_data = [tuple(row) for row in filtered_df.to_numpy()]
    vulnerabilities_query = """
        INSERT INTO dwclean.vulnerabilities 
        (CVE_ID, SOURCE_IDENTIFIER, PUBLISHED_DATE, LAST_MODIFIED_DATE, VULNERABILITY_STATUS, DESCRIPTION_EN, CVSS_BASE_SCORE, ACCESS_VECTOR,
        CONFIDENTIALITY_IMPACT, INTEGRITY_IMPACT, AVAILABILITY_IMPACT, BASE_SEVERITY, EXPLOITABILITY_SCORE, IMPACT_SCORE, WEAKNESS_DESCRIPTION,
        CONFIGURATION_CRITERIA, REFERENCE_URLS, RECORD_ADDED_DATE) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    cursor.executemany(vulnerabilities_query, vulnerabilities_data)
    conn.commit()
    print("Filtered vulnerabilities data inserted into dwclean.vulnerabilities")

# Function to process the cve_changes table
def process_cve_changes_table():
    mysql_table = 'dwextract.cve_changes'

    # Load the data from the MySQL table into a DataFrame
    cursor.execute(f'SELECT * FROM {mysql_table}')
    data = cursor.fetchall()
    columns = [i[0] for i in cursor.description]
    df = pd.DataFrame(data, columns=columns)

    # Define the regex pattern for valid CVE IDs (CVE-YYYY-XXXX or CVE-YYYY-XXXXX)
    cve_pattern = r'^CVE-\d{4}-\d+$'

    # Filter the DataFrame for valid CVE IDs
    filtered_df = df[df['CVE_ID'].astype(str).str.match(cve_pattern)].copy()

    # Fill default values for missing data
    default_values = {
        'CVE_CHANGE_ID': 'NA',
        'EVENT_NAME': 'NA',
        'SOURCE_IDENTIFIER': 'NA',
        'CREATED_DATE': pd.to_datetime('1900-01-01')
    }

    # Apply default values for empty fields and empty strings
    for column, default_value in default_values.items():
        filtered_df[column] = filtered_df[column].fillna(default_value).replace('', default_value)

    # Ensure CREATED_DATE is of datetime type
    filtered_df['CREATED_DATE'] = pd.to_datetime(filtered_df['CREATED_DATE'], errors='coerce').fillna(default_values['CREATED_DATE'])

    # Print the filtered DataFrame with default values filled
    print("Filtered CVE Changes DataFrame with default values:")
    display(filtered_df)

    # Remove duplicate records based on all columns
    filtered_df.drop_duplicates(inplace=True)

    # Print the filtered DataFrame with default values filled
    print("Filtered CVE Changes DataFrame with default values and duplicates removed:")
    display(filtered_df)

    # Add RECORD_ADDED_DATE column with the current date
    filtered_df['RECORD_ADDED_DATE'] = date.today()

    # Insert the filtered DataFrame into the dwclean.cve_changes table
    cve_changes_data = [tuple(row) for row in filtered_df.to_numpy()]
    cve_changes_query = """
        INSERT INTO dwclean.cve_changes 
        (CVE_ID, EVENT_NAME, CVE_CHANGE_ID, SOURCE_IDENTIFIER, CREATED_DATE, RECORD_ADDED_DATE) 
        VALUES (%s, %s, %s, %s, %s, %s)
    """
    cursor.executemany(cve_changes_query, cve_changes_data)
    conn.commit()
    print("Filtered CVE changes data inserted into dwclean.cve_changes")

# Process both tables
process_vulnerabilities_table()
process_cve_changes_table()

# Close the cursor and connection
cursor.close()
conn.close()
