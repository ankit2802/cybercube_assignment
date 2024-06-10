import mysql.connector
from datetime import datetime

# Define MySQL connection parameters
mysql_host = 'localhost'
mysql_user = 'root'
mysql_password = 'admin'
mysql_database = 'cybercube'

# Create a connection to the MySQL database
conn = mysql.connector.connect(host=mysql_host, user=mysql_user, password=mysql_password, database=mysql_database)
cursor = conn.cursor()

# Function to fetch the existing CVE_IDs and CREATED_DATEs
def fetch_existing_cve_ids_and_dates(table_name):
    query = f"SELECT cve_id,cve_change_id FROM {table_name}"
    cursor.execute(query)
    return set(cursor.fetchall())

# Function to copy data from dwtransform.vulnerabilities to dwcurrent.vulnerabilities
def copy_vulnerabilities_data():
    # Read data from dwtransform.vulnerabilities
    cursor.execute("SELECT * FROM dwtransform.vulnerabilities")
    vulnerabilities_data = cursor.fetchall()

    # Create the dwcurrent schema and table if they don't exist
    cursor.execute("CREATE SCHEMA IF NOT EXISTS dwcurrent")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dwcurrent.vulnerabilities (
            CVE_ID VARCHAR(255) PRIMARY KEY NOT NULL,
            SOURCE_IDENTIFIER VARCHAR(255) NOT NULL,
            PUBLISHED_DATE DATETIME NOT NULL,
            LAST_MODIFIED_DATE DATETIME NOT NULL,
            VULNERABILITY_STATUS VARCHAR(255) NOT NULL,
            DESCRIPTION_EN TEXT,
            CVSS_BASE_SCORE DECIMAL(4,2),
            ACCESS_VECTOR VARCHAR(255),
            CONFIDENTIALITY_IMPACT VARCHAR(255),
            INTEGRITY_IMPACT VARCHAR(255),
            AVAILABILITY_IMPACT VARCHAR(255),
            BASE_SEVERITY VARCHAR(255),
            EXPLOITABILITY_SCORE DECIMAL(4,2),
            IMPACT_SCORE DECIMAL(4,2),
            WEAKNESS_DESCRIPTION TEXT,
            CONFIGURATION_CRITERIA TEXT,
            PLATFORM VARCHAR(255),
            PRODUCT VARCHAR(255),
            PUBLISHED_DATE_DATE DATE NOT NULL,
            PUBLISHED_DATE_TIME TIME NOT NULL,
            LAST_MODIFIED_DATE_DATE DATE NOT NULL,
            LAST_MODIFIED_DATE_TIME TIME NOT NULL,
            RECORD_ADDED_DATE DATE NOT NULL,
            INDEX cve_id_index (CVE_ID),
            INDEX last_modified_date_index (LAST_MODIFIED_DATE),
            INDEX record_added_at_index (RECORD_ADDED_DATE)
        )
    """)

    # Fetch existing CVE_IDs
    cursor.execute("SELECT CVE_ID FROM dwcurrent.vulnerabilities")
    existing_cve_ids = set(row[0] for row in cursor.fetchall())

    # Insert new records into dwcurrent.vulnerabilities
    insert_vulnerabilities_query = """
        INSERT INTO dwcurrent.vulnerabilities 
        (CVE_ID, SOURCE_IDENTIFIER, PUBLISHED_DATE, LAST_MODIFIED_DATE, VULNERABILITY_STATUS, DESCRIPTION_EN, CVSS_BASE_SCORE, ACCESS_VECTOR,
        CONFIDENTIALITY_IMPACT, INTEGRITY_IMPACT, AVAILABILITY_IMPACT, BASE_SEVERITY, EXPLOITABILITY_SCORE, IMPACT_SCORE, WEAKNESS_DESCRIPTION,
        CONFIGURATION_CRITERIA, PLATFORM, PRODUCT, PUBLISHED_DATE_DATE, PUBLISHED_DATE_TIME, LAST_MODIFIED_DATE_DATE, LAST_MODIFIED_DATE_TIME, RECORD_ADDED_DATE) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    for record in vulnerabilities_data:
        cve_id = record[0]
        if cve_id not in existing_cve_ids:
            cursor.execute(insert_vulnerabilities_query, record)

    conn.commit()
    print("Data copied to dwcurrent.vulnerabilities")

# Function to copy data from dwtransform.cve_changes to dwhist.cve_changes
def copy_cve_changes_data():
    # Read data from dwtransform.cve_changes
    cursor.execute("SELECT * FROM dwtransform.cve_changes")
    cve_changes_data = cursor.fetchall()

    # Create the dwhist schema and table if they don't exist
    cursor.execute("CREATE SCHEMA IF NOT EXISTS dwhist")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dwhist.cve_changes (
            CVE_ID VARCHAR(255) NOT NULL,
            EVENT_NAME VARCHAR(255) NOT NULL,
            CVE_CHANGE_ID VARCHAR(255) NOT NULL,
            SOURCE_IDENTIFIER VARCHAR(255) NOT NULL,
            CREATED_DATE DATETIME NOT NULL,
            CREATED_DATE_DATE DATE NOT NULL,
            CREATED_DATE_TIME TIME NOT NULL,
            RECORD_ADDED_DATE DATE NOT NULL,
            PRIMARY KEY (CVE_ID, CVE_CHANGE_ID),
            INDEX cve_id_index (CVE_ID),
            INDEX created_date_index (CREATED_DATE)
        )
    """)

    # Fetch existing CVE_IDs and CREATED_DATEs
    existing_cve_ids_and_dates = fetch_existing_cve_ids_and_dates('dwhist.cve_changes')

    # Insert new records into dwhist.cve_changes
    insert_cve_changes_query = """
        INSERT INTO dwhist.cve_changes 
        (CVE_ID, EVENT_NAME, CVE_CHANGE_ID, SOURCE_IDENTIFIER, CREATED_DATE, CREATED_DATE_DATE, CREATED_DATE_TIME, RECORD_ADDED_DATE) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    for record in cve_changes_data:
        cve_id = record[0]
        cve_change_id = record[2]
        if (cve_id,cve_change_id) not in existing_cve_ids_and_dates:
            cursor.execute(insert_cve_changes_query, record)

    conn.commit()
    print("Data copied to dwhist.cve_changes")

# Copy data from dwtransform tables to dwcurrent and dwhist tables
copy_vulnerabilities_data()
copy_cve_changes_data()

# Close the cursor and connection
cursor.close()
conn.close()
