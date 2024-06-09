import mysql.connector

# Define MySQL connection parameters
mysql_host = 'localhost'
mysql_user = 'root'
mysql_password = 'admin'
mysql_database = 'cybercube'

# Create a connection to the MySQL database
conn = mysql.connector.connect(host=mysql_host, user=mysql_user, password=mysql_password, database=mysql_database)
cursor = conn.cursor()

# Create the dwconform schema and tables if they don't exist
cursor.execute("CREATE SCHEMA IF NOT EXISTS dwconform")
cursor.execute("""
    CREATE TABLE IF NOT EXISTS dwconform.vulnerabilities (
        CVE_ID VARCHAR(255) PRIMARY KEY NOT NULL,
        SOURCE_IDENTIFIER_ID INT NOT NULL,
        PUBLISHED_DATE DATETIME NOT NULL,
        LAST_MODIFIED_DATE DATETIME NOT NULL,
        VULNERABILITY_STATUS_ID INT NOT NULL,
        DESCRIPTION_EN TEXT,
        CVSS_BASE_SCORE DECIMAL(4,2),
        ACCESS_VECTOR_ID INT,
        CONFIDENTIALITY_IMPACT_ID INT,
        INTEGRITY_IMPACT_ID INT,
        AVAILABILITY_IMPACT_ID INT,
        BASE_SEVERITY_ID INT,
        EXPLOITABILITY_SCORE DECIMAL(4,2),
        IMPACT_SCORE DECIMAL(4,2),
        WEAKNESS_DESCRIPTION_ID INT,
        CONFIGURATION_CRITERIA TEXT,
        PLATFORM_ID INT,
        PRODUCT_ID INT,
        PUBLISHED_DATE_DATE DATE NOT NULL,
        PUBLISHED_DATE_TIME TIME NOT NULL,
        LAST_MODIFIED_DATE_DATE DATE NOT NULL,
        LAST_MODIFIED_DATE_TIME TIME NOT NULL,
        RECORD_ADDED_DATE DATE NOT NULL
    )
""")
cursor.execute("""
    CREATE TABLE IF NOT EXISTS dwconform.cve_changes (
        CVE_ID VARCHAR(255) NOT NULL,
        EVENT_NAME_ID INT NOT NULL,
        CVE_CHANGE_ID VARCHAR(255) NOT NULL,
        SOURCE_IDENTIFIER_ID INT NOT NULL,
        CREATED_DATE DATETIME NOT NULL,
        CREATED_DATE_DATE DATE NOT NULL,
        CREATED_DATE_TIME TIME NOT NULL,
        RECORD_ADDED_DATE DATE NOT NULL,
        PRIMARY KEY (CVE_ID, CVE_CHANGE_ID, CREATED_DATE)
    )
""")
cursor.execute("TRUNCATE TABLE dwconform.vulnerabilities")
cursor.execute("TRUNCATE TABLE dwconform.cve_changes")

# Function to transform and insert vulnerabilities data
def transform_and_insert_vulnerabilities():
    cursor.execute("SELECT * FROM dwcurrent.vulnerabilities")
    vulnerabilities_data = cursor.fetchall()

    transformed_data = []

    # Join and transform the data to get codes instead of real values
    for record in vulnerabilities_data:
        cve_id, source_identifier, published_date, last_modified_date, vulnerability_status, description_en, \
        cvss_base_score, access_vector, confidentiality_impact, integrity_impact, availability_impact, \
        base_severity, exploitability_score, impact_score, weakness_description, configuration_criteria, \
        platform, product, published_date_date, published_date_time, last_modified_date_date, last_modified_date_time, record_added_date = record

        # Transform real values to codes (assuming you have lookup tables for the codes)
        cursor.execute("SELECT RECORD_ID FROM dwtransform.source_identification WHERE SOURCE_IDENTIFIER = %s", (source_identifier,))
        source_identifier_id = cursor.fetchone()[0]

        cursor.execute("SELECT RECORD_ID FROM dwtransform.vulnerability_status WHERE VULNERABILITY_STATUS = %s", (vulnerability_status,))
        vulnerability_status_id = cursor.fetchone()[0]

        cursor.execute("SELECT RECORD_ID FROM dwtransform.access_vector WHERE ACCESS_VECTOR = %s", (access_vector,))
        access_vector_id = cursor.fetchone()[0]

        cursor.execute("SELECT RECORD_ID FROM dwtransform.availability_impact WHERE AVAILABILITY_IMPACT = %s", (availability_impact,))
        availability_impact_id = cursor.fetchone()[0]

        cursor.execute("SELECT RECORD_ID FROM dwtransform.confidentiality_impact WHERE CONFIDENTIALITY_IMPACT = %s", (confidentiality_impact,))
        confidentiality_impact_id = cursor.fetchone()[0]

        cursor.execute("SELECT RECORD_ID FROM dwtransform.integrity_impact WHERE INTEGRITY_IMPACT = %s", (integrity_impact,))
        integrity_impact_id = cursor.fetchone()[0]

        cursor.execute("SELECT RECORD_ID FROM dwtransform.base_severity WHERE BASE_SEVERITY = %s", (base_severity,))
        base_severity_id = cursor.fetchone()[0]

        cursor.execute("SELECT RECORD_ID FROM dwtransform.weakness_description WHERE WEAKNESS_DESCRIPTION = %s", (weakness_description,))
        weakness_description_id = cursor.fetchone()[0]

        cursor.execute("SELECT RECORD_ID FROM dwtransform.platform WHERE PLATFORM = %s",(platform,))
        platform_id = cursor.fetchone()[0]

        cursor.execute("SELECT RECORD_ID FROM dwtransform.product WHERE PRODUCT = %s",(product,))
        product_id = cursor.fetchone()[0]

        # Append the transformed data to the list
        transformed_data.append((cve_id, source_identifier_id, published_date, last_modified_date, vulnerability_status_id, description_en,
                                 cvss_base_score, access_vector_id, confidentiality_impact_id, integrity_impact_id, availability_impact_id,
                                 base_severity_id, exploitability_score, impact_score, weakness_description_id, configuration_criteria,
                                 platform_id, product_id, published_date_date, published_date_time, last_modified_date_date, last_modified_date_time, record_added_date))

    # Insert the transformed data into dwconform.vulnerabilities
    insert_query = """
        INSERT INTO dwconform.vulnerabilities 
        (CVE_ID, SOURCE_IDENTIFIER_ID, PUBLISHED_DATE, LAST_MODIFIED_DATE, VULNERABILITY_STATUS_ID, DESCRIPTION_EN, 
        CVSS_BASE_SCORE, ACCESS_VECTOR_ID, CONFIDENTIALITY_IMPACT_ID, INTEGRITY_IMPACT_ID, AVAILABILITY_IMPACT_ID, 
        BASE_SEVERITY_ID, EXPLOITABILITY_SCORE, IMPACT_SCORE, WEAKNESS_DESCRIPTION_ID, CONFIGURATION_CRITERIA, 
        PLATFORM_ID, PRODUCT_ID, PUBLISHED_DATE_DATE, PUBLISHED_DATE_TIME, LAST_MODIFIED_DATE_DATE, LAST_MODIFIED_DATE_TIME, RECORD_ADDED_DATE) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    cursor.executemany(insert_query, transformed_data)
    conn.commit()
    print("Data transformed and copied to dwconform.vulnerabilities")

# Function to transform and insert cve_changes data
def transform_and_insert_cve_changes():
    cursor.execute("SELECT * FROM dwhist.cve_changes")
    cve_changes_data = cursor.fetchall()

    transformed_data = []

    # Transform and insert the data
    for record in cve_changes_data:
        cve_id, event_name, cve_change_id, source_identifier, created_date, created_date_date, created_date_time, record_added_date = record

        # Transform real values to codes (assuming you have lookup tables for the codes)
        cursor.execute("SELECT RECORD_ID FROM dwtransform.source_identification WHERE SOURCE_IDENTIFIER = %s", (source_identifier,))
        source_identifier_id = cursor.fetchone()[0]

        cursor.execute("SELECT RECORD_ID FROM dwtransform.event_name WHERE EVENT_NAME = %s", (event_name,))
        event_name_id = cursor.fetchone()[0]

        # Append the transformed data to the list
        transformed_data.append((cve_id, event_name_id, cve_change_id, source_identifier_id, created_date, created_date_date, created_date_time, record_added_date))

    # Insert the transformed data into dwconform.cve_changes
    insert_query = """
        INSERT INTO dwconform.cve_changes 
        (CVE_ID, EVENT_NAME_ID, CVE_CHANGE_ID, SOURCE_IDENTIFIER_ID, CREATED_DATE, CREATED_DATE_DATE, CREATED_DATE_TIME, RECORD_ADDED_DATE) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    cursor.executemany(insert_query, transformed_data)
    conn.commit()
    print("Data transformed and copied to dwconform.cve_changes")

# Transform and insert data
transform_and_insert_vulnerabilities()
transform_and_insert_cve_changes()

# Close the cursor and connection
cursor.close()
conn.close()
