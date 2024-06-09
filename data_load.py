import mysql.connector

# Define MySQL connection parameters
mysql_host = 'localhost'
mysql_user = 'root'
mysql_password = 'admin'
mysql_database = 'cybercube'

# Create a connection to the MySQL database
conn = mysql.connector.connect(host=mysql_host, user=mysql_user, password=mysql_password, database=mysql_database)
cursor = conn.cursor()

# Create the dw schema and tables if they don't exist
cursor.execute("CREATE SCHEMA IF NOT EXISTS dw")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS dw.vulnerabilities (
        CVE_ID VARCHAR(255) PRIMARY KEY NOT NULL,
        SOURCE_IDENTIFIER_ID INT NOT NULL,
        PUBLISHED_DATE DATETIME NOT NULL,
        LAST_MODIFIED_DATE DATETIME NOT NULL,
        VULNERABILITY_STATUS_ID INT NOT NULL,
        DESCRIPTION_EN TEXT NOT NULL,
        CVSS_BASE_SCORE DECIMAL(4,2) NOT NULL,
        ACCESS_VECTOR_ID INT NOT NULL,
        CONFIDENTIALITY_IMPACT_ID INT NOT NULL,
        INTEGRITY_IMPACT_ID INT NOT NULL,
        AVAILABILITY_IMPACT_ID INT NOT NULL,
        BASE_SEVERITY_ID INT NOT NULL,
        EXPLOITABILITY_SCORE DECIMAL(4,2) NOT NULL,
        IMPACT_SCORE DECIMAL(4,2) NOT NULL,
        WEAKNESS_DESCRIPTION_ID INT NOT NULL,
        CONFIGURATION_CRITERIA TEXT NOT NULL,
        PLATFORM_ID INT NOT NULL,
        PRODUCT_ID INT NOT NULL,
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

cursor.execute("""
    CREATE TABLE IF NOT EXISTS dw.cve_changes (
        CVE_ID VARCHAR(255) NOT NULL,
        EVENT_NAME_ID INT NOT NULL,
        CVE_CHANGE_ID VARCHAR(255) NOT NULL,
        SOURCE_IDENTIFIER_ID INT NOT NULL,
        CREATED_DATE DATETIME NOT NULL,
        CREATED_DATE_DATE DATE NOT NULL,
        CREATED_DATE_TIME TIME NOT NULL,
        RECORD_ADDED_DATE DATE NOT NULL,
        PRIMARY KEY (CVE_ID, CVE_CHANGE_ID),
        INDEX cve_id_index (CVE_ID),
        INDEX created_date_index (CREATED_DATE)
    )
""")

# Function to fetch existing CVE_IDs, CVE_CHANGE_IDs from dw.cve_changes
def fetch_existing_cve_ids_and_dates(table_name):
    query = f"SELECT CVE_ID, CVE_CHANGE_ID FROM {table_name}"
    cursor.execute(query)
    return set(cursor.fetchall())

# Function to copy data from dwconform.vulnerabilities to dw.vulnerabilities
def copy_vulnerabilities_data():
    cursor.execute("SELECT * FROM dwconform.vulnerabilities")
    vulnerabilities_data = cursor.fetchall()

    transformed_data = []

    for record in vulnerabilities_data:
        cve_id, source_identifier_id, published_date, last_modified_date, vulnerability_status_id, description_en, \
        cvss_base_score, access_vector_id, confidentiality_impact_id, integrity_impact_id, availability_impact_id, \
        base_severity_id, exploitability_score, impact_score, weakness_description_id, configuration_criteria, \
        platform_id, product_id, published_date_date, published_date_time, last_modified_date_date, last_modified_date_time, record_added_date = record

        # Check if the record already exists in dw.vulnerabilities
        cursor.execute("SELECT COUNT(*) FROM dw.vulnerabilities WHERE CVE_ID = %s", (cve_id,))
        if cursor.fetchone()[0] == 0:
            transformed_data.append((cve_id, source_identifier_id, published_date, last_modified_date, vulnerability_status_id, description_en,
                                     cvss_base_score, access_vector_id, confidentiality_impact_id, integrity_impact_id, availability_impact_id,
                                     base_severity_id, exploitability_score, impact_score, weakness_description_id, configuration_criteria,
                                     platform_id, product_id, published_date_date, published_date_time, last_modified_date_date, last_modified_date_time, record_added_date))

    if transformed_data:
        insert_query = """
            INSERT INTO dw.vulnerabilities 
            (CVE_ID, SOURCE_IDENTIFIER_ID, PUBLISHED_DATE, LAST_MODIFIED_DATE, VULNERABILITY_STATUS_ID, DESCRIPTION_EN, 
            CVSS_BASE_SCORE, ACCESS_VECTOR_ID, CONFIDENTIALITY_IMPACT_ID, INTEGRITY_IMPACT_ID, AVAILABILITY_IMPACT_ID, 
            BASE_SEVERITY_ID, EXPLOITABILITY_SCORE, IMPACT_SCORE, WEAKNESS_DESCRIPTION_ID, CONFIGURATION_CRITERIA, 
            PLATFORM_ID, PRODUCT_ID, PUBLISHED_DATE_DATE, PUBLISHED_DATE_TIME, LAST_MODIFIED_DATE_DATE, LAST_MODIFIED_DATE_TIME, RECORD_ADDED_DATE) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.executemany(insert_query, transformed_data)
        conn.commit()
        print("Data copied to dw.vulnerabilities")

# Function to copy data from dwconform.cve_changes to dw.cve_changes
def copy_cve_changes_data():
    cursor.execute("SELECT * FROM dwconform.cve_changes")
    cve_changes_data = cursor.fetchall()

    # Fetch existing CVE_IDs and CVE_CHANGE_IDs
    existing_cve_ids_and_dates = fetch_existing_cve_ids_and_dates('dw.cve_changes')

    # Insert new records into dw.cve_changes
    insert_cve_changes_query = """
        INSERT INTO dw.cve_changes 
        (CVE_ID, EVENT_NAME_ID, CVE_CHANGE_ID, SOURCE_IDENTIFIER_ID, CREATED_DATE, CREATED_DATE_DATE, CREATED_DATE_TIME, RECORD_ADDED_DATE) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    for record in cve_changes_data:
        cve_id = record[0]
        cve_change_id = record[2]
        if (cve_id, cve_change_id) not in existing_cve_ids_and_dates:
            cursor.execute(insert_cve_changes_query, record)
    print("Data copied to dw.cve_changes")

    conn.commit()

# Copy data
copy_vulnerabilities_data()
copy_cve_changes_data()

# Close the cursor and connection
cursor.close()
conn.close()
