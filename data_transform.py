import pandas as pd
import re
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

# Function to extract platform and product information from CONFIGURATION_CRITERIA
def extract_platform_product(criteria):
    cpe_regex = r'cpe:2\.3:[^:]+:([^:]+):([^:]+):'
    match = re.search(cpe_regex, criteria)
    if match:
        platform = match.group(1)
        product = match.group(2)
        return platform, product
    return 'NA', 'NA'

# Function to create and insert into separate tables
def create_and_insert_into_separate_table(table_name, column_name, data):
    create_table_query = f"""
    CREATE TABLE IF NOT EXISTS dwtransform.{table_name} (
        RECORD_ID INT AUTO_INCREMENT PRIMARY KEY,
        {column_name} VARCHAR(255),
        RECORD_ADDED_DATE DATE
    )
    """
    cursor.execute(create_table_query)

    # Check if values already exist in the table
    existing_values_query = f"SELECT {column_name} FROM dwtransform.{table_name}"
    cursor.execute(existing_values_query)
    existing_values = cursor.fetchall()
    existing_values = [value[0] for value in existing_values]

    unique_data = data.drop_duplicates().tolist()
    today_date = date.today()

    # Insert only if the value doesn't exist
    for item in unique_data:
        if item not in existing_values:
            insert_query = f"INSERT INTO dwtransform.{table_name} ({column_name}, RECORD_ADDED_DATE) VALUES (%s, %s)"
            cursor.execute(insert_query, (item, today_date))
            print(f"Data inserted into dwtransform.{table_name}: {item}")

    conn.commit()

# Function to process the vulnerabilities table
def process_vulnerabilities_table():
    mysql_table = 'dwclean.vulnerabilities'

    # Load the data from the MySQL table into a DataFrame
    cursor.execute(f'SELECT * FROM {mysql_table}')
    data = cursor.fetchall()
    columns = [i[0] for i in cursor.description]
    df = pd.DataFrame(data, columns=columns)

    # Extract platform and product information from CONFIGURATION_CRITERIA
    df[['PLATFORM', 'PRODUCT']] = df['CONFIGURATION_CRITERIA'].apply(lambda x: pd.Series(extract_platform_product(x)))

    # Create separate date and time columns for timestamps
    df['PUBLISHED_DATE'] = pd.to_datetime(df['PUBLISHED_DATE'])
    df['PUBLISHED_DATE_DATE'] = df['PUBLISHED_DATE'].dt.strftime('%Y-%m-%d')
    df['PUBLISHED_DATE_TIME'] = df['PUBLISHED_DATE'].dt.strftime('%H:%M:%S')

    df['LAST_MODIFIED_DATE'] = pd.to_datetime(df['LAST_MODIFIED_DATE'])
    df['LAST_MODIFIED_DATE_DATE'] = df['LAST_MODIFIED_DATE'].dt.strftime('%Y-%m-%d')
    df['LAST_MODIFIED_DATE_TIME'] = df['LAST_MODIFIED_DATE'].dt.strftime('%H:%M:%S')

    # Drop the REFERENCE_URLS column
    df.drop(columns=['REFERENCE_URLS'], inplace=True)

    # Debug: Print a sample of the DataFrame
    print("Sample of Transformed Vulnerabilities DataFrame:")
    print(df.head())

    # Move RECORD_ADDED_DATE column to the end
    record_added_date_column = df.pop('RECORD_ADDED_DATE')
    df['RECORD_ADDED_DATE'] = record_added_date_column

    # Insert the transformed DataFrame into the dwtransform.vulnerabilities table
    vulnerabilities_data = df.values.tolist()
    vulnerabilities_query = """
            INSERT INTO dwtransform.vulnerabilities 
            (CVE_ID, SOURCE_IDENTIFIER, PUBLISHED_DATE, LAST_MODIFIED_DATE, VULNERABILITY_STATUS, DESCRIPTION_EN, CVSS_BASE_SCORE, ACCESS_VECTOR,
            CONFIDENTIALITY_IMPACT, INTEGRITY_IMPACT, AVAILABILITY_IMPACT, BASE_SEVERITY, EXPLOITABILITY_SCORE, IMPACT_SCORE, WEAKNESS_DESCRIPTION,
            CONFIGURATION_CRITERIA, PLATFORM, PRODUCT, PUBLISHED_DATE_DATE, PUBLISHED_DATE_TIME, LAST_MODIFIED_DATE_DATE, LAST_MODIFIED_DATE_TIME, RECORD_ADDED_DATE) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
    cursor.executemany(vulnerabilities_query, vulnerabilities_data)
    conn.commit()
    print("Transformed vulnerabilities data inserted into dwtransform.vulnerabilities")

    # Create and insert into separate tables
    create_and_insert_into_separate_table('vulnerability_status', 'VULNERABILITY_STATUS', df['VULNERABILITY_STATUS'])
    create_and_insert_into_separate_table('access_vector', 'ACCESS_VECTOR', df['ACCESS_VECTOR'])
    create_and_insert_into_separate_table('confidentiality_impact', 'CONFIDENTIALITY_IMPACT', df['CONFIDENTIALITY_IMPACT'])
    create_and_insert_into_separate_table('availability_impact', 'AVAILABILITY_IMPACT', df['AVAILABILITY_IMPACT'])
    create_and_insert_into_separate_table('integrity_impact', 'INTEGRITY_IMPACT', df['INTEGRITY_IMPACT'])
    create_and_insert_into_separate_table('base_severity', 'BASE_SEVERITY', df['BASE_SEVERITY'])
    create_and_insert_into_separate_table('weakness_description', 'WEAKNESS_DESCRIPTION', df['WEAKNESS_DESCRIPTION'])
    create_and_insert_into_separate_table('source_identification', 'SOURCE_IDENTIFIER', df['SOURCE_IDENTIFIER'])
    create_and_insert_into_separate_table('platform', 'PLATFORM', df['PLATFORM'])
    create_and_insert_into_separate_table('product', 'PRODUCT', df['PRODUCT'])

# Function to process the cve_changes table
def process_cve_changes_table():
    mysql_table = 'dwclean.cve_changes'

    # Load the data from the MySQL table into a DataFrame
    cursor.execute(f'SELECT * FROM {mysql_table}')
    data = cursor.fetchall()
    columns = [i[0] for i in cursor.description]
    df = pd.DataFrame(data, columns=columns)

    # Create separate date and time columns for timestamps
    df['CREATED_DATE'] = pd.to_datetime(df['CREATED_DATE'])
    df['CREATED_DATE_DATE'] = df['CREATED_DATE'].dt.strftime('%Y-%m-%d')
    df['CREATED_DATE_TIME'] = df['CREATED_DATE'].dt.strftime('%H:%M:%S')

    # Move RECORD_ADDED_DATE column to the end
    record_added_date_column = df.pop('RECORD_ADDED_DATE')
    df['RECORD_ADDED_DATE'] = record_added_date_column

    # Debug: Print a sample of the DataFrame
    print("Sample of Transformed CVE Changes DataFrame:")
    print(df.head())

    # Insert the transformed DataFrame into the dwtransform.cve_changes table
    cve_changes_data = df.values.tolist()
    cve_changes_query = """
        INSERT INTO dwtransform.cve_changes 
        (CVE_ID, EVENT_NAME, CVE_CHANGE_ID, SOURCE_IDENTIFIER, CREATED_DATE, CREATED_DATE_DATE, CREATED_DATE_TIME, RECORD_ADDED_DATE) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    cursor.executemany(cve_changes_query, cve_changes_data)
    conn.commit()
    print("Transformed CVE changes data inserted into dwtransform.cve_changes")

    # Create and insert into separate tables
    create_and_insert_into_separate_table('event_name', 'EVENT_NAME', df['EVENT_NAME'])
    create_and_insert_into_separate_table('source_identification', 'SOURCE_IDENTIFIER', df['SOURCE_IDENTIFIER'])

# Create the dwtransform schema and tables if they don't exist
cursor.execute("CREATE SCHEMA IF NOT EXISTS dwtransform")

# Create dwtransform.vulnerabilities table
cursor.execute("""
    CREATE TABLE IF NOT EXISTS dwtransform.vulnerabilities (
        CVE_ID VARCHAR(255),
        SOURCE_IDENTIFIER VARCHAR(255),
        PUBLISHED_DATE DATETIME,
        LAST_MODIFIED_DATE DATETIME,
        VULNERABILITY_STATUS VARCHAR(255),
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
        PUBLISHED_DATE_DATE DATE,
        PUBLISHED_DATE_TIME TIME,
        LAST_MODIFIED_DATE_DATE DATE,
        LAST_MODIFIED_DATE_TIME TIME,
        RECORD_ADDED_DATE DATE
    )
""")
cursor.execute("TRUNCATE TABLE dwtransform.vulnerabilities")

# Create dwtransform.cve_changes table
cursor.execute("""
    CREATE TABLE IF NOT EXISTS dwtransform.cve_changes (
        CVE_ID VARCHAR(255),
        EVENT_NAME VARCHAR(255),
        CVE_CHANGE_ID VARCHAR(255),
        SOURCE_IDENTIFIER VARCHAR(255),
        CREATED_DATE DATETIME,
        CREATED_DATE_DATE DATE,
        CREATED_DATE_TIME TIME,
        RECORD_ADDED_DATE DATE
    )
""")
cursor.execute("TRUNCATE TABLE dwtransform.cve_changes")

# Process both tables
process_vulnerabilities_table()
process_cve_changes_table()

# Close the cursor and connection
cursor.close()
conn.close()
