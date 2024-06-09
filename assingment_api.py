from flask import Flask, jsonify, request
import mysql.connector
import datetime

app = Flask(__name__)

# MySQL database connection configuration
db_config = {
    'user': 'root',
    'password': 'admin',
    'host': 'localhost',
    'database': 'cybercube'
}


def get_db_connection():
    conn = mysql.connector.connect(**db_config)
    return conn


def convert_to_serializable(data):
    """ Convert non-serializable data types to serializable formats """
    for row in data:
        for key, value in row.items():
            if isinstance(value, (datetime.date, datetime.datetime)):
                row[key] = value.isoformat()
            elif isinstance(value, datetime.timedelta):
                row[key] = str(value)
    return data


@app.route('/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    cve_id = request.args.get('cve_id')
    product_id = request.args.get('product_id')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = "SELECT * FROM dw.vulnerabilities"
    conditions = []
    params = []

    if cve_id:
        conditions.append("CVE_ID = %s")
        params.append(cve_id)
    if product_id:
        conditions.append("PRODUCT = %s")
        params.append(product_id)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    serializable_data = convert_to_serializable(rows)
    return jsonify(serializable_data)


@app.route('/cve_changes', methods=['GET'])
def get_cve_changes():
    cve_id = request.args.get('cve_id')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = "SELECT * FROM dw.cve_changes"
    conditions = []
    params = []

    if cve_id:
        conditions.append("CVE_ID = %s")
        params.append(cve_id)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    serializable_data = convert_to_serializable(rows)
    return jsonify(serializable_data)


if __name__ == '__main__':
    app.run(debug=True)
