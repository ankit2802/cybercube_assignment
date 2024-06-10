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
        conditions.append("PRODUCT_ID = %s")
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


@app.route('/severity_distribution', methods=['GET'])
def get_severity_distribution():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
    select count(*),bs.BASE_SEVERITY  from dw.vulnerabilities v join 
    dwtransform.base_severity bs on bs.RECORD_ID  = v.BASE_SEVERITY_ID group by bs.BASE_SEVERITY
    """

    cursor.execute(query)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify(rows)


@app.route('/worst_products_platforms', methods=['GET'])
def get_worst_products_platforms():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
    select pl.platform,P.PRODUCT,COUNT(CVE_ID) AS vulnerability_count FROM dw.vulnerabilities v
    inner join dwtransform.product p on v.PRODUCT_ID = p.record_id
    inner join dwtransform.platform pl on v.PRODUCT_ID = pl.record_id 
    GROUP BY p.product,pl.platform
    ORDER BY vulnerability_count DESC
    LIMIT 100
    """

    cursor.execute(query)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify(rows)


@app.route('/top_vulnerabilities_impact', methods=['GET'])
def get_top_vulnerabilities_impact():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
    SELECT CVE_ID,DESCRIPTION_EN,p.product,IMPACT_SCORE FROM dw.vulnerabilities v
    inner join dwtransform.product p on v.PRODUCT_ID = p.record_id
    ORDER BY IMPACT_SCORE DESC LIMIT 10
    """

    cursor.execute(query)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify(rows)


@app.route('/top_vulnerabilities_exploitability', methods=['GET'])
def get_top_vulnerabilities_exploitability():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
    SELECT CVE_ID,DESCRIPTION_EN,p.product,EXPLOITABILITY_SCORE FROM dw.vulnerabilities v
    inner join dwtransform.product p on v.PRODUCT_ID = p.record_id 
    ORDER BY EXPLOITABILITY_SCORE DESC LIMIT 10
    """

    cursor.execute(query)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify(rows)


@app.route('/top_attack_vectors', methods=['GET'])
def get_top_attack_vectors():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
    SELECT av.ACCESS_VECTOR AS AttackVector, COUNT(v.ACCESS_VECTOR_ID) AS Frequency FROM dw.vulnerabilities v
    JOIN dwtransform.access_vector av ON v.ACCESS_VECTOR_ID = av.RECORD_ID
    GROUP BY av.ACCESS_VECTOR ORDER BY Frequency DESC LIMIT 10
    """

    cursor.execute(query)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify(rows)


if __name__ == '__main__':
    app.run(debug=True)
