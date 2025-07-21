from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session, flash
import sqlite3
import io
import pandas as pd
import json
import datetime
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
DATABASE = 'tcwd_database.db'
ITEMS_PER_PAGE = 15
NUMERIC_COLUMNS = ['CumUsed', 'BillAmount']

PRIMARY_METRIC_OPTIONS = ["Type", "RateCode", "Status", "CumUsed", "BillAmount"]
GROUP_BY_OPTIONS = ["Address", "MeterNo", "BookNo", "RateCode", "Status", "AREA"]

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def bookno_sort_key(val):
    if val is None:
        return (2, "")
    val = str(val)
    return (1, int(val)) if val.isdigit() else (0, val.upper())

def get_columns():
    conn = get_db_connection()
    columns = [desc[0] for desc in conn.execute('SELECT * FROM "database" LIMIT 1').description]
    conn.close()
    return columns

def is_numeric_column(col):
    return col in NUMERIC_COLUMNS

def valid_column(col):
    columns = get_columns()
    return col in columns

def valid_aggregation(agg):
    return agg in ['sum', 'avg', 'min', 'max', 'count']

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['username'] == 'tcwd' and request.form['password'] == 'tcwdcic':
            session.clear()
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid credentials.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    search = request.args.get('q', '')
    status = request.args.get('status', '')
    bookno = request.args.get('bookno', '')
    ratecode = request.args.get('ratecode', '')
    area = request.args.get('area', '')
    type_ = request.args.get('type', '')
    page = int(request.args.get('page', 1))

    try:
        query = """
            SELECT Type, AccountNumber, Name, Address, MeterNo, BookNo, RateCode, Status, 
                   Cellphone, SeqNo, AREA, x, y, PRVReading, PRSReading, CumUsed, BillAmount
            FROM "database" WHERE 1=1
        """
        params = []

        if search:
            query += " AND (Name LIKE ? OR AccountNumber LIKE ? OR MeterNo LIKE ?)"
            like_term = f"%{search}%"
            params.extend([like_term, like_term, like_term])

        if status:
            query += " AND Status = ?"
            params.append(status)

        if bookno:
            query += " AND BookNo = ?"
            params.append(bookno)

        if ratecode:
            query += " AND RateCode = ?"
            params.append(ratecode)

        if area:
            query += " AND AREA = ?"
            params.append(area)

        if type_:
            query += " AND Type = ?"
            params.append(type_)

        offset = (page - 1) * ITEMS_PER_PAGE
        paginated_query = query + " LIMIT ? OFFSET ?"
        params_for_count = params.copy()
        params.extend([ITEMS_PER_PAGE, offset])

        conn = get_db_connection()
        rows = conn.execute(paginated_query, params).fetchall()
        rows = [dict(row) for row in rows]

        all_statuses = [row['Status'] for row in conn.execute('SELECT DISTINCT Status FROM "database"').fetchall()]
        all_booknos = [row['BookNo'] for row in conn.execute('SELECT DISTINCT BookNo FROM "database"').fetchall()]
        all_ratecodes = [row['RateCode'] for row in conn.execute('SELECT DISTINCT RateCode FROM "database"').fetchall()]
        all_areas = [row['AREA'] for row in conn.execute('SELECT DISTINCT AREA FROM "database"').fetchall()]
        all_types = [row['Type'] for row in conn.execute('SELECT DISTINCT Type FROM "database"').fetchall()]
        all_booknos = sorted(all_booknos, key=bookno_sort_key)

        count_query = "SELECT COUNT(*) FROM (SELECT * FROM \"database\" WHERE 1=1"
        count_params = []
        if search:
            count_query += " AND (Name LIKE ? OR AccountNumber LIKE ? OR MeterNo LIKE ?)"
            count_params.extend([like_term, like_term, like_term])
        if status:
            count_query += " AND Status = ?"
            count_params.append(status)
        if bookno:
            count_query += " AND BookNo = ?"
            count_params.append(bookno)
        if ratecode:
            count_query += " AND RateCode = ?"
            count_params.append(ratecode)
        if area:
            count_query += " AND AREA = ?"
            count_params.append(area)
        if type_:
            count_query += " AND Type = ?"
            count_params.append(type_)
        count_query += ")"
        total_rows = conn.execute(count_query, count_params).fetchone()[0]

        columns = [description[0] for description in conn.execute('SELECT * FROM "database" LIMIT 1').description]
        conn.close()

        total_pages = max(1, (total_rows + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE)

        return render_template(
            'index.html',
            rows=rows,
            columns=columns,
            search=search,
            statuses=all_statuses,
            selected_status=status,
            booknos=all_booknos,
            selected_bookno=bookno,
            ratecodes=all_ratecodes,
            selected_ratecode=ratecode,
            areas=all_areas,
            selected_area=area,
            types=all_types,
            selected_type=type_,
            page=page,
            total_pages=total_pages,
            total_rows=total_rows,
            zip=zip
        )
    except Exception as e:
        return render_template('error.html', message="A database error occurred. Please contact support.", error=str(e)), 500

@app.route('/export')
def export():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    search = request.args.get('q', '')
    status = request.args.get('status', '')
    bookno = request.args.get('bookno', '')
    ratecode = request.args.get('ratecode', '')
    area = request.args.get('area', '')
    type_ = request.args.get('type', '')
    export_format = request.args.get('format', 'csv')

    query = """
        SELECT Type, AccountNumber, Name, Address, MeterNo, BookNo, RateCode, Status, 
               Cellphone, SeqNo, AREA, x, y, PRVReading, PRSReading, CumUsed, BillAmount
        FROM "database" WHERE 1=1
    """
    params = []

    if search:
        query += " AND (Name LIKE ? OR AccountNumber LIKE ? OR MeterNo LIKE ?)"
        like_term = f"%{search}%"
        params.extend([like_term, like_term, like_term])

    if status:
        query += " AND Status = ?"
        params.append(status)

    if bookno:
        query += " AND BookNo = ?"
        params.append(bookno)

    if ratecode:
        query += " AND RateCode = ?"
        params.append(ratecode)

    if area:
        query += " AND AREA = ?"
        params.append(area)

    if type_:
        query += " AND Type = ?"
        params.append(type_)

    conn = get_db_connection()
    rows = conn.execute(query, params).fetchall()
    columns = [description[0] for description in conn.execute('SELECT * FROM "database" LIMIT 1').description]
    conn.close()

    df = pd.DataFrame([dict(row) for row in rows], columns=columns)

    if export_format == 'excel':
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False)
        output.seek(0)
        return send_file(output, as_attachment=True, download_name="tcwd_export.xlsx", mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    else:
        output = io.StringIO()
        df.to_csv(output, index=False)
        output.seek(0)
        return send_file(io.BytesIO(output.getvalue().encode()), as_attachment=True, download_name="tcwd_export.csv", mimetype='text/csv')

@app.route('/suggest')
def suggest():
    if not session.get('logged_in'):
        return jsonify([])

    term = request.args.get('term', '')
    conn = get_db_connection()
    rows = conn.execute(
        'SELECT DISTINCT Name FROM "database" WHERE Name LIKE ? LIMIT 10',
        (f'%{term}%',)
    ).fetchall()
    conn.close()
    suggestions = [row['Name'] for row in rows]
    return jsonify(suggestions)

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    columns = get_columns()
    date_column = None
    for c in columns:
        if c.lower() in ['date', 'createdat', 'timestamp']:
            date_column = c
            break
    return render_template(
        'dashboard.html', 
        columns=columns, 
        date_column=date_column, 
        numeric_columns=NUMERIC_COLUMNS, 
        primary_metric_options=PRIMARY_METRIC_OPTIONS,
        group_by_options=GROUP_BY_OPTIONS
    )

@app.route('/dashboard/data', methods=['GET'])
def dashboard_data():
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401

    metric = request.args.get('metric', 'CumUsed')
    group_by = request.args.get('group_by', '')
    group_by_value = request.args.get('group_by_value', '')
    aggregation = request.args.get('aggregation', 'sum').lower()
    chart_type = request.args.get('chart', 'pie')
    top_n = int(request.args.get('top_n', '10'))
    date_column = request.args.get('date_column', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    drill_field = request.args.get('drill_field', '')
    drill_value = request.args.get('drill_value', '')

    if metric not in PRIMARY_METRIC_OPTIONS:
        metric = 'CumUsed'
    if group_by and group_by not in GROUP_BY_OPTIONS:
        group_by = ''
    if not valid_aggregation(aggregation):
        aggregation = 'sum'
    if metric not in NUMERIC_COLUMNS and aggregation != 'count':
        aggregation = 'count'

    columns = get_columns()
    where_clauses = []
    params = []
    if date_column and date_from and date_to and date_column in columns:
        where_clauses.append(f'"{date_column}" >= ? AND "{date_column}" <= ?')
        params.extend([date_from, date_to])
    if drill_field and drill_value and drill_field in columns:
        where_clauses.append(f'"{drill_field}" = ?')
        params.append(drill_value)
    if group_by and group_by_value:
        where_clauses.append(f'"{group_by}" = ?')
        params.append(group_by_value)
    where_sql = ''
    if where_clauses:
        where_sql = 'WHERE ' + ' AND '.join(where_clauses)

    conn = get_db_connection()
    df = None
    summary = {}
    table_html = ''
    if group_by:
        agg_sql = f'{aggregation.upper()}("{metric}")' if aggregation != "count" else "COUNT(*)"
        query = f'SELECT "{group_by}" as group_field, {agg_sql} as value FROM "database" {where_sql} GROUP BY "{group_by}" ORDER BY value DESC LIMIT ?'
        params2 = params + [top_n]
        df = pd.read_sql_query(query, conn, params=params2)
        labels = df['group_field'].astype(str).tolist()
        values = df['value'].fillna(0).tolist()
        summary = {
            "total": float(df['value'].sum()) if len(df) else 0,
            "average": float(df['value'].mean()) if len(df) else 0,
            "min": float(df['value'].min()) if len(df) else 0,
            "max": float(df['value'].max()) if len(df) else 0,
            "groups": len(df),
            "metric": metric,
            "aggregation": aggregation,
            "group_by": group_by
        }
        table_html = df.rename(columns={'group_field': group_by, 'value': f"{aggregation.title()} of {metric}"}).to_html(
            classes="data-table", index=False, border=0)
        chart_data = {
            "labels": labels,
            "values": values
        }
    else:
        agg_sql = f'{aggregation.upper()}("{metric}")' if aggregation != "count" else "COUNT(*)"
        query = f'SELECT {agg_sql} as value FROM "database" {where_sql}'
        df = pd.read_sql_query(query, conn, params=params)
        val = float(df['value'].iloc[0]) if len(df) else 0
        chart_data = {
            "labels": [f"{aggregation.title()} of {metric}"],
            "values": [val]
        }
        summary = {
            "total": val,
            "metric": metric,
            "aggregation": aggregation
        }
        table_html = df.rename(columns={'value': f"{aggregation.title()} of {metric}"}).to_html(
            classes="data-table", index=False, border=0)

    ext_kpi = {}
    for col in NUMERIC_COLUMNS:
        if col != metric and col in columns:
            subq = f'SELECT SUM("{col}") as sum, AVG("{col}") as avg, MIN("{col}") as min, MAX("{col}") as max FROM "database" {where_sql}'
            subdf = pd.read_sql_query(subq, conn, params=params)
            ext_kpi[col] = {
                "sum": float(subdf['sum'].iloc[0]) if subdf['sum'].iloc[0] is not None else 0,
                "avg": float(subdf['avg'].iloc[0]) if subdf['avg'].iloc[0] is not None else 0,
                "min": float(subdf['min'].iloc[0]) if subdf['min'].iloc[0] is not None else 0,
                "max": float(subdf['max'].iloc[0]) if subdf['max'].iloc[0] is not None else 0,
            }
    summary["extra"] = ext_kpi
    conn.close()
    return jsonify({
        "data": chart_data,
        "summary": summary,
        "table_html": table_html
    })

@app.route('/dashboard/group_values')
def dashboard_group_values():
    if not session.get('logged_in'):
        return jsonify([])
    col = request.args.get("col", "")
    if col not in GROUP_BY_OPTIONS:
        return jsonify([])
    conn = get_db_connection()
    try:
        rows = conn.execute(f'SELECT DISTINCT "{col}" FROM "database" WHERE "{col}" IS NOT NULL ORDER BY "{col}" ASC LIMIT 300').fetchall()
        values = [str(row[0]) for row in rows if row[0] is not None and str(row[0]).strip() != ""]
    finally:
        conn.close()
    return jsonify(values)

@app.route('/dashboard/presets', methods=['GET', 'POST'])
def dashboard_presets():
    preset_file = 'dashboard_presets.json'
    if request.method == 'GET':
        try:
            with open(preset_file, 'r') as f:
                presets = json.load(f)
        except Exception:
            presets = []
        return jsonify(presets)
    else:
        try:
            preset = request.get_json()
            with open(preset_file, 'r') as f:
                presets = json.load(f)
        except Exception:
            presets = []
        presets = ([preset] + [p for p in presets if p != preset])[:10]
        with open(preset_file, 'w') as f:
            json.dump(presets, f)
        return jsonify({"ok": True})

@app.route('/dashboard/feedback', methods=['POST'])
def dashboard_feedback():
    feedback = request.form.get('feedback') or (request.json.get('feedback') if request.is_json else None)
    if feedback:
        with open("dashboard_feedback.log", "a", encoding='utf-8') as f:
            f.write(f"[{datetime.datetime.now()}]\n{feedback}\n\n")
        return '', 204
    return '', 400

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', message="Internal server error.", error=str(error)), 500

if __name__ == '__main__':
    app.run(debug=True)