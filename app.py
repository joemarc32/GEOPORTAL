from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session, flash
import sqlite3
import io
import pandas as pd


app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

DATABASE = 'tcwd_data.db'  # Updated to new database file
ITEMS_PER_PAGE = 15

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def bookno_sort_key(val):
    if val is None:
        return (2, "")
    val = str(val)
    return (1, int(val)) if val.isdigit() else (0, val.upper())

# Endpoint to provide available years for an account (for chart selector)
@app.route('/account_usage_years')
def account_usage_years():
    if not session.get('logged_in'):
        return jsonify([])
    account = request.args.get('account')
    if not account:
        return jsonify([])
    conn = get_db_connection()
    rows = conn.execute('SELECT DISTINCT Year FROM tcwd_data WHERE AccountNumber = ? ORDER BY Year ASC', (account,)).fetchall()
    conn.close()
    years = [row['Year'] for row in rows]
    return jsonify(years)

# Endpoint to provide CumUsed per month for a given account and year
# ... (existing imports and code) ...

# Endpoint to provide CumUsed per month for a given account and year
@app.route('/account_usage')
def account_usage():
    if not session.get('logged_in'):
        return jsonify({'error': 'Not logged in'}), 401

    account = request.args.get('account')
    year = request.args.get('year', type=int)
    if not account or not year:
        return jsonify({'error': 'Missing account or year'}), 400

    conn = get_db_connection()
    # Fetch data without sorting to handle sorting in Python
    rows = conn.execute(
        'SELECT Month, CumUsed FROM tcwd_data WHERE AccountNumber = ? AND Year = ?',
        (account, year)
    ).fetchall()
    conn.close()

    # Create a mapping of month names to numbers for correct sorting
    month_mapping = {
        'January': 1, 'February': 2, 'March': 3, 'April': 4,
        'May': 5, 'June': 6, 'July': 7, 'August': 8,
        'September': 9, 'October': 10, 'November': 11, 'December': 12
    }
    
    # Check if the Month column contains numerical month values, or month names
    # This assumes that if 'Month' is a key in the month_mapping, it's a month name.
    # If not, it assumes the value is already a number, and the original sorting worked fine.
    # It's always best to be explicit about the sorting.
    
    # Sort the data using the month_mapping
    sorted_rows = sorted(rows, key=lambda row: month_mapping.get(row['Month'], row['Month']))

    # Return array of objects for frontend compatibility
    return jsonify([{'Month': row['Month'], 'CumUsed': row['CumUsed']} for row in sorted_rows])

# ... (rest of the code) ...

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['username'] == 'tcwd' and request.form['password'] == 'tcwdcic':
            session.clear()  # Clear session to prevent fixation
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
    type_ = request.args.get('type', '')  # NEW: get Type filter
    page = int(request.args.get('page', 1))

    try:
        query = """
            SELECT Type, AccountNumber, Name, Address, MeterNo, BookNo, RateCode, Status, 
                   Cellphone, SeqNo, AREA, x, y, PRVReading, PRSReading, CumUsed, BillAmount, Year, Month
            FROM "tcwd_data" WHERE 1=1
        """
        params = []

        # Filter for latest year and month in the table
        conn = get_db_connection()
        latest_row = conn.execute('SELECT Year, Month FROM tcwd_data ORDER BY Year DESC, Month DESC LIMIT 1').fetchone()
        if latest_row:
            latest_year = latest_row['Year']
            latest_month = latest_row['Month']
            query += " AND Year = ? AND Month = ?"
            params.extend([latest_year, latest_month])
        else:
            latest_year = None
            latest_month = None

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

        rows = conn.execute(paginated_query, params).fetchall()
        rows = [dict(row) for row in rows]

        # Fetching all distinct values for filters (from latest month only)
        if latest_year is not None and latest_month is not None:
            filter_base = "SELECT DISTINCT {col} FROM tcwd_data WHERE Year = ? AND Month = ?"
            all_statuses = [row['Status'] for row in conn.execute(filter_base.format(col='Status'), (latest_year, latest_month)).fetchall()]
            all_booknos = [row['BookNo'] for row in conn.execute(filter_base.format(col='BookNo'), (latest_year, latest_month)).fetchall()]
            all_ratecodes = [row['RateCode'] for row in conn.execute(filter_base.format(col='RateCode'), (latest_year, latest_month)).fetchall()]
            all_areas = [row['AREA'] for row in conn.execute(filter_base.format(col='AREA'), (latest_year, latest_month)).fetchall()]
            all_types = [row['Type'] for row in conn.execute(filter_base.format(col='Type'), (latest_year, latest_month)).fetchall()]
            all_booknos = sorted(all_booknos, key=bookno_sort_key)
            all_ratecodes = sorted(all_ratecodes, key=lambda x: (str(x).upper() if x is not None else ""))
        else:
            all_statuses = []
            all_booknos = []
            all_ratecodes = []
            all_areas = []
            all_types = []

        # Get total rows for pagination (from latest month only)
        count_query = "SELECT COUNT(*) FROM (SELECT * FROM tcwd_data WHERE 1=1"
        count_params = []
        if latest_year is not None and latest_month is not None:
            count_query += " AND Year = ? AND Month = ?"
            count_params.extend([latest_year, latest_month])
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

        columns = [description[0] for description in conn.execute('SELECT * FROM tcwd_data LIMIT 1').description]
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
            zip=zip,
            # Pass idle timeout (ms) to template for JS
            idle_timeout_ms=60*60*1000
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
    type_ = request.args.get('type', '')  # NEW
    export_format = request.args.get('format', 'csv')

    query = """
        SELECT Type, AccountNumber, Name, Address, MeterNo, BookNo, RateCode, Status, 
               Cellphone, SeqNo, AREA, x, y, PRVReading, PRSReading, CumUsed, BillAmount, Year, Month
        FROM "tcwd_data" WHERE 1=1
    """
    params = []

    # Filter for latest year and month in the table
    conn = get_db_connection()
    latest_row = conn.execute('SELECT Year, Month FROM tcwd_data ORDER BY Year DESC, Month DESC LIMIT 1').fetchone()
    if latest_row:
        latest_year = latest_row['Year']
        latest_month = latest_row['Month']
        query += " AND Year = ? AND Month = ?"
        params.extend([latest_year, latest_month])
    else:
        latest_year = None
        latest_month = None

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

    rows = conn.execute(query, params).fetchall()
    columns = [description[0] for description in conn.execute('SELECT * FROM tcwd_data LIMIT 1').description]
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
    latest_row = conn.execute('SELECT Year, Month FROM tcwd_data ORDER BY Year DESC, Month DESC LIMIT 1').fetchone()
    suggestions = []
    if latest_row:
        latest_year = latest_row['Year']
        latest_month = latest_row['Month']
        rows = conn.execute(
            '''SELECT DISTINCT Name, AccountNumber, MeterNo FROM tcwd_data 
               WHERE (Name LIKE ? OR AccountNumber LIKE ? OR MeterNo LIKE ?) 
               AND Year = ? AND Month = ? LIMIT 10''',
            (f'%{term}%', f'%{term}%', f'%{term}%', latest_year, latest_month)
        ).fetchall()
        for row in rows:
            suggestions.append({
                'Name': row['Name'],
                'AccountNumber': row['AccountNumber'],
                'MeterNo': row['MeterNo']
            })
    conn.close()
    return jsonify(suggestions)

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', message="Internal server error.", error=str(error)), 500

if __name__ == '__main__':
    app.run(debug=True)