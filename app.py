from flask import Flask, render_template, redirect, url_for, session, flash, request, send_file, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt
from flask_mysqldb import MySQL
import pdfkit
import tempfile
import pandas as pd
from io import BytesIO


app = Flask(__name__)

# ------------------- MySQL Configuration -------------------
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'mydatabase'
app.config['MYSQL_PORT'] = 6306
app.secret_key = 'your_secret_key_here'

mysql = MySQL(app)

# ------------------- wkhtmltopdf Configuration -------------------
path_to_wkhtmltopdf = r'D:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'
config = pdfkit.configuration(wkhtmltopdf=path_to_wkhtmltopdf)

# ------------------- Forms -------------------
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise ValidationError('Email already registered.')

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

# ------------------- Helper Function -------------------
def get_user_by_id(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    return user

def render_user_page(template_name, **kwargs):
    if 'user_id' not in session:
        flash("Please log in to continue.", "warning")
        return redirect(url_for('login'))
    return render_template(template_name, **kwargs)

# ------------------- Routes -------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_password))
        mysql.connection.commit()
        cursor.close()

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['user_id'] = user[0]
            flash('Login successful.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash("Please log in to view your profile.", "warning")
        return redirect(url_for('login'))
    user = get_user_by_id(session['user_id'])
    return render_template('profile.html', user=user)


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user = get_user_by_id(session['user_id'])
        if user:
            return render_template('dashboard.html', user=user)
    flash("Please log in to access the dashboard.", 'warning')
    return redirect(url_for('login'))

@app.route('/calculator')
def calculator():
    return render_template('calculator.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()

        if user:
            session['reset_email'] = email
            return redirect(url_for('reset_password'))
        else:
            flash("Email not registered", "danger")
    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session:
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm_password']
        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(url_for('reset_password'))

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_pw, session['reset_email']))
        mysql.connection.commit()
        cur.close()
        session.pop('reset_email')
        flash("Password reset successful. Please login.", "success")
        return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/calculation-type1', methods=['GET', 'POST'])
def calculation_type1():
    return render_user_page('calculation_type1.html')

@app.route('/calculation-type2', methods=['GET', 'POST'])
def calculation_type2():
    items = [
        "Aluminium Cooker", "Aluminium Degda", "Aluminium Bhagona",
        "Aluminium Ghamela", "Aluminium Tope", "Aluminium Patila",
        "Aluminum Kadai", "Aluminium Dabba", "Aluminium Cooking Vessel"
    ]
    return render_user_page('calculation_type2.html', items=items)

@app.route('/download-pdf-type1', methods=['POST'])
def download_pdf_type1():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON payload"}), 400

        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO type1_reports
            (client_name, gross, bardan, bad, scrap_rate, net, scrap_amount,
             owner_item, object_net, object_bhav, object_amount,
             previous_bill, total_bill, final_amount)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            data['client_name'], data['gross'], data['bardan'], data['bad'],
            data['scrap_rate'], data['net'], data['scrap_amount'], data['owner_item'],
            data['object_net'], data['object_bhav'], data['object_amount'],
            data['previous_bill'], data['total_bill'], data['final_amount']
        ))
        mysql.connection.commit()
        cur.close()

        rendered = render_template('pdf_template_type1.html', data=data)
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_file:
            pdfkit.from_string(rendered, tmp_file.name, configuration=config)
            tmp_file_path = tmp_file.name

        filename = f"{data['client_name']}_report_type1.pdf"
        return send_file(tmp_file_path, as_attachment=True, download_name=filename)

    except Exception as e:
        print("❌ PDF Generation Error (Type 1):", e)
        return jsonify({"error": "PDF generation failed", "details": str(e)}), 500

@app.route('/download-pdf-type2', methods=['POST'])
def download_pdf_type2():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON payload"}), 400

        client_name = data['client_name']
        items = data['items']
        total_amount = float(data['total_amount'])
        paid_cash = float(data['paid_cash'])
        final_amount = float(data['final_amount'])

        cur = mysql.connection.cursor()
        for item in items:
            cur.execute("""
                INSERT INTO type2_reports
                (client_name, object_name, object_net, object_rate, object_amount,
                 total_amount, paid_cash, final_amount)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                client_name,
                item['name'], float(item['net']), float(item['rate']),
                float(item['amount']), total_amount, paid_cash, final_amount
            ))
        mysql.connection.commit()
        cur.close()

        rendered = render_template('pdf_template_type2.html', client_name=client_name, items=items,
                                   total_amount=total_amount, paid_cash=paid_cash, final_amount=final_amount)

        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_file:
            pdfkit.from_string(rendered, tmp_file.name, configuration=config)
            tmp_file_path = tmp_file.name

        filename = f"{client_name}_report_type2.pdf"
        return send_file(tmp_file_path, as_attachment=True, download_name=filename)

    except Exception as e:
        print("❌ PDF Generation Error (Type 2):", e)
        return jsonify({"error": "PDF generation failed", "details": str(e)}), 500

@app.route('/clients')
def clients():
    if 'user_id' not in session:
        flash("Please log in to access this page.", 'warning')
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, client_name, final_amount, 'Type 1' as report_type FROM type1_reports")
    type1_data = cur.fetchall()

    cur.execute("SELECT id, client_name, final_amount, 'Type 2' as report_type FROM type2_reports GROUP BY client_name")
    type2_data = cur.fetchall()

    cur.close()
    all_clients = type1_data + type2_data

    return render_template('clients.html', all_clients=all_clients)

@app.route('/edit-client/<report_type>/<int:id>', methods=['GET', 'POST'])
def edit_client(report_type, id):
    cur = mysql.connection.cursor()

    if report_type == 'Type 1':
        if request.method == 'POST':
            name = request.form['client_name']
            amount = request.form['final_amount']
            cur.execute("UPDATE type1_reports SET client_name=%s, final_amount=%s WHERE id=%s", (name, amount, id))
            mysql.connection.commit()
            flash("Client updated successfully.", "success")
            return redirect(url_for('clients'))

        cur.execute("SELECT id, client_name, final_amount FROM type1_reports WHERE id=%s", (id,))
        record = cur.fetchone()
        cur.close()
        return render_template('edit_client.html', record=record, report_type=report_type)

    elif report_type == 'Type 2':
        if request.method == 'POST':
            name = request.form['client_name']
            amount = request.form['final_amount']
            cur.execute("UPDATE type2_reports SET client_name=%s, final_amount=%s WHERE client_name=(SELECT client_name FROM type2_reports WHERE id=%s LIMIT 1)", (name, amount, id))
            mysql.connection.commit()
            flash("Client updated successfully.", "success")
            return redirect(url_for('clients'))

        cur.execute("SELECT id, client_name, final_amount FROM type2_reports WHERE id=%s", (id,))
        record = cur.fetchone()
        cur.close()
        return render_template('edit_client.html', record=record, report_type=report_type)

@app.route('/view-client/<report_type>/<int:id>')
def view_client(report_type, id):
    cur = mysql.connection.cursor()
    if report_type == 'Type 1':
        cur.execute("SELECT * FROM type1_reports WHERE id = %s", (id,))
        data = cur.fetchone()
        cur.close()
        client = [data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
                  data[10], data[11], data[12], data[13], data[14]]
        return render_template('view_client.html', report_type=report_type, client=client)

    elif report_type == 'Type 2':
        cur.execute("SELECT * FROM type2_reports WHERE client_name = (SELECT client_name FROM type2_reports WHERE id = %s LIMIT 1)", (id,))
        rows = cur.fetchall()
        cur.close()
        client = [rows[0][0], rows[0][1], rows[0][7], rows[0][5], rows[0][6]]  # [id, name, paid_cash, total_amount, final_amount]
        items = [{'name': r[2], 'net': r[3], 'rate': r[4], 'amount': r[5]} for r in rows]
        return render_template('view_client.html', report_type=report_type, client=client, items=items)

@app.route('/update-client/<report_type>/<int:id>', methods=['POST'])
def update_client(report_type, id):
    cur = mysql.connection.cursor()

    if report_type == 'Type 1':
        # Update Type 1 report fields
        data = {
            'client_name': request.form['client_name'],
            'gross': request.form['gross'],
            'bardan': request.form['bardan'],
            'bad': request.form['bad'],
            'scrap_rate': request.form['scrap_rate'],
            'net': request.form['net'],
            'scrap_amount': request.form['scrap_amount'],
            'owner_item': request.form['owner_item'],
            'object_net': request.form['object_net'],
            'object_bhav': request.form['object_bhav'],
            'object_amount': request.form['object_amount'],
            'previous_bill': request.form['previous_bill'],
            'total_bill': request.form['total_bill'],
            'final_amount': request.form['final_amount']
        }

        cur.execute("""
            UPDATE type1_reports SET
                client_name=%s, gross=%s, bardan=%s, bad=%s, scrap_rate=%s, net=%s, scrap_amount=%s,
                owner_item=%s, object_net=%s, object_bhav=%s, object_amount=%s,
                previous_bill=%s, total_bill=%s, final_amount=%s
            WHERE id=%s
        """, (*data.values(), id))
        mysql.connection.commit()
        flash("Type 1 report updated successfully.", "success")

    elif report_type == 'Type 2':
        # Delete old entries and insert new
        client_name = request.form['client_name']
        total_amount = request.form['total_amount']
        paid_cash = request.form['paid_cash']
        final_amount = request.form['final_amount']

        cur.execute("SELECT client_name FROM type2_reports WHERE id=%s LIMIT 1", (id,))
        old_name = cur.fetchone()[0]
        cur.execute("DELETE FROM type2_reports WHERE client_name=%s", (old_name,))

        item_names = request.form.getlist('item_name[]')
        nets = request.form.getlist('net[]')
        rates = request.form.getlist('rate[]')
        amounts = request.form.getlist('amount[]')

        for name, net, rate, amount in zip(item_names, nets, rates, amounts):
            cur.execute("""
                INSERT INTO type2_reports
                (client_name, object_name, object_net, object_rate, object_amount,
                 total_amount, paid_cash, final_amount)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (client_name, name, net, rate, amount, total_amount, paid_cash, final_amount))

        mysql.connection.commit()
        flash("Type 2 report updated successfully.", "success")

    cur.close()
    return redirect(url_for('clients'))
@app.route('/download-view-pdf/<report_type>/<int:id>')
def download_view_pdf(report_type, id):
    cur = mysql.connection.cursor()
    if report_type == 'Type 1':
        cur.execute("SELECT * FROM type1_reports WHERE id = %s", (id,))
        data = cur.fetchone()
        cur.close()

        rendered = render_template('pdf_template_type1.html', data={
            'client_name': data[1], 'gross': data[2], 'bardan': data[3], 'bad': data[4],
            'scrap_rate': data[5], 'net': data[6], 'scrap_amount': data[7],
            'owner_item': data[8], 'object_net': data[9], 'object_bhav': data[10],
            'object_amount': data[11], 'previous_bill': data[12],
            'total_bill': data[13], 'final_amount': data[14]
        })

        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_file:
            pdfkit.from_string(rendered, tmp_file.name, configuration=config)
            tmp_file_path = tmp_file.name
        return send_file(tmp_file_path, as_attachment=True, download_name=f"{data[1]}_report_type1.pdf")

    elif report_type == 'Type 2':
        cur.execute("SELECT * FROM type2_reports WHERE client_name = (SELECT client_name FROM type2_reports WHERE id = %s LIMIT 1)", (id,))
        rows = cur.fetchall()
        cur.close()
        items = [{'name': r[2], 'net': r[3], 'rate': r[4], 'amount': r[5]} for r in rows]

        rendered = render_template('pdf_template_type2.html',
                                   client_name=rows[0][1], items=items,
                                   total_amount=rows[0][6], paid_cash=rows[0][7],
                                   final_amount=rows[0][8])

        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_file:
            pdfkit.from_string(rendered, tmp_file.name, configuration=config)
            tmp_file_path = tmp_file.name
        return send_file(tmp_file_path, as_attachment=True, download_name=f"{rows[0][1]}_report_type2.pdf")

@app.route('/delete-client/<report_type>/<int:id>')
def delete_client(report_type, id):
    cur = mysql.connection.cursor()
    if report_type == 'Type 1':
        cur.execute("DELETE FROM type1_reports WHERE id = %s", (id,))
    elif report_type == 'Type 2':
        cur.execute("SELECT client_name FROM type2_reports WHERE id = %s", (id,))
        name = cur.fetchone()[0]
        cur.execute("DELETE FROM type2_reports WHERE client_name = %s", (name,))
    mysql.connection.commit()
    cur.close()
    flash("Client record deleted.", 'success')
    return redirect(url_for('clients'))

@app.route('/payment-analytics')
def payment_analytics():
    if 'user_id' not in session:
        flash("Please log in to access analytics.", 'warning')
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    cur.execute("SELECT client_name, final_amount, 'Type 1' as report_type FROM type1_reports")
    type1_data = cur.fetchall()

    cur.execute("SELECT client_name, final_amount, 'Type 2' as report_type FROM type2_reports GROUP BY client_name")
    type2_data = cur.fetchall()

    cur.close()
    combined_data = type1_data + type2_data
    return render_template('analytics.html', data=combined_data)

@app.route('/export-to-excel')
def export_to_excel():
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM type1_reports")
        type1_data = cur.fetchall()
        type1_columns = [desc[0] for desc in cur.description]
        df1 = pd.DataFrame(type1_data, columns=type1_columns)

        cur.execute("SELECT * FROM type2_reports")
        type2_data = cur.fetchall()
        type2_columns = [desc[0] for desc in cur.description]
        df2 = pd.DataFrame(type2_data, columns=type2_columns)

        cur.close()

        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df1.to_excel(writer, sheet_name='Type1 Reports', index=False)
            df2.to_excel(writer, sheet_name='Type2 Reports', index=False)
        output.seek(0)

        return send_file(output, as_attachment=True, download_name='client_reports.xlsx',
                         mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

    except Exception as e:
        print("❌ Excel Export Error:", e)
        return jsonify({"error": "Export failed", "details": str(e)}), 500

# ------------------- Run App -------------------
if __name__ == '__main__':
    app.run(debug=True)