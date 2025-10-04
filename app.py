from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

# --------------------- DATABASE MODELS ---------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(300))
    status = db.Column(db.String(20), default="Pending")

# --------------------- INITIALIZE DATABASE ---------------------
with app.app_context():
    db.create_all()
    if not User.query.filter_by(userid='admin1').first():
        u1 = User(userid='emp1', password=generate_password_hash('1234'), role='employee')
        u2 = User(userid='man1', password=generate_password_hash('1234'), role='manager')
        u3 = User(userid='admin1', password=generate_password_hash('1234'), role='admin')
        db.session.add_all([u1, u2, u3])
        db.session.commit()
        print("✅ Default users added: emp1 / man1 / admin1")

# --------------------- ROUTES ---------------------
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        userid = request.form['userid']
        password = request.form['password']
        user = User.query.filter_by(userid=userid).first()

        if user and check_password_hash(user.password, password):
            session['userid'] = user.userid
            session['role'] = user.role
            flash('Login successful!', 'success')

            if user.role == 'employee':
                return redirect(url_for('employee_dashboard'))
            elif user.role == 'manager':
                return redirect(url_for('manager_dashboard'))
            elif user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid UserID or Password', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --------------------- EMPLOYEE DASHBOARD ---------------------
@app.route('/employee/dashboard')
def employee_dashboard():
    if 'role' not in session or session['role'] != 'employee':
        return redirect(url_for('login'))
    expenses = Expense.query.filter_by(employee_id=session['userid']).all()
    return render_template('employee.html', userid=session['userid'], expenses=expenses)

@app.route('/employee/add', methods=['POST'])
def add_expense():
    if 'role' not in session or session['role'] != 'employee':
        return redirect(url_for('login'))

    category = request.form['category']
    amount = request.form['amount']
    description = request.form['description']

    new_expense = Expense(employee_id=session['userid'], category=category, amount=amount, description=description)
    db.session.add(new_expense)
    db.session.commit()
    flash('Expense added successfully!', 'success')
    return redirect(url_for('employee_dashboard'))

# --------------------- MANAGER DASHBOARD ---------------------
@app.route('/manager/dashboard')
def manager_dashboard():
    if 'role' not in session or session['role'] != 'manager':
        return redirect(url_for('login'))
    expenses = Expense.query.all()
    return render_template('manager.html', userid=session['userid'], expenses=expenses)

@app.route('/manager/approve/<int:id>')
def approve_expense(id):
    if 'role' not in session or session['role'] != 'manager':
        return redirect(url_for('login'))
    exp = Expense.query.get(id)
    exp.status = "Approved"
    db.session.commit()
    flash('Expense approved!', 'success')
    return redirect(url_for('manager_dashboard'))

@app.route('/manager/reject/<int:id>')
def reject_expense(id):
    if 'role' not in session or session['role'] != 'manager':
        return redirect(url_for('login'))
    exp = Expense.query.get(id)
    exp.status = "Rejected"
    db.session.commit()
    flash('Expense rejected!', 'danger')
    return redirect(url_for('manager_dashboard'))

# --------------------- ADMIN DASHBOARD ---------------------
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    users = User.query.all()
    expenses = Expense.query.all()
    return render_template('admin.html', userid=session['userid'], users=users, expenses=expenses)

@app.route('/admin/add_user', methods=['POST'])
def add_user():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    userid = request.form['userid']
    password = request.form['password']
    role = request.form['role']

    if User.query.filter_by(userid=userid).first():
        flash('User ID already exists!', 'warning')
        return redirect(url_for('admin_dashboard'))

    hashed_pw = generate_password_hash(password)
    new_user = User(userid=userid, password=hashed_pw, role=role)
    db.session.add(new_user)
    db.session.commit()
    flash(f'User "{userid}" added as {role} successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

# --------------------- RUN APP ---------------------
if __name__ == '__main__':
    app.run(debug=True)

