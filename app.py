from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'devavrat_secret'  # fixed secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ------------------ MODELS ------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default='employee')  # employee/manager/admin

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    category = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200))
    status = db.Column(db.String(20), default='Pending')  # Pending/Approved/Rejected

# ------------------ ROUTES ------------------

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    userid = request.form['userid']
    password = request.form['password']

    user = User.query.filter_by(userid=userid).first()
    if user and check_password_hash(user.password, password):
        session['user_id'] = user.id
        session['userid'] = user.userid
        session['role'] = user.role.lower()
        flash(f"Welcome {user.userid}!", "success")

        if session['role'] == 'employee':
            return redirect(url_for('employee_dashboard'))
        elif session['role'] == 'manager':
            return redirect(url_for('manager_dashboard'))
        elif session['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
    else:
        flash("Invalid credentials!", "danger")
        return redirect(url_for('home'))

@app.route('/dashboard')
def employee_dashboard():
    if 'role' not in session or session['role'] != 'employee':
        flash("Access denied!", "danger")
        return redirect(url_for('home'))
    user_expenses = Expense.query.filter_by(employee_id=session['user_id']).all()
    return render_template('employee.html', userid=session['userid'], expenses=user_expenses)

@app.route('/manager-dashboard')
def manager_dashboard():
    if 'role' not in session or session['role'] != 'manager':
        flash("Access denied!", "danger")
        return redirect(url_for('home'))
    pending_expenses = Expense.query.filter_by(status='Pending').all()
    return render_template('manager.html', userid=session['userid'], expenses=pending_expenses)

@app.route('/admin-dashboard')
def admin_dashboard():
    if 'role' not in session or session['role'] != 'admin':
        flash("Access denied!", "danger")
        return redirect(url_for('home'))
    all_expenses = Expense.query.all()
    all_users = User.query.all()
    return render_template('admin.html', userid=session['userid'], expenses=all_expenses, users=all_users)

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully!", "info")
    return redirect(url_for('home'))

# ------------------ ADD EXPENSE ------------------
@app.route('/add-expense', methods=['POST'])
def add_expense():
    if 'role' not in session or session['role'] != 'employee':
        flash("Access denied!", "danger")
        return redirect(url_for('home'))

    category = request.form['category']
    amount = request.form['amount']
    description = request.form['description']

    new_expense = Expense(
        employee_id=session['user_id'],
        category=category,
        amount=amount,
        description=description
    )
    db.session.add(new_expense)
    db.session.commit()
    flash("Expense added successfully!", "success")
    return redirect(url_for('employee_dashboard'))

# ------------------ MANAGER APPROVE/REJECT ------------------
@app.route('/update-expense/<int:expense_id>/<action>')
def update_expense(expense_id, action):
    if 'role' not in session or session['role'] != 'manager':
        flash("Access denied!", "danger")
        return redirect(url_for('home'))

    expense = Expense.query.get_or_404(expense_id)
    if action.lower() == 'approve':
        expense.status = 'Approved'
    elif action.lower() == 'reject':
        expense.status = 'Rejected'
    db.session.commit()
    flash(f"Expense {action.capitalize()}d successfully!", "success")
    return redirect(url_for('manager_dashboard'))

# ------------------ INITIALIZE DB ------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Add default users if not exist
        if not User.query.filter_by(userid='emp1').first():
            u1 = User(userid='emp1', password=generate_password_hash('1234'), role='employee')
            u2 = User(userid='man1', password=generate_password_hash('1234'), role='manager')
            u3 = User(userid='admin1', password=generate_password_hash('1234'), role='admin')
            db.session.add_all([u1,u2,u3])
            db.session.commit()
    app.run(debug=True)

# ------------------ ADMIN: ADD USER ------------------
@app.route('/add-user', methods=['POST'])
def add_user():
    if 'role' not in session or session['role'] != 'admin':
        flash("Access denied!", "danger")
        return redirect(url_for('home'))

    userid = request.form['userid']
    password = request.form['password']
    role = request.form['role']

    if User.query.filter_by(userid=userid).first():
        flash("UserID already exists!", "danger")
    else:
        new_user = User(
            userid=userid,
            password=generate_password_hash(password),
            role=role.lower()
        )
        db.session.add(new_user)
        db.session.commit()
        flash(f"User '{userid}' added successfully!", "success")

    return redirect(url_for('admin_dashboard'))
