from flask import Flask, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import abort

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:root@localhost:5432/employee'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'dev-secret-key-change-this-later'

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class employee(db.Model):
    e_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    department = db.Column(db.Text, nullable=True)
    role = db.Column(db.String(200), nullable=False)
    salary = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f'<employee {self.e_id}>'


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=True)   # changed: was nullable=False
    role = db.Column(db.String(20), nullable=False)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.e_id'), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator


with app.app_context():
    db.create_all()
    # Temporary: creates one test user per role if they don't already exist.
    # Safe to leave in — the "if not" check prevents duplicate-username errors on restart.
    if not Users.query.filter_by(username="hr1").first():
        u = Users(username="hr1", role="hr")
        u.set_password("password123")
        db.session.add(u)
    if not Users.query.filter_by(username="admin1").first():
        u = Users(username="admin1", role="admin")
        u.set_password("password123")
        db.session.add(u)
    db.session.commit()


@app.route('/')
@login_required
def Employee_records():
    if current_user.role == 'employee':
        return redirect(url_for('dashboard'))
    
    search = request.args.get('search', '')
    role_filter = request.args.get('role', '')
    department_filter = request.args.get('department', '')
    salary_filter = request.args.get('salary', '')
    
    query = employee.query
    
    if search:
        query = query.filter(employee.name.ilike(f'{search}%'))
    if role_filter:
        query = query.filter(employee.role == role_filter)
    if department_filter:
        query = query.filter(employee.department == department_filter)
    if salary_filter:
        query = query.filter(employee.salary >= int(salary_filter))
    
    query = query.order_by(employee.name.asc())
    
    employees = query.all()
    
    all_roles = [r[0] for r in db.session.query(employee.role).distinct()]
    all_departments = [d[0] for d in db.session.query(employee.department).distinct() if d[0]]
    
    return render_template('main.html', employees=employees, search=search,
                            role_filter=role_filter, department_filter=department_filter,
                            salary_filter=salary_filter, all_roles=all_roles, all_departments=all_departments)


@app.route('/dashboard')
@login_required
@role_required('employee')
def dashboard():
    emp = employee.query.get_or_404(current_user.employee_id)
    return render_template('dashboard.html', emp=emp)


@app.route('/add', methods=['GET', 'POST'])
@login_required
@role_required('hr','admin')
def add_empdeets():
    if request.method == 'POST':
        name = request.form.get('name')
        department = request.form.get('department')
        role = request.form.get('role')
        salary = int(request.form.get('salary'))

        new_emp = employee(name=name, department=department, role=role, salary=salary)
        db.session.add(new_emp)
        db.session.commit()

        new_user = Users(username=name, role='employee', employee_id=new_emp.e_id, password_hash=None)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('Employee_records'))
    return render_template('add.html')


@app.route('/update/<int:e_id>', methods=['GET', 'POST'])
@login_required
def update_emp(e_id):
    emp = employee.query.get_or_404(e_id)

    if current_user.role == 'employee' and current_user.employee_id != e_id:
        abort(403)

    if request.method == 'POST':
        if current_user.role == 'employee':
            emp.name = request.form.get('name')
        else:
            emp.name = request.form.get('name')
            emp.department = request.form.get('department')
            emp.role = request.form.get('role')
            emp.salary = int(request.form.get('salary'))
        db.session.commit()
        return redirect(url_for('Employee_records'))

    if current_user.role == 'employee':
        return render_template('eupdate.html', emp=emp)
    return render_template('update.html', emp=emp)


@app.route('/delete/<int:e_id>')
@login_required
@role_required('admin')
def delete_emp(e_id):
    user = Users.query.filter_by(employee_id=e_id).first()
    db.session.delete(user)
    emp = employee.query.get_or_404(e_id)
    db.session.delete(emp)
    db.session.commit()
    return redirect(url_for('Employee_records'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = Users.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('Employee_records'))
        return "Invalid credentials"
    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = Users.query.filter_by(username=username).first()

        if not user:
            return "No account found with that username. Ask HR to confirm your username."
        if user.password_hash is not None:
            return "This account is already registered. Please log in instead."

        user.set_password(password)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')



if __name__ == '__main__':
    app.run(debug=True)
    
#search make it seperate in UI and make work in backend as  , make it sort as well, cook ui
#add session handling
#fix dashboard for employees , cuz it can edit salaries and role.