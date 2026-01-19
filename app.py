from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy import func
import os
app = Flask(__name__)


DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL:
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///local.db"

app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # admin, manager, employee
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    decisions = db.relationship('Decision', backref='creator', lazy=True)
    alerts = db.relationship('Alert', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Decision(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    financial_impact = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    outcome = db.Column(db.String(20), default='not_determined')  # not_determined, good, bad
    lessons_learned = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(500), nullable=False)
    alert_type = db.Column(db.String(20), nullable=False)  # high_risk, overdue
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    decision_id = db.Column(db.Integer, db.ForeignKey('decision.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/login/<role>', methods=['GET', 'POST'])
def login(role):
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password) and user.role == role:
            login_user(user)
            if role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif role == 'manager':
                return redirect(url_for('manager_dashboard'))
            else:
                return redirect(url_for('employee_dashboard'))
        else:
            flash('Invalid credentials or role mismatch', 'error')
    
    return render_template('login.html', role=role)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('landing'))

# Admin Routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('landing'))
    
    users = User.query.all()
    total_users = len(users)
    admins = len([u for u in users if u.role == 'admin'])
    managers = len([u for u in users if u.role == 'manager'])
    employees = len([u for u in users if u.role == 'employee'])
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    
    return render_template('admin_dashboard.html', 
                         total_users=total_users,
                         admins=admins,
                         managers=managers,
                         employees=employees,
                         recent_users=recent_users)

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        return redirect(url_for('landing'))
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/create-user', methods=['GET', 'POST'])
@login_required
def admin_create_user():
    if current_user.role != 'admin':
        return redirect(url_for('landing'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
        elif User.query.filter_by(email=email).first():
            flash('Email already exists', 'error')
        else:
            user = User(username=username, email=email, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('User created successfully', 'success')
            return redirect(url_for('admin_users'))
    
    return render_template('admin_create_user.html')

# Manager Routes
@app.route('/manager/dashboard')
@login_required
def manager_dashboard():
    if current_user.role != 'manager':
        return redirect(url_for('landing'))
    
    pending = Decision.query.filter_by(status='pending').count()
    reviewed = Decision.query.filter(Decision.status.in_(['approved', 'rejected'])).count()
    total_debt = db.session.query(func.sum(Decision.financial_impact)).filter(
        Decision.status == 'pending'
    ).scalar() or 0
    categories = Decision.query.with_entities(Decision.category).distinct().count()
    pending_decisions = Decision.query.filter_by(status='pending').order_by(Decision.created_at.desc()).limit(5).all()
    
    return render_template('manager_dashboard.html',
                         pending=pending,
                         reviewed=reviewed,
                         total_debt=total_debt,
                         categories=categories,
                         pending_decisions=pending_decisions)

@app.route('/manager/decisions')
@login_required
def manager_decisions():
    if current_user.role != 'manager':
        return redirect(url_for('landing'))
    decisions = Decision.query.order_by(Decision.created_at.desc()).all()
    return render_template('manager_decisions.html', decisions=decisions)

@app.route('/manager/review/<int:decision_id>', methods=['GET', 'POST'])
@login_required
def manager_review(decision_id):
    if current_user.role != 'manager':
        return redirect(url_for('landing'))
    
    decision = Decision.query.get_or_404(decision_id)
    
    if request.method == 'POST':
        action = request.form.get('action')
        outcome = request.form.get('outcome')
        lessons = request.form.get('lessons_learned')
        
        decision.status = action
        decision.outcome = outcome
        decision.lessons_learned = lessons
        decision.reviewed_at = datetime.utcnow()
        db.session.commit()
        
        flash(f'Decision {action} successfully', 'success')
        return redirect(url_for('manager_decisions'))
    
    return render_template('manager_review.html', decision=decision)

@app.route('/manager/analytics')
@login_required
def manager_analytics():
    if current_user.role != 'manager':
        return redirect(url_for('landing'))
    
    # Employee debt
    employee_debt = db.session.query(
        User.username,
        func.sum(Decision.financial_impact).label('debt')
    ).join(Decision).filter(Decision.status == 'pending').group_by(User.username).all()
    
    # High risk decisions
    high_risk = Decision.query.filter_by(status='pending').filter(
        Decision.financial_impact > 100000
    ).order_by(Decision.financial_impact.desc()).all()
    
    return render_template('manager_analytics.html',
                         employee_debt=employee_debt,
                         high_risk=high_risk)

# Employee Routes
@app.route('/employee/dashboard')
@login_required
def employee_dashboard():
    if current_user.role != 'employee':
        return redirect(url_for('landing'))
    
    total = Decision.query.filter_by(user_id=current_user.id).count()
    pending = Decision.query.filter_by(user_id=current_user.id, status='pending').count()
    debt = db.session.query(func.sum(Decision.financial_impact)).filter(
        Decision.user_id == current_user.id,
        Decision.status == 'pending'
    ).scalar() or 0
    alerts_count = Alert.query.filter_by(user_id=current_user.id, is_read=False).count()
    recent_alerts = Alert.query.filter_by(user_id=current_user.id).order_by(Alert.created_at.desc()).limit(5).all()
    
    return render_template('employee_dashboard.html',
                         total=total,
                         pending=pending,
                         debt=debt,
                         alerts_count=alerts_count,
                         recent_alerts=recent_alerts)

@app.route('/employee/create-decision', methods=['GET', 'POST'])
@login_required
def employee_create_decision():
    if current_user.role != 'employee':
        return redirect(url_for('landing'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        category = request.form.get('category')
        financial_impact = float(request.form.get('financial_impact'))
        
        decision = Decision(
            title=title,
            description=description,
            category=category,
            financial_impact=financial_impact,
            user_id=current_user.id
        )
        db.session.add(decision)
        db.session.commit()
        
        # Create alert for high-risk decisions
        if financial_impact > 100000:
            alert = Alert(
                message=f'High-risk decision "{title}" pending review',
                alert_type='high_risk',
                user_id=current_user.id,
                decision_id=decision.id
            )
            db.session.add(alert)
            db.session.commit()
        
        flash('Decision created successfully', 'success')
        return redirect(url_for('employee_decisions'))
    
    return render_template('employee_create.html')

@app.route('/employee/decisions')
@login_required
def employee_decisions():
    if current_user.role != 'employee':
        return redirect(url_for('landing'))
    decisions = Decision.query.filter_by(user_id=current_user.id).order_by(Decision.created_at.desc()).all()
    return render_template('employee_decisions.html', decisions=decisions)

@app.route('/employee/alerts')
@login_required
def employee_alerts():
    if current_user.role != 'employee':
        return redirect(url_for('landing'))
    alerts = Alert.query.filter_by(user_id=current_user.id).order_by(Alert.created_at.desc()).all()
    return render_template('employee_alerts.html', alerts=alerts)

@app.route('/api/dismiss-alert/<int:alert_id>', methods=['POST'])
@login_required
def dismiss_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    if alert.user_id == current_user.id:
        alert.is_read = True
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False}), 403

# API Routes for Charts
@app.route('/api/decisions-by-category')
@login_required
def decisions_by_category():
    data = db.session.query(
        Decision.category,
        func.count(Decision.id)
    ).group_by(Decision.category).all()
    return jsonify({'categories': [d[0] for d in data], 'counts': [d[1] for d in data]})

@app.route('/api/outcome-distribution')
@login_required
def outcome_distribution():
    data = db.session.query(
        Decision.outcome,
        func.count(Decision.id)
    ).group_by(Decision.outcome).all()
    return jsonify({'outcomes': [d[0] for d in data], 'counts': [d[1] for d in data]})

# Initialize database and create sample data
def init_db():
    with app.app_context():
        db.create_all()
        
        # Create sample users if none exist
        if not User.query.first():
            admin = User(username='admin', email='admin@example.com', role='admin')
            admin.set_password('admin123')
            
            manager = User(username='john_manager', email='john@example.com', role='manager')
            manager.set_password('manager123')
            
            employee1 = User(username='alice_employee', email='alice@example.com', role='employee')
            employee1.set_password('employee123')
            
            employee2 = User(username='bob_employee', email='bob@example.com', role='employee')
            employee2.set_password('employee123')
            
            db.session.add_all([admin, manager, employee1, employee2])
            db.session.commit()
            
            # Create sample decisions
            decision1 = Decision(
                title='Implement Cloud Migration Strategy',
                description='Migrate our on-premise infrastructure to AWS cloud services to improve scalability and reduce costs',
                category='Technical',
                financial_impact=150000,
                user_id=employee1.id
            )
            
            decision2 = Decision(
                title='CRM System Upgrade',
                description='Upgrade our current CRM system to the latest version',
                category='Operational',
                financial_impact=120000,
                user_id=employee2.id
            )
            
            db.session.add_all([decision1, decision2])
            db.session.commit()
            
            print("Database initialized with sample data!")
            print("Login credentials:")
            print("Admin: admin / admin123")
            print("Manager: john_manager / manager123")
            print("Employee: alice_employee / employee123")

if __name__ == '__main__':
    init_db()
    app.run(debug=True)



import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
