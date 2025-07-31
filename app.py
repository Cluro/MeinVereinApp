from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
import os
from datetime import datetime
import requests
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'pb_!7#a@s$d&f*g(h)j-k_l+z=x_c)v]b[n|m'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Brevo Konfiguration ---
app.config['BREVO_API_KEY'] = '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' # Bitte deinen Schlüssel eintragen
app.config['MAIL_SENDER'] = 'vereinapp@gmail.com' # Deine verifizierte Absender-E-Mail
# ------------------------------------

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'
login_manager.login_message = "Bitte melde dich an, um diese Seite zu sehen."
login_manager.login_message_category = "danger"

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    # Basis-Daten von der Registrierung
    full_name = db.Column(db.String(150), nullable=False) # Geändert von 'name'
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    
    # Status- und Rollen-System
    role = db.Column(db.String(50), nullable=False, default='Gast')
    is_approved = db.Column(db.Boolean, nullable=False, default=False) 
    email_confirmed = db.Column(db.Boolean, nullable=False, default=False)
    
    # Eltern-Kind-Verknüpfung
    parent_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    children = db.relationship('User', backref=db.backref('parent', remote_side=[id]))
    
    # NEU: Profil-Daten aus dem Warteraum-Formular
    birth_date = db.Column(db.Date, nullable=True)
    street = db.Column(db.String(150), nullable=True)
    zip_code = db.Column(db.String(10), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    phone_number = db.Column(db.String(50), nullable=True)
    allergies = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<User {self.full_name}>'

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f'<Event {self.title}>'

def send_email(to, subject, template):
    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "accept": "application/json",
        "api-key": app.config['BREVO_API_KEY'],
        "content-type": "application/json"
    }
    data = {
        "sender": {"email": app.config['MAIL_SENDER'], "name": "VereinsApp"},
        "to": [{"email": to}],
        "subject": subject,
        "htmlContent": template
    }
    response = requests.post(url, json=data, headers=headers)
    return response.status_code == 201

# --- Routen ---

@app.route("/", methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        email = request.form.get('email')
        password_candidate = request.form.get('password')
        remember = True if request.form.get('remember') else False # NEU

        user = User.query.filter_by(email=email).first()

        if not user or not bcrypt.check_password_hash(user.password, password_candidate):
            flash('Login fehlgeschlagen. Überprüfe E-Mail und Passwort.', 'danger')
            return redirect(url_for('login_page'))

        if not user.email_confirmed:
            flash('Bitte bestätige zuerst deine E-Mail-Adresse.', 'warning')
            return redirect(url_for('login_page'))

        # NEU: 'remember=remember' wurde hinzugefügt
        login_user(user, remember=remember) 

        if not user.is_approved:
            return redirect(url_for('warteraum_page'))
        else:
            return redirect(url_for('dashboard_page'))
            
    return render_template("login.html")

@app.route("/registrieren", methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        full_name = request.form.get('full_name') # Geändert von 'name'
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(full_name=full_name, email=email, password=hashed_password) # Geändert von 'name'
        db.session.add(new_user)
        db.session.commit()

        token = s.dumps(email, salt='email-confirm')
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('email/activate.html', confirm_url=confirm_url, name=full_name) # 'name' für die E-Mail hinzugefügt
        send_email(email, "Bitte bestätige deine E-Mail-Adresse", html)

        flash('Dein Account wurde erstellt. Bitte überprüfe dein E-Mail-Postfach, um deine Adresse zu bestätigen.', 'success')
        return redirect(url_for('login_page'))
    return render_template("register.html")

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except:
        flash('Der Bestätigungs-Link ist ungültig oder abgelaufen.', 'danger')
        return redirect(url_for('login_page'))

    user = User.query.filter_by(email=email).first_or_404()
    if user.email_confirmed:
        flash('Dein Account wurde bereits bestätigt.', 'success')
    else:
        user.email_confirmed = True
        db.session.commit()
        # HIER IST DIE GEÄNDERTE NACHRICHT:
        flash('Du hast dich erfolgreich mit der E-Mail bestätigt. Du musst dich jetzt einloggen und das Formular ausfüllen.', 'success')
    return redirect(url_for('login_page'))

@app.route("/warteraum")
@login_required
def warteraum_page():
    if current_user.is_approved:
        return redirect(url_for('dashboard_page'))
    return render_template("warteraum.html")

@app.route("/dashboard")
@login_required
def dashboard_page():
    if not current_user.is_approved:
        return redirect(url_for('warteraum_page'))
    return render_template("dashboard.html")

@app.route("/logout")
def logout_page():
    logout_user()
    flash("Du wurdest erfolgreich ausgeloggt.", "success")
    return redirect(url_for('login_page'))

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)