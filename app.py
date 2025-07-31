# ---------------------------------------------------
# --- 1. IMPORTS (Alle Zutaten an einem Ort) ---
# ---------------------------------------------------
import os
from datetime import datetime
import requests
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

# ---------------------------------------------------
# --- 2. KONFIGURATION (Die Grundeinstellungen) ---
# ---------------------------------------------------
load_dotenv() # Lädt die Geheimnisse aus der .env Datei

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)

# Liest die Geheimnisse jetzt sicher aus der .env Datei
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['BREVO_API_KEY'] = os.getenv('BREVO_API_KEY')
app.config['MAIL_SENDER'] = os.getenv('MAIL_SENDER')

# ---------------------------------------------------
# --- 3. INITIALISIERUNG (Die Helfer startklar machen) ---
# ---------------------------------------------------
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'
login_manager.login_message = "Bitte melde dich an, um diese Seite zu sehen."
login_manager.login_message_category = "danger"
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# ---------------------------------------------------
# --- 4. DATENBANK MODELLE (Der Bauplan für die Daten) ---
# ---------------------------------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='Gast')
    is_approved = db.Column(db.Boolean, nullable=False, default=False) 
    email_confirmed = db.Column(db.Boolean, nullable=False, default=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    children = db.relationship('User', backref=db.backref('parent', remote_side=[id]))
    birth_date = db.Column(db.Date, nullable=True)
    street = db.Column(db.String(150), nullable=True)
    zip_code = db.Column(db.String(10), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    phone_number = db.Column(db.String(50), nullable=True)
    allergies = db.Column(db.Text, nullable=True)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(200), nullable=False)

# ---------------------------------------------------
# --- 5. HILFSFUNKTIONEN (Unsere Werkzeuge) ---
# ---------------------------------------------------
def send_email(to, subject, template):
    # ... (Diese Funktion bleibt wie sie ist)
    pass

# ---------------------------------------------------
# --- 6. ROUTEN (Die Logik für die Webseiten) ---
# ---------------------------------------------------
@app.route("/", methods=['GET', 'POST'])
def login_page():
    if current_user.is_authenticated:
        if not current_user.is_approved:
            return redirect(url_for('warteraum_page'))
        return redirect(url_for('dashboard_page'))

    if request.method == 'POST':
        email = request.form.get('email')
        password_candidate = request.form.get('password')
        remember = True if request.form.get('remember') else False
        user = User.query.filter_by(email=email).first()

        if not user or not bcrypt.check_password_hash(user.password, password_candidate):
            flash('Login fehlgeschlagen. Überprüfe E-Mail und Passwort.', 'danger')
            return redirect(url_for('login_page'))

        if not user.email_confirmed:
            flash('Bitte bestätige zuerst deine E-Mail-Adresse.', 'warning')
            return redirect(url_for('login_page'))

        login_user(user, remember=remember)

        if not user.is_approved:
            return redirect(url_for('warteraum_page'))
        else:
            return redirect(url_for('dashboard_page'))
            
    return render_template("login.html")

@app.route("/registrieren", methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        email = request.form.get('email')
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Diese E-Mail-Adresse ist bereits registriert. Bitte logge dich ein.', 'danger')
            return redirect(url_for('register_page'))

        full_name = request.form.get('full_name')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # HIER IST DIE ÄNDERUNG: Wir setzen email_confirmed direkt auf True
        new_user = User(full_name=full_name, email=email, password=hashed_password, email_confirmed=True)
        
        db.session.add(new_user)
        db.session.commit()

        flash('Temporärer Test: Account wurde direkt bestätigt. Du kannst dich jetzt einloggen.', 'success')
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
        flash('Du hast dich erfolgreich mit der E-Mail bestätigt. Du musst dich jetzt einloggen und das Formular ausfüllen.', 'success')
    
    return redirect(url_for('login_page'))

@app.route("/warteraum/spieler", methods=['GET', 'POST'])
@login_required
def spieler_formular_page():
    # Logik zum Speichern kommt im nächsten Schritt
    return render_template("spieler_formular.html")

@app.route("/warteraum/eltern", methods=['GET', 'POST'])
@login_required
def eltern_formular_page():
    # Logik zum Speichern kommt im nächsten Schritt
    return render_template("eltern_formular.html")

@app.route("/dashboard")
@login_required
def dashboard_page():
    if not current_user.is_approved:
        return redirect(url_for('warteraum_page'))
    return render_template("dashboard.html")

@app.route("/logout")
@login_required
def logout_page():
    logout_user()
    flash("Du wurdest erfolgreich ausgeloggt.", "success")
    return redirect(url_for('login_page'))

# --- (Hier kommen die Routen für die Warteraum-Formulare hin, die wir als nächstes bauen) ---


# ---------------------------------------------------
# --- 7. APP STARTEN ---
# ---------------------------------------------------
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)