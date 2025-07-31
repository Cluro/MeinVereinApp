from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
import os
from datetime import datetime
import requests
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

load_dotenv()

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['BREVO_API_KEY'] = os.getenv('BREVO_API_KEY')
app.config['MAIL_SENDER'] = os.getenv('MAIL_SENDER')

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
    
    # Profildaten aus dem Warteraum-Formular
    birth_date = db.Column(db.Date, nullable=True)
    street = db.Column(db.String(150), nullable=True)
    zip_code = db.Column(db.String(10), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    phone_number = db.Column(db.String(50), nullable=True)
    # Allergien nehmen wir hier wie besprochen raus

    def __repr__(self):
        return f'<User {self.full_name}>'

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(200), nullable=False)

def send_email(to, subject, template):
    if not app.config['BREVO_API_KEY']:
        print("FEHLER: Brevo API Key nicht gefunden. E-Mail nicht gesendet.")
        return False
    url = "https://api.brevo.com/v3/smtp/email"
    headers = {"accept": "application/json", "api-key": app.config['BREVO_API_KEY'], "content-type": "application/json"}
    data = {"sender": {"email": app.config['MAIL_SENDER'], "name": "VereinsApp"}, "to": [{"email": to}], "subject": subject, "htmlContent": template}
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 201:
        print(f"E-Mail erfolgreich an {to} gesendet.")
        return True
    else:
        print(f"E-Mail-Versand an {to} fehlgeschlagen. Status: {response.status_code}, Antwort: {response.text}")
        return False

# --- Routen ---

@app.route("/")
def login_page():
    # TEMPORÄRE UMLEITUNG ZUM WARTERAUM FÜR ENTWICKLUNG
    return redirect(url_for('warteraum_page'))

@app.route("/registrieren", methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        # Prüfen, ob die E-Mail bereits existiert
        email = request.form.get('email')
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Diese E-Mail-Adresse ist bereits registriert. Bitte logge dich ein.', 'danger')
            return redirect(url_for('register_page'))

        # Neuen Benutzer erstellen
        full_name = request.form.get('full_name') # Geändert von 'name'
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(full_name=full_name, email=email, password=hashed_password) # Geändert von 'name'
        db.session.add(new_user)
        db.session.commit()

        # Bestätigungs-E-Mail senden
        token = s.dumps(email, salt='email-confirm')
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('email/activate.html', confirm_url=confirm_url, name=full_name)

        if send_email(email, "Bitte bestätige deine E-Mail-Adresse", html):
            flash('Dein Account wurde erstellt. Bitte überprüfe dein E-Mail-Postfach.', 'success')
        else:
            flash('Dein Account wurde erstellt, aber die Bestätigungs-E-Mail konnte nicht gesendet werden.', 'danger')
        return redirect(url_for('login_page'))
    return render_template("register.html")

@app.route('/confirm/<token>')
def confirm_email(token):
    # ... (bleibt wie bisher)
    pass # Platzhalter

@app.route("/warteraum")
@login_required
def warteraum_page():
    # Wenn ein Nutzer schon freigeschaltet ist, soll er nicht im Warteraum sein.
    # Schicke ihn direkt zum Dashboard.
    if current_user.is_approved:
        return redirect(url_for('dashboard_page'))
    
    # Ansonsten zeige die Warteraum-Seite an.
    return render_template("warteraum.html")


@app.route("/warteraum/spieler", methods=['GET', 'POST'])
@login_required
def spieler_formular_page():
    if request.method == 'POST':
        # Daten aus dem Formular holen und in der Datenbank speichern
        current_user.birth_date = datetime.strptime(request.form.get('birth_date'), '%Y-%m-%d').date()
        current_user.street = request.form.get('street')
        current_user.zip_code = request.form.get('zip_code')
        current_user.city = request.form.get('city')
        current_user.phone_number = request.form.get('phone_number')
        current_user.role = 'Spieler' # Rolle aktualisieren
        db.session.commit()
        flash('Deine Daten wurden erfolgreich übermittelt. Bitte warte auf die Freischaltung.', 'success')
        return redirect(url_for('warteraum_page'))

    return render_template("spieler_formular.html")


@app.route("/warteraum/eltern", methods=['GET', 'POST'])
@login_required
def eltern_formular_page():
    if request.method == 'POST':
        # Daten des Elternteils speichern
        current_user.phone_number = request.form.get('phone_number')
        current_user.role = 'Elternteil' # Rolle aktualisieren
        
        # Daten des Kindes holen und einen neuen Benutzer für das Kind erstellen
        child_full_name = request.form.get('child_full_name')
        child_birth_date = datetime.strptime(request.form.get('child_birth_date'), '%Y-%m-%d').date()

        # Kind-Account erstellen und mit Elternteil verknüpfen
        # Wir generieren ein temporäres, sehr schwer zu erratendes Passwort
        temp_password = os.urandom(16).hex() 
        hashed_password = bcrypt.generate_password_hash(temp_password).decode('utf-8')

        new_child = User(
            full_name=child_full_name,
            email=f"kind_{current_user.id}_{child_full_name.replace(' ','_')}@app.local", # Eindeutige Dummy-E-Mail
            password=hashed_password,
            role='Kind',
            is_approved=True,
            email_confirmed=True,
            birth_date=child_birth_date,
            parent_id=current_user.id
        )
        db.session.add(new_child)
        db.session.commit()
        
        flash('Deine und die Daten deines Kindes wurden erfolgreich übermittelt. Bitte warte auf die Freischaltung.', 'success')
        return redirect(url_for('warteraum_page'))

    return render_template("eltern_formular.html")

@app.route("/dashboard")
@login_required
def dashboard_page():
    # Wenn ein Nutzer noch nicht freigeschaltet ist, schicke ihn in den Warteraum.
    if not current_user.is_approved:
        return redirect(url_for('warteraum_page'))

    # Ansonsten zeige das Dashboard an.
    return render_template("dashboard.html")

@app.route("/logout")
# @login_required
def logout_page():
    # ... (bleibt wie bisher)
    pass # Platzhalter

# --- NEUE ROUTEN FÜR PASSWORT VERGESSEN ---
@app.route("/passwort-vergessen", methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            html = render_template('email/reset_instruction.html', user=user, reset_url=reset_url)
            if send_email(email, "Anleitung zum Zurücksetzen deines Passworts", html):
                flash('Eine E-Mail mit Anweisungen wurde an dich gesendet.', 'success')
            else:
                flash('Die E-Mail konnte nicht gesendet werden. Bitte versuche es später erneut.', 'danger')
        else:
            flash('Kein Account mit dieser E-Mail-Adresse gefunden.', 'warning')
        return redirect(url_for('forgot_password'))
    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600) # 1 Stunde gültig
    except:
        flash('Der Link zum Zurücksetzen des Passworts ist ungültig oder abgelaufen.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        password2 = request.form.get('password2')
        if password != password2:
            flash('Die Passwörter stimmen nicht überein.', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        user = User.query.filter_by(email=email).first_or_404()
        user.password = bcrypt.generate_password_hash(password).decode('utf-8')
        db.session.commit()
        flash('Dein Passwort wurde erfolgreich aktualisiert! Du kannst dich jetzt einloggen.', 'success')
        return redirect(url_for('login_page'))
        
    return render_template("reset_password.html", token=token)


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)