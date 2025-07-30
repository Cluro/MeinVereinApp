from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
# WICHTIG: Ein geheimer Schlüssel für die Sicherheit von Formularen
app.config['SECRET_KEY'] = 'dein_super_geheimer_schluessel'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f'<User {self.name}>'

# Route für die Login-Seite
@app.route("/")
def login_page():
    return render_template("login.html")

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
# WICHTIG: Ein geheimer Schlüssel für die Sicherheit von Formularen
app.config['SECRET_KEY'] = 'dein_super_geheimer_schluessel'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f'<User {self.name}>'

# Route für die Login-Seite
@app.route("/", methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        email = request.form.get('email')
        password_candidate = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        # KORRIGIERTE LOGIK:
        if user and bcrypt.check_password_hash(user.password, password_candidate):
            # Fall 1: Login erfolgreich
            flash('Erfolgreich eingeloggt!', 'success')
            return redirect(url_for('dashboard_page')) # Leite zum Dashboard weiter
        else:
            # Fall 2: Login fehlgeschlagen
            flash('Login fehlgeschlagen. Überprüfe E-Mail und Passwort.', 'danger')
            return redirect(url_for('login_page')) # Bleibe auf der Login-Seite

    return render_template("login.html")

# Route für die Registrierungs-Seite
@app.route("/registrieren", methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Dein Account wurde erfolgreich erstellt! Du kannst dich jetzt einloggen.', 'success')
        return redirect(url_for('login_page'))
    return render_template("register.html")

# Route für die Dashboard-Seite (nach dem Login)
@app.route("/dashboard")
def dashboard_page():
    return render_template("dashboard.html")


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)