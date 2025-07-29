from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def login_page():
    # Dieser Befehl sucht im "templates"-Ordner nach der login.html und zeigt sie an.
    return render_template("login.html")

if __name__ == "__main__":
    app.run(debug=True)