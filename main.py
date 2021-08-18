from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# Flask Login Configure
login_manager = LoginManager()
login_manager.init_app(app)


# Provide user loader callback
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


# Line below only required once, when creating DB.
# db.create_all()


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == "POST":
        form_data = request.form
        user_name = form_data['name']
        user_email = form_data['email']
        if User.query.filter_by(email=user_email).first():
            # user already exist msg
            flash("you are already logged in using this email")
            return redirect(url_for('register'))
        user_password = generate_password_hash(form_data['password'], method='pbkdf2:sha256', salt_length=8)
        new_user = User(name=user_name, email=user_email, password=user_password)
        db.session.add(new_user)
        db.session.commit()
        # Log in and authenticate user after adding details to database.
        login_user(new_user)
        return redirect(url_for('secrets', name=new_user.name))
    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == "POST":
        form_data = request.form
        user_email = form_data['email']
        user_password = form_data['password']
        # Email doesn't exist
        user = User.query.filter_by(email=user_email).first()
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        # Password incorrect
        elif not check_password_hash(user.password, user_password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        # Email exists and password correct
        else:
            login_user(user)
            return redirect(url_for('secrets', name=user.name))
    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets/<name>')
@login_required
def secrets(name):
    return render_template("secrets.html", name=name)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    try:
        return send_from_directory('static', filename="files/cheat_sheet.pdf")
    except FileNotFoundError:
        return "404! File not found..."


if __name__ == "__main__":
    app.run(debug=True)
