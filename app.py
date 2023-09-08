from datetime import datetime, timedelta
from flask import Flask, request, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
import secrets
import string
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

app = Flask(__name__)
app.config['SECRET_KEY'] = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'sameerjadhav2228@gmail.com'
app.config['MAIL_PASSWORD'] = 'uqwvjpdglblgjnlc'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

class PasswordReset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    expiration_date = db.Column(db.DateTime, nullable=False)

def send_confirmation_email(email, token):
    try:
        msg = Message('Confirm Your Email', sender='sameerjadhav2228@gmail.com', recipients=[email])
        confirmation_link = url_for('confirm_email', token=token, _external=True)
        msg.body = f'Click the following link to confirm your email: {confirmation_link}'
        mail.send(msg)
        flash('A confirmation email has been sent. Please check your email and click the link to confirm.', 'success')
    except Exception as e:
        flash(f'Email sending failed. Error: {str(e)}', 'danger')

@app.route("/")
@app.route("/home")
@login_required
def home():
    login_method = "email" if "@" in current_user.username else "username"
    return render_template('home.html', title='Home', current_user=current_user, login_method=login_method)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        logout_user()

    if request.method == 'POST':
        login_input, password = request.form['login_input'], request.form['password']
        user = User.query.filter((User.email == login_input) | (User.username == login_input)).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            current_user.email = '' if '@' not in user.username else current_user.email
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email or username and password', 'danger')

    return render_template('login.html', title='Login')

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username, email, password = request.form['username'], request.form['email'], request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        existing_user = User.query.filter((User.email == email) | (User.username == username)).first()

        if existing_user:
            flash('Email address or username already registered. Please use a different email or username.', 'danger')
        else:
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            token = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(32))
            send_confirmation_email(email, token)

            flash('Your account has been created! An email with a confirmation link has been sent to your email.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html', title='Register')

@app.route("/reset_password", methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            # Generate a password reset token
            token_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            token = token_serializer.dumps(user.email, salt='password-reset-salt')
            
            # Store the token and expiration date in the database
            expiration_date = datetime.now() + timedelta(hours=1)  # Token valid for 1 hour
            reset_token = PasswordReset(user_id=user.id, token=token, expiration_date=expiration_date)
            db.session.add(reset_token)
            db.session.commit()
            
            # Send the reset password email
            reset_link = url_for('set_new_password', token=token, _external=True)
            msg = Message('Password Reset', sender='sameerjadhav2228@gmail.com', recipients=[email])
            msg.body = f'Click the following link to reset your password: {reset_link}'
            mail.send(msg)

            flash('A password reset link has been sent to your email.', 'info')
            return redirect(url_for('login'))
        else:
            flash('Email address not found. Please check your email and try again.', 'danger')
    
    return render_template('reset_password.html', title='Reset Password')

@app.route('/set_new_password/<token>', methods=['GET', 'POST'])
def set_new_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
        else:
            # Verify and reset the user's password here
            token_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            try:
                email = token_serializer.loads(token, salt='password-reset-salt', max_age=3600)  # Max age: 1 hour
                user = User.query.filter_by(email=email).first()
                if user:
                    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                    user.password = hashed_password
                    db.session.commit()
                    flash('Your password has been reset successfully.', 'success')
                    return redirect(url_for('login'))
                else:
                    flash('Invalid token. Please request a new password reset.', 'danger')
            except SignatureExpired:
                flash('Token has expired. Please request a new password reset.', 'danger')
            except Exception:
                flash('Invalid token. Please request a new password reset.', 'danger')

    return render_template('set_new_password.html', title='Set New Password', token=token)

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = token
        # Implement email confirmation logic here
        flash(f'Your email ({email}) has been successfully confirmed!', 'success')
    except SignatureExpired:
        flash('The confirmation link has expired.', 'danger')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
