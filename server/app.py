from flask import Flask, request,render_template, redirect, session, g, flash, request, url_for
from flask_sqlalchemy import SQLAlchemy
from helper import read_blocklist_file, isValid
from forms.forms import *
import os
import ssl
import smtplib
import bcrypt
import uuid
import datetime
from datetime import timedelta, datetime
# from sqlalchemy.sql import func
from smtplib import SMTPAuthenticationError
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
# PSQL
from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import text

app = Flask(__name__)
app.config.from_object('config.Config')
app.permanent_session_lifetime = timedelta(days=30)
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    email = Column(String(100), unique=True)
    password = Column(String(100), nullable=False)
    token = Column(String(100), unique=True)
    created_at = Column(DateTime, server_default=text('NOW()'), nullable=False)

    def __init__(self, name, email, password, token):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self.token = token

    def check_password(self,password):
        return bcrypt.checkpw(password.encode('utf-8'),self.password.encode('utf-8'))

class AuthUser(db.Model):
    __tablename__ = 'auth_users'

    user_id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(100), unique=True, nullable=False)
    is_auth = db.Column(db.Boolean, default=False)

    def __init__(self, user_email, is_auth=False):
        self.user_email = user_email
        self.is_auth = is_auth

with app.app_context():
    db.create_all()

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me', default=True)

class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])


def writeEmail(address, name, token):
    nolist = read_blocklist_file(app)
    # make sure email address put in form is not on blocklist
    if address not in nolist and name and token:
        username = app.config['USERNAME']
        password = app.config['PASS']
        sender_name = 'coding in py'
        try:
            if request.host == '127.0.0.1:5000':
                # Development environment URL
                base_url = 'http://127.0.0.1:5000'
            else:
                # Production environment URL
                base_url = 'https://login-tfe4zqdz6a-ue.a.run.app'
            htmls = ""
            #Change this name if you want to be presented differently in emails
            html = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Account Registration</title>
            </head>
            <body>
                <p>Hello {name},</p>
                <p>Thank you for registering an account with us. Here are your registration details:</p>    
                <ul>
                    <li><strong>Name:</strong> {name}</li>
                    <li><strong>Email:</strong> {address}</li>
                </ul>
                <p>To complete your registration, please click the following link:</p>
                <p><a href="{base_url}/register?t={token}">Complete Registration</a></p>
                <p>If you did not create an account with us, please ignore this email.</p>        
                <p>Best regards,<br>Your Company Name</p>
            </body>
            </html>
            """
            msg = MIMEMultipart()
            msg['Subject'] = "finish registering"
            msg['From'] = f'{sender_name} • <{username}>'
            recipients = address
            msg['To'] = address
            # Attach HTML to the email
            body = MIMEText(html, 'html')
            msg.attach(body)

            try:
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
                    smtp.login(username, password)
                    smtp.sendmail(username, recipients, msg.as_string())
                print("Email sent successfully to " + recipients)
            except smtplib.SMTPAuthenticationError:
                print('SMTPAuthenticationError')
                return "Email Server Error"

        except Exception as e:
            print('form error:', str(e))
            return "Email Server Error"
        return True
    else: 
        print("Request from blocked email")
        return None

def authNewU(t):
    now = datetime.utcnow()
    try:
        findU = db.session.query(User).filter_by(token=t).first()
    except:
        flash('invalid registration')
        print('incorrect auth request')
        return None
    if findU:
        datetime_str1 = findU.created_at

        date_difference = now - datetime_str1
        # Check if the difference is less than or equal to 14 days
        if date_difference <= timedelta(days=14):
            return findU
        else:
            print("Must auth within 14 days")
            flash("Must auth within 14 days")
            try:
                # Email new token if auth is too late after 14 days
                newtoken = str(uuid.uuid4())
                user_to_update = db.session.query(User).filter_by(token=t).first()
                if user_to_update:
                    user_to_update.created_at = now
                    user_to_update.token = newtoken
                writeEmail(findU.email, findU.name, newtoken)
            except Exception as e:
                print(e)
                return None
            flash("new email sent")
            db.session.commit()
            return None
    else:
        print("invalid auth in request parameters")
        return None

@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        obj = load_user(session['user_id'])
        if obj:
            g.user = obj
        
@app.route('/')
def index():
    return render_template('index.html', home=True)

def load_user(id):
    return db.session.query(User).filter_by(id=id).first()

@app.route('/register',methods=['GET','POST'])
def register():
    regform = RegisterForm()
    if request.method == 'GET':
        t = request.args.get('t', None)
        if t:
            authres = authNewU(t)
            if authres:
                try:
                    ret_user = AuthUser.query.filter_by(user_email=authres.email).first()
                    if ret_user and ret_user.is_auth == False:
                        ret_user.is_auth = True
                        db.session.commit()
                        session['user_id'] = authres.id
                        g.user = authres
                        return redirect(url_for('dashboard', new=1))
                    else:
                        flash('error validating account')
                except Exception as e:
                    print(e)
                    flash("authorizing new user error")

    if request.method == 'POST' and regform.validate_on_submit:
        if not g.user:
            # handle request
            name = regform.name.data
            email = regform.email.data
            password = regform.password.data
            token = None
            if not isValid(email):
                flash("invalid email pattern")
                return render_template('register.html', regform=regform)
            try:
                token = str(uuid.uuid4())
                new_user = User(name=name.strip(),email=email.strip(),password=password, token=token)
                db.session.add(new_user)
                db.session.commit()
            except Exception as e:
                print(e)
                flash('please register with unique email address')
                return render_template('register.html', regform=regform)
            response = writeEmail(email, name, token)
            if isinstance(response, bool) and response:
                flash('confirmation email sent')
            if not response:
                user_to_delete = db.session.query(User).filter_by(email=email).first()
                if user_to_delete:
                    db.session.delete(user_to_delete)
                    db.session.commit()
                    flash('email confirmation error')
                    return render_template('register.html', regform=regform)
        if g.user:
            pass
        return redirect('/login/login')
    return render_template('register.html', regform=regform)

@app.route('/login/<new>',methods=['GET','POST'])
def login(new):
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit:
        email = form.email.data
        password = form.password.data
        remember_me = form.remember
        # When a site admin submits login credentials.
        if email==app.config['USERNAME'] and password==app.config['ADMIN']:
            g.user = { "id": -1, "admin_name": "admin", "email": app.config['USERNAME'], "password": app.config['ADMIN']}
            return redirect('/admin')

        if not g.user:
            tempu = db.session.query(User).filter_by(email=email).first()
            au_user = AuthUser.query.filter_by(user_email=email).first()
            
            if tempu and tempu.check_password(password) and au_user and au_user.is_auth==True:
                g.user = tempu
                session['user_id'] = g.user.id  # Store user ID in the session
                if not remember_me:
                    session.permanent = False  # Make the session permanent
                return redirect('/dashboard')
            elif tempu and tempu.check_password(password) and au_user.is_auth==False:
                flash('check email inbox for validation')
                return render_template('login.html', form=form)
            elif not tempu or not tempu.check_password(password) or not au_user:
                flash('invalid email or password')
                return render_template('login.html', form=form)
        elif g.user:
            return render_template('login.html', user=g.user, form=form)
    if request.method == 'GET':
        if new=='o':
            fla = False
            if g.user:
                fla = True
            session.pop('user_id',None)
            g.user = None
            if fla:
                flash('logged out')
        return render_template('login.html', user=g.user, form=form)

@app.route('/dashboard')
def dashboard():
        n = request.args.get('new')
        return render_template('dashboard.html',user=g.user, newuser=n)
# Delete logged in user, on success redirect to register page
@app.route('/settings/<username>')
def settings(username):
        stderrmsg = 'sql server error'
        if not g.get('user', None):
            return redirect('/login/login')
        if g.user and g.user.name + "Delete" == username:
            try:
                user_to_delete = db.session.query(User).filter_by(id=g.user.id).first()
                aa_user = AuthUser.query.filter_by(user_id=g.user.id).first()
                if user_to_delete and aa_user:
                    if aa_user.is_auth == True:
                        aa_user.is_auth = False
                        db.session.delete(user_to_delete)
                        db.session.commit()
                        g.user = None
                        return redirect('/register')
                    else:
                        flash(stderrmsg)
                else:
                    flash(stderrmsg)
            except:
                flash(stderrmsg)
        return render_template('settings.html', user=g.user)
# use admin route to lookup auth email and remove from database.
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    lookupform = AdminForm()
    fempu = None
    fa_user = None
    if g.user is not None and 'admin_name' not in g.user:
        return redirect('/')
    if request.method == 'POST' and lookupform.validate_on_submit:
        lookupemail = lookupform.email.data
        try:
            fempu = db.session.query(User).filter_by(email=lookupemail).first()
            fa_user = AuthUser.query.filter_by(user_email=lookupemail).first()
            # if fempu:
            #     db.session.delete(fempu)
            # if fa_user:
            #     db.session.delete(fempu)
            # if fempu or fa_user:
            #     db.session.commit()
        except Exception as e:
            print(e)
    return render_template('admin.html', users=fempu, auth_users=fa_user, lookupform=lookupform)
# utility link to logout session user.
@app.route('/logout')
def logout():
    session.pop('user_id',None)
    g.user = None
    return redirect('/login/login')
# Custom error handler for 404 Not Found
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True)