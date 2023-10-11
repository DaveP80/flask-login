from flask import Flask, request,render_template, redirect, session, g, flash, request, url_for, send_file
from flask_sqlalchemy import SQLAlchemy
from helper import read_blocklist_file, isValid, clearDir, validFile
from functools import wraps
from forms.forms import *
import io
import os
import ssl
import smtplib
import bcrypt
import uuid
import datetime
from datetime import timedelta, datetime
from werkzeug.utils import secure_filename
# from sqlalchemy.sql import func
from smtplib import SMTPAuthenticationError
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
# PSQL
from sqlalchemy import create_engine, LargeBinary, Column, Integer, String, DateTime, UniqueConstraint
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

class Images(db.Model):
    __tablename__ = 'images'

    img_id = db.Column(db.Integer, primary_key=True)
    id = db.Column(db.Integer, nullable=False)
    img_path = db.Column(db.String(100), nullable=False)

    __table_args__ = (
        UniqueConstraint('id', 'img_path', name='unique_id_img_path'),
    )

    def __init__(self, id, img_path):
        self.id = id
        self.img_path = img_path

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

def query(filename, path, id):
    with open(filename, "rb") as f:
        err = False
        try:
            image_record = Images(id=id, img_path=path)
            db.session.add(image_record)
            db.session.commit()
        except Exception as error:
            print(error)
            err = True
        f.close()
    if err:
        return {'error': 'bad file path'}
    return {"image": [str(uuid.uuid4()), path]}


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
                base_url = app.config['URL']
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
    g.retrvd_images = []
    if 'user_id' in session:
        obj = load_user(session['user_id'])
        if obj[0]:
            g.retrvd_images = obj[0]
        g.user = obj[1]
        
def load_user(id):
    stor = []
    arra = db.session.query(Images).filter_by(id=id).all()
    arrb = db.session.query(User).filter_by(id=id).first()
    if arra and arrb:
        user_folder = os.path.join(app.config['IMG_FOLDER']+str(arrb.id))
        if os.path.exists(user_folder) and os.path.isdir(user_folder):
            pass
            # The folder exists, and it's a directory
            # List all file paths in the user's folder
        if not os.path.exists(user_folder):
            os.makedirs(user_folder)
        file_paths = []
        for root, dirs, files in os.walk(user_folder):
            for file in files:
                file_paths.append(os.path.join(root, file))
        # Extract file names from the full paths
        file_paths = [os.path.basename(file) for file in file_paths]
        if file_paths:
            for j,k in enumerate(arra):
                if k.img_path in file_paths:
                    stor.append({"id": id, "img_id": k.img_id, "img_path": k.img_path})
    return [stor, arrb]

@app.route('/')
def index():
    return render_template('index.html', home=True)
# Create new account
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
            email = regform.email.data.strip()
            password = regform.password.data
            token = None
            if not isValid(email):
                flash("invalid email pattern")
                return render_template('register.html', regform=regform)
            try:
                token = str(uuid.uuid4())
                new_user = User(name=name.strip(),email=email,password=password, token=token)
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
                em_user = AuthUser.query.filter_by(user_email=email).first()
                user_to_delete = db.session.query(User).filter_by(email=email).first()
                if user_to_delete and em_user:
                    db.session.delete(user_to_delete)
                    db.session.delete(em_user)
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
            session.pop('adminlogin', None)
            session.pop('user_id',None)
            g.user = None
            if fla:
                flash('logged out')
        return render_template('login.html', user=g.user, form=form)

@app.route('/dashboard', methods=['GET','POST'])
def dashboard():
        n = request.args.get('new')
        form = UploadForm()
        if request.method == 'POST' and form.validate_on_submit():
            file = form.file.data
            print(file.content_type)
            if file.content_type.startswith('image/'):
                tempkey = secure_filename(file.filename)
                user_folder = os.path.join(app.config['IMG_FOLDER']+str(g.user.id))
                if not os.path.exists(user_folder):
                    os.makedirs(user_folder)
                upload_path = os.path.join(user_folder, tempkey)
                file.save(upload_path)
                if validFile(g.retrvd_images, tempkey):
                    image_info = query(upload_path, tempkey, g.user.id)
                    if 'image' in image_info:
                        try:
                            g.retrvd_images.append({"img_id": image_info['image'][0], "id": g.user.id, "img_path": image_info['image'][1]})
                        except Exception as e:
                            print(e)
                            flash('SQL server error')
                    elif 'error' in image_info:
                        flash('Error: There was an issue with the API request.')
                else:
                    flash('Duplicate img file.')
            else:
                flash('Invalid file input')
        return render_template('dashboard.html',user=g.user, newuser=n, form=form, retrvd_images=g.retrvd_images)
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
# Define a custom decorator to check if the user is logged in as an admin
def admin_login_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        # Check if the user is logged in as an admin
        if not session.get('adminlogin'):
            return redirect('/admin/login')
        return func(*args, **kwargs)
    return decorated_view

@app.route('/admin/<route>', methods=['GET', 'POST'])
def admin(route):
    if route == 'login':
        lookupform = None
        inform = AdminLoginForm()
        if request.method == 'POST' and inform.validate_on_submit:
            if app.config['ADMIN'] == inform.password.data and app.config['USERNAME'] == inform.email.data:
                session['adminlogin'] = True
                session.permanent = False
                return redirect('/admin/lookup')
    elif route == 'lookup':
        # Use the custom decorator to protect the 'lookup' route
        @admin_login_required
        def lookup():
            lookupform = AdminForm()
            fempu = None
            fa_user = None
            tempstring = None
            admindelstr = None
            # remove all records of user and email from databases
            if request.args.get('del'):
                try:
                    q = request.args.get('del')
                    fi_user = AuthUser.query.filter_by(user_id=q).first()
                    if fi_user:
                        db.session.delete(fi_user)
                        db.session.commit()
                        fa_user = None
                        flash('user removed from all logs')
                except:
                    flash('database or query string error')
            # remove/deactivate user using the admin login
            if request.args.get('admin_del'):
                try:
                    z = request.args.get('admin_del')
                    user_to_delete = db.session.query(User).filter_by(id=z).first()
                    aa_user = AuthUser.query.filter_by(user_id=z).first()
                    if user_to_delete and aa_user:
                        if aa_user.is_auth == True:
                            aa_user.is_auth = False
                            db.session.delete(user_to_delete)
                            db.session.commit()
                            fempu = None
                            fa_user = aa_user
                            flash('user is deactivated')
                        else: flash('database or query string error')
                except:
                    flash('database or query string error')
            
            if request.method == 'POST' and lookupform and lookupform.validate_on_submit:
                lookupemail = lookupform.email.data
                try:
                    fempu = db.session.query(User).filter_by(email=lookupemail).first()
                    fa_user = AuthUser.query.filter_by(user_email=lookupemail).first()
                    if not fempu and fa_user:
                        tempstring = f'/admin/lookup?del={fa_user.user_id}'
                    if fempu and fa_user and fa_user.is_auth:
                        admindelstr = f'/admin/lookup?admin_del={fempu.id}'
                except Exception as e:
                    print(e)
            return render_template('admin.html', users=fempu, auth_users=fa_user, lookupform=lookupform, tempstring=tempstring, admindelstr=admindelstr)
        
        return lookup()
    return render_template('admin.html', lookupform=lookupform, inform=inform)
# user uploaded images
@app.route('/images/<imgpath>')
def uploaded_file(imgpath):
    file_extension = 'jpg'
    parts = imgpath.split('.')
    if len(parts) > 1:
        file_extension = parts[-1]
    file_path = os.path.join(app.config['IMG_FOLDER']+str(g.user.id), imgpath)
    if os.path.exists(file_path):
        # Send the file
        return send_file(file_path, mimetype='image/jpeg', download_name=f'yourimage.{file_extension}')
    else:
        # Handle the case where the file does not exist
        return "File not found", 404  # You can customize the error response as needed
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