from flask import Flask, request,render_template, redirect, session, g, flash
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import uuid
import datetime
from datetime import timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.secret_key = 'secret_key'
app.permanent_session_lifetime = timedelta(days=30)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self,email,password,name):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self,password):
        return bcrypt.checkpw(password.encode('utf-8'),self.password.encode('utf-8'))

with app.app_context():
    db.create_all()

@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        obj = load_user(session['user_id'])
        if obj:
            g.user = obj
        
@app.route('/')
def index():
    return render_template('index.html')

def load_user(id):
    return User.query.filter_by(id=id).first()

@app.route('/register',methods=['GET','POST'])
def register():
    if request.method == 'POST':
        if not g.user:
            # handle request
            name = request.form['name']
            email = request.form['email']
            password = request.form['password']

            new_user = User(name=name,email=email,password=password)
            db.session.add(new_user)
            db.session.commit()
        if g.user:
            pass
        return redirect('/login')

    return render_template('register.html')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        remember_me = 'remember_me' in request.form

        if not g.user:

            g.user = User.query.filter_by(email=email).first()
            
            if g.user and g.user.check_password(password):
                session['user_id'] = g.user.id  # Store user ID in the session
                if not remember_me:
                    session.permanent = False  # Make the session permanent
                return redirect('/dashboard')
            elif not g.user or not g.user.check_password(password):
                g.user = None
                return render_template('login.html',error='Invalid user')
        elif g.user:
            return render_template('login.html', user=g.user)
    if request.method == 'GET':
        return render_template('login.html', user=g.user)


@app.route('/dashboard')
def dashboard():
        return render_template('dashboard.html',user=g.user)
@app.route('/logout')
def logout():
    session.pop('user_id',None)
    g.user = None
    return redirect('/login')

def save_remember_me_token(id, token, expiration_date):
    try:
        # Create a new RememberMe object
        new_remember_me = RememberMe(id=id, token=token, expiration_date=expiration_date)
        
        # Add the new object to the database session
        db.session.add(new_remember_me)
        
        # Commit the session to save the changes to the database
        db.session.commit()
        
        return True  # Insertion was successful
    except Exception as e:
        print(f"Error inserting into remember_me: {str(e)}")
        db.session.rollback()
        return False  # Insertion failed

if __name__ == '__main__':
    app.run(debug=True)