
#import 
import email
from encodings import utf_8
from sre_constants import SUCCESS
from tkinter import Label
from wsgiref.validate import validator
from xml.dom import ValidationErr
from flask import Flask , request , render_template , redirect,url_for, flash
import flask 
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy import true
from wtforms import StringField,PasswordField,SubmitField,IntegerField,SelectField
from wtforms_sqlalchemy.fields import QuerySelectField
from wtforms.validators import Length , EqualTo , Email ,DataRequired ,ValidationError ,NumberRange
from flask_login import LoginManager ,login_user ,UserMixin ,logout_user ,login_required
from flask_bcrypt import Bcrypt
import numpy as np
import pickle
import pandas as pd
from sklearn.utils.validation import check_array
#intit flask app
app=Flask(__name__)
#load model
model = pickle.load(open('model.pkl', 'rb'))
app.config['SECRET_KEY']='HI'
#log in manager
login_manager=LoginManager(app)
login_manager.login_view="login" #our log in route 
login_manager.login_message_category="info"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
#Register form
class RegisterForm(FlaskForm):

    def validate_username(self, username_to_check):
        user=User.query.filter_by(username=username_to_check.data).first()
        if user:
            raise ValidationError('username already exist! Please try a diffrent username')
    def validate_email(self, email_to_check):
       email=User.query.filter_by(email=email_to_check.data).first()
       if email:
           raise ValidationError('email already exists! Please try different email address')

    username=StringField(label='User name:',validators=[Length(min=2,max=30), DataRequired()])
    email=StringField(label='Email:',validators=[Email(),DataRequired()])
    password1=PasswordField(label='Password:',validators=[Length(min=1),DataRequired()])
    password2=PasswordField(label='Confirm password:',validators=[EqualTo('password1'),DataRequired()])
    submit=SubmitField(label='Create Account')
#login form
class LoginForm(FlaskForm):
    username=StringField(label='User name',validators=[DataRequired()])
    password=PasswordField(label='password',validators=[DataRequired()])
    submit=SubmitField(label='Login')





#db load
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
#comnt
db = SQLAlchemy(app)
bcrypt=Bcrypt(app)

class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(length=50), unique=True, nullable=False)
    email = db.Column(db.String(length=100), unique=True ,nullable=False)
    password_hash= db.Column(db.String(length=50),nullable=False)

    @property
    def password(self):
      return self.password

    @password.setter
    def password(self, plain_text_password):
        self.password_hash = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')
    
    def check_password_correction(self, attempted_password):
        return bcrypt.check_password_hash(self.password_hash, attempted_password)


class City(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    city=db.Column(db.String(length=100), unique=True, nullable=False)
    
    def __repr__(self):
        return repr(self.id)



class reportForm(FlaskForm):
    city=QuerySelectField(query_factory=lambda: City.query,get_label='city',allow_blank=False)
    AQI=IntegerField(label='AQI',validators=[NumberRange(min=0, max=500),DataRequired()])
    submit=SubmitField(label='Predict')
#Route
@app.route('/')
def WelcomePage():
    return render_template("welcome.html")

@app.route('/about')
def About():
    return render_template("about.html")
    
@app.route('/login' , methods=['GET','POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        attempted_user = User.query.filter_by(username=form.username.data).first()
        if attempted_user and attempted_user.check_password_correction(
                attempted_password=form.password.data
        ):
            login_user(attempted_user)
            flash(f'Success! You are logged in as: {attempted_user.username}', category='success')
            return redirect(url_for('report'))
        else:
            flash('Username and password are not match! Please try again', category='danger')
        
    return render_template("login.html",form=form)

@app.route('/report',methods=['POST','GET'])
@login_required
def report():
  form=reportForm()
  if form.validate_on_submit:
       aqi=form.AQI.data
       city=form.city.data
       if city:
        city=city.city
        city_id=City.query.filter_by(city=city).first()
        if city_id:
            city_id=city_id.id
        else:
            city_id=''
        return redirect(url_for('result', city_id=city_id,aqi=aqi))
       else:
           flash('No city selected ',category='danger')
    
  return render_template("report.html",form=form)

@app.route('/result',methods=['POST','GET'])
def result():
    City=int(request.args.get('city_id'))
    AQI=int(request.args.get('aqi'))
    input_data=[[City,AQI]]
    prediction = model.predict(input_data)
    return render_template('result.html',prediction=prediction)



@app.route('/signin',methods=['GET','POST'])
def signin():
    form=RegisterForm()
    if form.validate_on_submit():
        user_to_create=User(username=form.username.data
                            ,email=form.email.data,
                            password=form.password1.data)
        db.session.add(user_to_create)
        db.session.commit()
        login_user(user_to_create)
        flash(f"Account created successfully! You are now logged in as{user_to_create.username} ",category='success')
        return redirect(url_for('report')) #redirect the user after create account to report page
    #CHECK FORM ERROR
    if form.errors!={}:#if its not empty then theres error
        for err_msg in form.errors.values():
            flash(f'There was an error in creating account {err_msg}', category='danger')

    return render_template("signin.html",form=form)

@app.route('/logout')
def Logout():
    logout_user()
    flash("You have been logged out!",category='info')
    return redirect(url_for("WelcomePage"))


if __name__ == '__main__':
 app.run(debug=True)