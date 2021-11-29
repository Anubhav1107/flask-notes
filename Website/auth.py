from codecs import CodecInfo
import re
from flask import Blueprint, request, flash, redirect,url_for
from flask.templating import render_template
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash

from flask_login import login_required,login_user,logout_user,current_user

auth = Blueprint("auth",__name__)

@auth.route('/login', methods = ['GET','POST'])
def login():

    if request.method =='POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("Logged in Successfully",category='success')
                login_user(user,remember=True)
                return redirect(url_for('views.home'))

            else:
                flash("Wrong Password",category='error')
        else:
            flash('User doesn\'t exist',category='error')

    return render_template("login.html",user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods =['GET', 'POST'])
def sign_up():
    if request.method =='POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()

        if user:
            flash("Email already exist",category='error')
        elif len(email) < 4:
            flash("Email must be greater than 3 characters",category='error')

        elif len(firstName) <2:
            flash("First Name should be greater than 1 characters",category='error')

        elif password1 != password2:
            flash('Passwords does\'t Match',category='error')
            
        elif len(password1) <7 :
            flash(" Password should be greater than 6 chars ",category='error')
            
        else:
            new_user = User(email = email,first_name=firstName,password = generate_password_hash(password1,
            method='sha256'))
            #add user to the database
            db.session.add(new_user)
            db.session.commit()
            flash("Account Created Succesfuly",category='success')
            login_user(user,remember=True)
            return redirect(url_for('views.home'))

    return render_template("sign-up.html",user = current_user)
