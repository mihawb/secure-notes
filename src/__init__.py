from flask import Flask, render_template, request, make_response, redirect, send_file
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_cors import CORS
from re import search
import markdown
from passlib.hash import argon2
import sqlite3
import os, requests


template_dir = os.path.abspath('../templates')
app = Flask(__name__, template_folder=template_dir)
CORS(app) # probably better to set up route specific cors https://flask-cors.readthedocs.io/en/latest/#resource-specific-cors
login_manager = LoginManager()
login_manager.init_app(app)
app.secret_key = os.getenv('APP_SECRET_KEY')
DATABASE = './sqlite3.db'

class User(UserMixin):
  pass

@login_manager.user_loader
def user_loader(username):
  if username is None:
    return None

  con = sqlite3.connect(DATABASE)
  sql = con.cursor()
  get_user_query = 'SELECT username, password FROM USERS WHERE username = ?'
  sql.execute(get_user_query, (username,))
  row = sql.fetchone()
  try:
    username, password = row
  except:
    return None

  user = User()
  user.id = username
  user.password = password
  return user


@login_manager.request_loader
def request_loader(request):
  username = request.form.get('username')
  user = user_loader(username)
  return user


@app.route('/', methods=['GET', 'POST'])
def login():
  if request.method == 'GET':
    return render_template('login.html')
  if request.method == "POST":
    username = request.form.get("username")
    password = request.form.get("password")
    user = user_loader(username)
    if user is None:
      return "Nieprawidłowy login lub hasło", 401
    if argon2.verify(password, user.password):
      login_user(user)
      return redirect('/dashboard')
    else:
      return "Nieprawidłowy login lub hasło", 401

@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")

@app.route('/user/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    if request.method == 'POST':
        con = sqlite3.connect(DATABASE)
        sql = con.cursor()

        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')

        em_check_valid = bool(search(r'', email))
        pw_check_valid = bool(search(r'', password))
        un_check_valid = bool(search(r'', username))
        sql.execute('SELECT EXISTS(SELECT 1 FROM USERS WHERE username = ?);', (username,))
        un_check_taken = bool(sql.fetchone()[0])

        if not (em_check_valid and pw_check_valid and un_check_taken and un_check_valid):
          return redirect('/badform')

        s = username.ljust(8, 'a').encode()
        arg2 = argon2.using(salt=s, type='ID', memory_cost=65536, time_cost=3, parallelism=4)
        password_argon2 = arg2.hash(password)

        register_user_query = 'INSERT INTO USERS (username, email, password) VALUES (?, ?, ?);'
        sql.execute(register_user_query, (username, email, password_argon2))

        con.commit()        
        return redirect('/')

@app.route('/badform')
def badform():
  return render_template('badform.html')

@app.route('/user/check', methods=['GET'])
def check_if_user_exists():
  if request.method == 'GET':
    username = request.args.get('name')
    con = sqlite3.connect(DATABASE)
    sql = con.cursor()
    check_user_query = 'SELECT EXISTS(SELECT 1 FROM USERS WHERE username = ?);'
    sql.execute(check_user_query, (username,))
    result = sql.fetchone()[0]
    con.commit()

    if result: return 'T'
    else: return 'F'

@app.route("/dashboard", methods=['GET'])
@login_required
def dashboard ():
  if request.method == 'GET':
    username = current_user.id
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    notes_query = 'SELECT id, title FROM notes WHERE username == ?'
    sql.execute(notes_query, (username,))
    result = sql.fetchall()
    notes = [{'id': i, 'title': t} for (i, t) in result]

    return render_template("dashboard.html", username=username, notes=notes)

@app.route("/render", methods=['POST'])
@login_required
def render():
  md = request.form.get("markdown","")
  rendered = markdown.markdown(md)
  username = current_user.id
  db = sqlite3.connect(DATABASE)
  sql = db.cursor()
  sql.execute(f"INSERT INTO notes (username, note) VALUES ('{username}', '{rendered}')")
  db.commit()
  return render_template("markdown.html", rendered=rendered)

@app.route("/render/<rendered_id>")
@login_required
def render_old(rendered_id):
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    get_note_query = 'SELECT username, title, note FROM notes WHERE id == ?'
    sql.execute(get_note_query, (rendered_id,))

    try:
        username, title, rendered_note  = sql.fetchone()
        if username != current_user.id:
            return "Access to note forbidden", 403
        return render_template("render.html", title=title, rendered_note=rendered_note)
    except:
        return "Note not found", 404


if __name__ == '__main__':
  con = sqlite3.connect(DATABASE)
  sql = con.cursor()
  sql.execute('CREATE TABLE IF NOT EXISTS USERS (username VARCHAR(32), email VARCHAR(96), password VARCHAR(128));')
  sql.execute('CREATE TABLE IF NOT EXISTS NOTES (id INTEGER PRIMARY KEY, username VARCHAR(32), title VARCHAR(32), note VARCHAR(1024));')
  con.commit()

  app.run('0.0.0.0', 5000)