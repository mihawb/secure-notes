from flask import Flask, render_template, request, make_response, redirect, send_file
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_cors import CORS
from re import search
import markdown
from passlib.hash import argon2
from Crypto.Cipher import AES
import sqlite3
import os, requests, mimetypes, glob


template_dir = os.path.abspath('../templates')
static_dir = os.path.abspath('../static')
app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
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
    username = request.form.get('username')
    password = request.form.get('password')
    user = user_loader(username)
    if user is None:
      return 'Incorrect login or password', 401
    if argon2.verify(password, user.password):
      login_user(user)
      return redirect('/dashboard')
    else:
      return 'Incorrect login or password', 401


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

    print(email, username, password)

    em_check_valid = bool(search(r'^.+@[a-zA-Z0-9\-]+(\.[a-zA-Z]+)+$', email))
    pw_check_valid = bool(search(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password))
    un_check_valid = bool(search(r'^[a-zA-Z0-9]+$', username))
    sql.execute('SELECT EXISTS(SELECT 1 FROM USERS WHERE username = ?);', (username,))
    un_check_taken = not bool(sql.fetchone()[0])

    print(em_check_valid, pw_check_valid, un_check_taken, un_check_valid)

    if not (em_check_valid and pw_check_valid and un_check_taken and un_check_valid):
      return "Incorrect form data. Sumbit again, complying to restrictions.", 406

    s = username.ljust(8, 'a').encode()
    arg2 = argon2.using(salt=s, type='ID', memory_cost=65536, time_cost=3, parallelism=4)
    password_argon2 = arg2.hash(password)

    register_user_query = 'INSERT INTO USERS (username, email, password) VALUES (?, ?, ?);'
    sql.execute(register_user_query, (username, email, password_argon2))
      
    con.commit()        
    return redirect('/')


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


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
  if request.method == 'GET':
    return render_template('create.html')

  if request.method == 'POST':
    public = request.form.get('public')
    passphrase = request.form.get('passphrase')
    passphrase_argon2 = ''
    username = current_user.id
    title = request.form.get('title')
    source_md = request.form.get('markdown', '')
    rendered = markdown.markdown(source_md)
    result_note = rendered
    banner_url = request.form.get('banner')

    if passphrase:
      block_length = 16
      data = rendered.encode()
      data = data + b'\x00' * (block_length - len(data) % block_length) 
      passphrase_bytes = passphrase.encode().ljust(block_length, b'a')[:block_length]
      # passphrase is manipulated but in deterministic way, should not cause problems

      aes = AES.new(passphrase_bytes, AES.MODE_CBC, passphrase_bytes)
      result_note = aes.encrypt(data)

      arg2 = argon2.using(type='ID', memory_cost=65536, time_cost=3, parallelism=4)
      passphrase_argon2 = arg2.hash(passphrase)

    con = sqlite3.connect(DATABASE)
    sql = con.cursor()
    post_note_query = 'INSERT INTO NOTES (username, public, encrypted, passphrase, title, note) VALUES (?, ?, ?, ?, ?, ?);'
    sql.execute(post_note_query, (username, bool(public), bool(passphrase), passphrase_argon2, title, result_note))
    con.commit()

    # sql.last_row_id() is not thread-safe
    get_scope_identity_query = 'SELECT id, username FROM NOTES WHERE username == ? ORDER BY id DESC LIMIT 1;'
    sql.execute(get_scope_identity_query, (username,))
    scope_identity, username_prim = sql.fetchone()

    try:
      res = requests.get(banner_url)
      content_type = res.headers['content-type']
      ext = mimetypes.guess_extension(content_type)
      with open(f"../banners/banner_{username}_{scope_identity}{ext}", "wb") as f:
        f.write(res.content)
    except Exception as e:
      print('Could not save banner image:', e)

    # safe formating, no third-party input
    return redirect(f'/render/{username_prim}/{scope_identity}')


@app.route('/render/<user>/<rendered_id>', methods=['GET'])
@login_required
def render(user, rendered_id):
  db = sqlite3.connect(DATABASE)
  sql = db.cursor()
  # note ids are global, not per user, so we want to check whether given user authored note with given id
  get_note_query = 'SELECT id, username, public, encrypted, title, note FROM notes WHERE id == ? AND username == ?'
  sql.execute(get_note_query, (rendered_id, user))

  try:
    id_note, username, public, encrypted, title, rendered_note = sql.fetchone()

    if not public and username != current_user.id:
      return 'Access to note forbidden', 403

    return render_template('render.html', rendered_id=id_note, author=username, public=bool(public), encrypted=bool(encrypted), title=title, rendered_note=rendered_note)
  except:
    return 'Note not found', 404


@app.route('/decrypt/<user>/<rendered_id>', methods=['POST'])
@login_required
def decrypt(user, rendered_id):
  passphrase = request.form.get('passphrase')

  db = sqlite3.connect(DATABASE)
  sql = db.cursor()
  # note ids are global, not per user, so we want to check whether given user authored note with given id
  get_note_query = 'SELECT id, username, public, encrypted, passphrase, title, note FROM notes WHERE id == ? AND username == ?'
  sql.execute(get_note_query, (rendered_id, user))

  try:
    id_note, username, public, encrypted, passphrase_hash, title, encrypted_note = sql.fetchone()

    if not encrypted:
      return redirect(f'/render/{user}/{rendered_id}')

    if not public and username != current_user.id:
      return 'Access to note forbidden', 403

    if not argon2.verify(passphrase, passphrase_hash):
      return 'Access to note forbidden', 403

    block_length = 16 
    passphrase_bytes = passphrase.encode().ljust(block_length, b'a')[:block_length]
    aes = AES.new(passphrase_bytes, AES.MODE_CBC, passphrase_bytes)
    decrypted_note = aes.decrypt(encrypted_note).decode()

    return render_template('render.html', rendered_id=id_note, author=username, public=bool(public), encrypted=not bool(encrypted), title=title, rendered_note=decrypted_note)
  except:
    return 'Note not found', 404


@app.route('/banner/<user>/<note_id>')
@login_required
def banner(user, note_id):
  banners = glob.glob(f'../banners/banner_{user}_{note_id}.*')
  try:
    return send_file(banners[0])
  except:
    return send_file('../banners/banner_default.png')


if __name__ == '__main__':
  print('DATABASE INITIALISATION STARTED...')
  con = sqlite3.connect(DATABASE)
  sql = con.cursor()
  sql.execute('CREATE TABLE IF NOT EXISTS USERS (username VARCHAR(32), email VARCHAR(96), password VARCHAR(128));')
  sql.execute('CREATE TABLE IF NOT EXISTS NOTES (id INTEGER PRIMARY KEY, public BOOLEAN, encrypted BOOLEAN, passphrase VARCHAR(128), username VARCHAR(32), title VARCHAR(32), note BLOB);')
  con.commit()
  con.close()
  print('DATABASE INITIALISATION FINISHED')

  # app.run('0.0.0.0', 5000)