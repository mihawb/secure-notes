from flask import Flask, render_template, request, redirect, send_file, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_cors import CORS
from passlib.hash import argon2, md5_crypt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sqlite3, markdown, bleach, requests
import os, mimetypes, glob, time
from threading import Event
from re import search


template_dir = os.path.abspath('./templates')
app = Flask(__name__, template_folder=template_dir)
CORS(app)
login_manager = LoginManager()
login_manager.init_app(app)
app.secret_key = os.getenv('APP_SECRET_KEY')
DATABASE = os.path.abspath('./sqlite3.db')
BANNERS = os.path.abspath('./banners')


# Event.wait() method is non-blocking, as opposed to time.sleep()
# timeout is applied only to bad requests, good folks don't have to wait
def bad_request_timeout():
  dummy_event = Event()
  dummy_event.wait(timeout=2)


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
    print(app.secret_key)
    return render_template('login.html')

  if request.method == "POST":
    username = request.form.get('username')
    password = request.form.get('password')

    if not search(r'^[a-zA-Z0-9]+$', username):
      bad_request_timeout()
      return 'Incorrect login or password', 401

    user = user_loader(username)
    if user is None:
      bad_request_timeout()
      return 'Incorrect login or password', 401

    if argon2.verify(password, user.password):
      login_user(user)
      return redirect('/dashboard')

    else:
      bad_request_timeout()
      return 'Incorrect login or password', 401


@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")


@app.route('/register', methods=['GET', 'POST'])
def register():
  if request.method == 'GET':
    return render_template('register.html')

  if request.method == 'POST':
    con = sqlite3.connect(DATABASE)
    sql = con.cursor()

    email = request.form.get('email')
    username = request.form.get('username')
    password = request.form.get('password')

    em_check_valid = bool(search(r'^.+@[a-zA-Z0-9\-]+(\.[a-zA-Z]+)+$', email))
    pw_check_valid = bool(search(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password))
    un_check_valid = bool(search(r'^[a-zA-Z0-9]+$', username))
    if un_check_valid:
      sql.execute('SELECT EXISTS(SELECT 1 FROM USERS WHERE username = ?);', (username,))
      un_check_taken = not bool(sql.fetchone()[0])

    if not (em_check_valid and pw_check_valid and un_check_valid and un_check_taken):
      bad_request_timeout()
      return 'Incorrect form data. Sumbit again, complying to restrictions.', 406

    s = get_random_bytes(16)
    arg2 = argon2.using(salt=s, type='ID', memory_cost=65536, time_cost=3, parallelism=4)
    password_argon2 = arg2.hash(password)

    register_user_query = 'INSERT INTO USERS (username, email, password) VALUES (?, ?, ?);'
    sql.execute(register_user_query, (username, email, password_argon2))
    con.commit()
      
    con.close()        
    return redirect('/')


@app.route('/check/<field>', methods=['GET']) 
def check_if_field_exists(field):
  if request.method == 'GET':
    name = request.args.get('name')
    con = sqlite3.connect(DATABASE)
    sql = con.cursor()

    # conditional in order to avoid querying
    # SELECT ... FROM USERS WHERE ? = ?
    # which would be amusingly easy to exploit
    if field == 'user':
      check_user_query = 'SELECT EXISTS(SELECT 1 FROM USERS WHERE username = ?);'
      sql.execute(check_user_query, (name,))
      result = sql.fetchone()[0]

    elif field == 'email':
      check_email_query = 'SELECT EXISTS(SELECT 1 FROM USERS WHERE email = ?);'
      sql.execute(check_email_query, (name,))
      result = sql.fetchone()[0]

    else:
      bad_request_timeout()
      return 'Bad request', 400

    con.close()
    if result: return 'T'
    else: 
      bad_request_timeout()
      return 'F'


@app.route('/requestreset', methods=['GET', 'POST'])
def requestreset():
  if request.method == 'GET':
    return render_template('requestreset.html')

  if request.method == 'POST':
    reqinput = request.form.get('reqinput')

    con = sqlite3.connect(DATABASE)
    sql = con.cursor()
    check_user_email_query = 'SELECT username, email FROM USERS WHERE username == ? OR email == ?;'
    sql.execute(check_user_email_query, (reqinput, reqinput))
    try:
      username, email = sql.fetchone()
    except:
      username = None
      email = None

    if not username:
      return render_template('email.html')

    validuntil = int(time.time()) + 3600
    checksum = md5_crypt.hash(get_random_bytes(16)).split('$')[-1]

    save_reset_req_query = 'INSERT INTO RESET (username, validuntil, checksum) VALUES (?, ?, ?);'
    sql.execute(save_reset_req_query, (username, validuntil, checksum))
    con.commit()
    con.close()

    link = url_for('resetpassword', username=username, checksum=checksum, _external=True)
    return render_template('email.html', link=link, email=email)


@app.route('/resetpassword', methods=['GET', 'POST'])
def resetpassword():
  if request.method == 'GET':
    username = request.args.get('username')
    checksum = request.args.get('checksum')

    con = sqlite3.connect(DATABASE)
    sql = con.cursor()
    check_if_req_valid_query = 'SELECT validuntil FROM RESET WHERE username == ? AND checksum == ?;'
    sql.execute(check_if_req_valid_query, (username, checksum))
    validuntil = sql.fetchone()

    if not (validuntil and validuntil[0] > int(time.time())):
      bad_request_timeout()
      return 'Invalid reset link', 403

    con.close()
    return render_template('resetpassword.html', username=username, checksum=checksum)

  if request.method == 'POST':
    username = request.args.get('username')
    checksum = request.args.get('checksum')
    password = request.form.get('password')
    
    con = sqlite3.connect(DATABASE)
    sql = con.cursor()
    check_if_req_valid_query = 'SELECT validuntil FROM RESET WHERE username == ? AND checksum == ?;'
    sql.execute(check_if_req_valid_query, (username, checksum))
    validuntil = sql.fetchone()

    if not (validuntil and validuntil[0] > int(time.time())):
      bad_request_timeout()
      return 'Invalid reset link', 403

    pw_check_valid = bool(search(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password))
    if not pw_check_valid:
      bad_request_timeout()
      return 'Incorrect form data. Sumbit again, complying to restrictions.', 406

    s = username.ljust(8, 'a').encode()
    arg2 = argon2.using(salt=s, type='ID', memory_cost=65536, time_cost=3, parallelism=4)
    password_argon2 = arg2.hash(password)

    reset_password_query = 'UPDATE USERS SET password = ? WHERE username == ?;'
    sql.execute(reset_password_query, (password_argon2, username))
    con.commit()

    remove_request_query = 'DELETE FROM RESET WHERE username == ? AND checksum == ?;'
    sql.execute(remove_request_query, (username, checksum))
    con.commit()

    con.close()
    return redirect('/')


@app.route("/dashboard", methods=['GET'])
@login_required
def dashboard():
  if request.method == 'GET':
    username = current_user.id
    con = sqlite3.connect(DATABASE)
    sql = con.cursor()
    notes_query = 'SELECT id, title FROM notes WHERE username == ?'
    sql.execute(notes_query, (username,))
    result = sql.fetchall()
    notes = [{'id': i, 'title': t} for (i, t) in result]

    con.close()
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
    source_title = request.form.get('title')
    title = bleach.clean(source_title)
    source_md = request.form.get('markdown', '')
    bleached_md = bleach.clean(source_md)
    rendered = markdown.markdown(bleached_md)
    result_note = rendered # in case of lack of encryption later on
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

    if banner_url:
      try:
        res = requests.get(banner_url)
        content_type = res.headers['content-type']
        if 'image' not in content_type: 
          raise ValueError('Supplied file is not an image')
        ext = mimetypes.guess_extension(content_type)
        with open(f"{BANNERS}/banner_{username}_{scope_identity}{ext}", "wb") as f:
          f.write(res.content)
      except Exception as e:
        print('Could not save banner image:', e)

    con.close()
    # safe formating, no third-party input
    return redirect(f'/render/{username_prim}/{scope_identity}')


@app.route('/render/<user>/<rendered_id>', methods=['GET'])
@login_required
def render(user, rendered_id):
  con = sqlite3.connect(DATABASE)
  sql = con.cursor()
  # note ids are global, not per user, so we want to check whether given user authored note with given id
  get_note_query = 'SELECT id, username, public, encrypted, title, note FROM notes WHERE id == ? AND username == ?'
  sql.execute(get_note_query, (rendered_id, user))

  try:
    id_note, username, public, encrypted, title, rendered_note = sql.fetchone()
    con.close()

    if not public and username != current_user.id:
      bad_request_timeout()
      return 'Access to note forbidden', 403

    return render_template('render.html', rendered_id=id_note, author=username, public=bool(public), encrypted=bool(encrypted), title=title, rendered_note=rendered_note)
  except:
    con.close()
    bad_request_timeout()
    return 'Note not found', 404


@app.route('/decrypt/<user>/<rendered_id>', methods=['POST'])
@login_required
def decrypt(user, rendered_id):
  passphrase = request.form.get('passphrase')

  con = sqlite3.connect(DATABASE)
  sql = con.cursor()
  # note ids are global, not per user, so we want to check whether given user authored note with given id
  get_note_query = 'SELECT id, username, public, encrypted, passphrase, title, note FROM notes WHERE id == ? AND username == ?'
  sql.execute(get_note_query, (rendered_id, user))

  try:
    id_note, username, public, encrypted, passphrase_hash, title, encrypted_note = sql.fetchone()
    con.close()

    if not encrypted:
      return redirect(f'/render/{user}/{rendered_id}')

    if not public and username != current_user.id:
      bad_request_timeout()
      return 'Access to note forbidden', 403

    if not argon2.verify(passphrase, passphrase_hash):
      bad_request_timeout()
      return 'Access to note forbidden', 403

    block_length = 16 
    passphrase_bytes = passphrase.encode().ljust(block_length, b'a')[:block_length]
    aes = AES.new(passphrase_bytes, AES.MODE_CBC, passphrase_bytes)
    decrypted_note = aes.decrypt(encrypted_note).decode()

    return render_template('render.html', rendered_id=id_note, author=username, public=bool(public), encrypted=not bool(encrypted), title=title, rendered_note=decrypted_note)
  except:
    con.close()
    bad_request_timeout()
    return 'Note not found', 404


@app.route('/banner/<user>/<note_id>')
@login_required
def banner(user, note_id):
  check_if_public_note_query = 'SELECT public FROM NOTES WHERE id = ?;'
  sql.execute(check_if_public_note_query, (note_id,))
  public = sql.fetchone()

  # note exists and is private and wrong user (existence check to allow default banner)
  if public and not public[0] and user != current_user.id:
    bad_request_timeout()
    return 'Access to banner forbidden', 403

  banners = glob.glob(f'{BANNERS}/banner_{user}_{note_id}.*')
  try:
    return send_file(banners[0])
  except:
    return send_file(f'{BANNERS}/banner_default.png')


if __name__ == '__main__':
  print('DATABASE INITIALISATION STARTED...')
  con = sqlite3.connect(DATABASE)
  sql = con.cursor()
  sql.execute('CREATE TABLE IF NOT EXISTS USERS (username VARCHAR(32), email VARCHAR(96), password VARCHAR(128));')
  sql.execute('CREATE TABLE IF NOT EXISTS NOTES (id INTEGER PRIMARY KEY, username VARCHAR(32), public BOOLEAN, encrypted BOOLEAN, passphrase VARCHAR(128), title VARCHAR(32), note BLOB);')
  sql.execute('CREATE TABLE IF NOT EXISTS RESET (username VARCHAR(32), validuntil DATETIME, checksum VARCHAR(128));')
  con.commit()
  con.close()
  print('DATABASE INITIALISATION FINISHED')