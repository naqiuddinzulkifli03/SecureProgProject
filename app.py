from flask import Flask, render_template, request, redirect, url_for, session, g
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
from Crypto.Cipher import AES
import base64
import sqlite3
import qrcode
import os
from time import time

app = Flask(__name__)
app.secret_key = "supersecretkey"

DATABASE = 'members.db'
#Track failed login attempts and lockout information
login_attempts = {}

#Configuration for timeout
MAX_ATTEMPTS = 3  #Maximum failed attempts before lockout
LOCKOUT_TIME = 120 #Lockout duration in second 

# Encryption key (must be 16, 24, or 32 bytes)
encryption_key = b'Sixteen byte key'


# Encryption and decryption functions
def encrypt_data(data):
    cipher = AES.new(encryption_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')


def decrypt_data(ciphertext):
    ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
    cipher = AES.new(encryption_key, AES.MODE_EAX)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8')


# In-memory user store
USERS = {
    "staff": {"password": generate_password_hash("staffpass"), "role": "staff", "otp_secret": pyotp.random_base32()},
    "member": {"password": generate_password_hash("memberpass"), "role": "member", "otp_secret": pyotp.random_base32()},
    "pakkarim": {"password": generate_password_hash("karim"), "role": "staff", "otp_secret": pyotp.random_base32()},
}


# Database connection
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

@app.before_request
def create_tables():
    db = get_db()
    db.execute ('''CREATE TABLE IF NOT EXISTS members (id INTEGER PRIMARY KEY, name TEXT NOT NULL, membership_status TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS classes (
                    id INTEGER PRIMARY KEY,
                    class_name TEXT NOT NULL,
                    class_time TEXT NOT NULL
                  )''')
    db.execute('''CREATE TABLE IF NOT EXISTS member_classes (
                    member_id INTEGER,
                    class_id INTEGER,
                    FOREIGN KEY (member_id) REFERENCES members (id),
                    FOREIGN KEY (class_id) REFERENCES classes (id)
                  )''')
    db.commit()


# Home Route (Login)
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        current_time = time()

        # Initialize user in login_attempts if not already present
        if username not in login_attempts:
            login_attempts[username] = {'attempts': 0, 'lockout_until': 0}

        user_data = login_attempts[username]

        # Check if account is locked
        if current_time < user_data['lockout_until']:
            remaining_time = int(user_data['lockout_until'] - current_time)
            return f"Account locked. Try again in {remaining_time} seconds.", 403

        # Validate username and password
        if username in USERS:
            user = USERS[username]
            if check_password_hash(user['password'], password):
                # Reset login attempts on successful login
                user_data['attempts'] = 0
                
                # Set session details
                session['user'] = username
                session['otp_secret'] = user['otp_secret']
                
                # Redirect to OTP verification
                return redirect(url_for('verify_otp'))

        # Failed login
        user_data['attempts'] += 1
        if user_data['attempts'] >= MAX_ATTEMPTS:
            # Lock the user out
            user_data['lockout_until'] = current_time + LOCKOUT_TIME
            user_data['attempts'] = 0  # Reset attempts for after lockout
            return "Too many failed attempts. Account locked for 2 minutes.", 403

        return "Invalid credentials. Try again.", 401

    return render_template('login.html')


# OTP Verification Route
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']
    otp_secret = session['otp_secret']
    print(f"User: {username}, OTP Secret: {otp_secret}")

    if request.method == 'POST':
        otp = request.form.get('otp')
        totp = pyotp.TOTP(otp_secret)
        expected_otp = totp.now()
        print(f"Entered OTP: {otp}, Expected OTP: {expected_otp}")

        # Add a larger validity window
        if totp.verify(otp, valid_window=3):  # Allows ±90 seconds
            session['authenticated'] = True
            return redirect(url_for('dashboard'))
        else:
            print("OTP verification failed.")
            return "Invalid OTP. Try again.", 401

    otp_uri = pyotp.TOTP(otp_secret).provisioning_uri(
        name=f"{username}@MyApp", issuer_name="MyApp"
    )
    print(f"Generated OTP URI: {otp_uri}")

    qr_code_path = f"static/qr_{username}.png"
    if not os.path.exists(qr_code_path):
        img = qrcode.make(otp_uri)
        img.save(qr_code_path)

    return render_template('verify_otp.html', qr_code=qr_code_path)



# Dashboard (for both staff and members)
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    username = session['user']
    return render_template('dashboard.html', username=username)


# Member Management Routes
@app.route('/add_member', methods=['GET', 'POST'])
def add_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        status = encrypt_data(request.form['status'])

        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))

    return render_template ('add_member.html')
#veiw specific member class
@app.route('/member/<int:member_id>/classes')
def member_classes(member_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Get member classes
    member = query_db("SELECT * FROM members WHERE id = ?", [member_id], one=True)
    classes = query_db("SELECT c.class_name, c.class_time FROM classes c "
                        "JOIN member_classes mc ON c.id = mc.class_id "
                        "WHERE mc.member_id = ?", [member_id])
    
    return render_template('member_classes.html', member=member, classes=classes)


#register class
@app.route('/register_class/<int:member_id>', methods=['GET', 'POST'])
def register_class(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))


    classes = query_db("SELECT * FROM classes")  # Get all available classes
    if request.method == 'POST':
        class_id = request.form['class_id']
        db = get_db()
        db.execute("INSERT INTO member_classes (member_id, class_id) VALUES (?, ?)", (member_id, class_id))
        db.commit()
        return redirect(url_for('member_classes', member_id=member_id))
    
    return render_template('register_class.html', member_id=member_id, classes=classes)


#view users
@app.route('/view_members')
def view_members():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    members = query_db("SELECT * FROM members")
    return render_template('view_members.html', members=members)


# New Route for Registering a Member
@app.route('/register_member', methods=['GET', 'POST'])
def register_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        password = request.form['password']

        #hash the password
        hashed_password = generate_password_hash(password)

        #Print the hashed password to the terminal
        print(f"New member registered : {name}")
        print(f"Original Password :{password}")
        print(f"Hashed Password : {hashed_password}")

        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))
        
    members = query_db("SELECT * FROM members")   
    return render_template('register_member.html', members = members)

@app.before_request
def print_hashed_passwords():
    for username, details in USERS.items():
        print (f"Username: {username}")
        print (f"Hashed Password: {details['password']}")

# Class Scheduling Routes
@app.route('/add_class', methods=['GET', 'POST'])
def add_class():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        class_name = request.form['class_name']
        class_time = request.form['class_time']
        db = get_db()
        db.execute("INSERT INTO classes (class_name, class_time) VALUES (?, ?)", (class_name, class_time))
        db.commit()
        return redirect(url_for('view_classes'))
    
    return render_template('add_class.html')


@app.route('/view_classes')
def view_classes():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    classes = query_db("SELECT * FROM classes")
    return render_template('view_classes.html', classes=classes)


#deleting member
@app.route('/delete_member/<int:member_id>', methods=['POST'])
def delete_member(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    db = get_db()
    
    # Delete member from the database
    db.execute("DELETE FROM members WHERE id = ?", [member_id])
    
    # Also delete any classes associated with the member in the member_classes table
    db.execute("DELETE FROM member_classes WHERE member_id = ?", [member_id])
    
    db.commit()
    
    return redirect(url_for('view_members'))


# Logout Route
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)

