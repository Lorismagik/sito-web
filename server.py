from flask import Flask, render_template, request, url_for, redirect, jsonify, session, Response
import flask_login
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import psycopg2																	
from psycopg2 import Error
import os
from werkzeug.security import generate_password_hash, check_password_hash
import random
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from datetime import datetime, date
from functools import wraps																
import secrets

app = Flask(__name__)
app.secret_key = "dhasjkdhjkasdjkasdh"

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    try:
        cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        result = cursor.fetchone()

        logo = result[4]
        username = result[2]
        email = result[1]
	
        user = User(user_id)
        user.username = username
        user.email = email
        user.logo = logo

        print(user)
        return user
	
    except Error as e:
	    return "Errore"

# DATABASE
conn = psycopg2.connect(host = "192.168.1.14", database = "casaos", user = 'casaos', password = 'casaos') # CONFIGURARE CON APPOSITO SERVER PSQL DA CONFIGURARE
cursor = conn.cursor()

#fnuzioni a caso di lrsmgk
def getLogo(username):
        letter = username[0]
        letter = letter.upper()
        print(letter)
        logoDir = "/DATA/AppData/Sito-ServerWeb/static/images/accounts/letters"
        dirProvv = '/static/images/accounts/letters'
				
        logos = os.listdir(logoDir)

        logo = [file for file in logos if file.startswith(letter)]
        print(logo)
        fileName = logo[0]
        logoPath = f"{dirProvv}/{fileName}"
		
        return logoPath

@app.route('/test')
def test():
    cursor.execute("SELECT * FROM users")
    result = cursor.fetchone()
    
    data = {
        "id": result[0],
        "email": result[1],
        "username": result[2],
        "password": result[3],
        "logo": result[4]
    }

    print(data)


    return "vaffanculo"

@app.route('/')
def helloworld():
    if current_user.is_authenticated:
        return render_template('index.html', username=current_user.username)
    else:
        return redirect(url_for('register'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form['name']
        password = request.form['password']

        try:
            cursor.execute('SELECT * FROM users WHERE username = %s OR email = %s', (format(username), format(username)))
            result = cursor.fetchone()

        except Error as e:
            print(e)
            return "rotto."
        
        if result:
            user_id = result[0]
            storedEmail = result[1]
            storedUsername = result[2]
            storedPassword = result[3]

            if check_password_hash(storedPassword, password):
                user = User(id=user_id)
                user.username = storedUsername
                user.email = storedEmail
                login_user(user, remember=True)

                return jsonify({"result": "success"})
                
            else:
                return jsonify({"result": "error", "error_text": "Password errata."})
            
        else:
            return jsonify({"result": "error", "popup_text": "Utente inesistente o username errato."})
        

    else:
        return render_template('login.html')
    

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        username = request.form['name']
        email = request.form['email']
        password = request.form['password']
        passwordConfirm = request.form['passwordConfirm']
 
        user_id = ''.join([str(random.randint(0, 9)) for _ in range(9)])
        logo = getLogo(username)
        print(logo)

        if password == passwordConfirm:
            hashed_password = generate_password_hash(password, method='sha256')

            try:
                cursor.execute('INSERT INTO users (id, email, username, password, logo)' 'VALUES (%s, %s, %s, %s, %s)', (int(user_id), format(email), format(username), format(hashed_password), format(logo)))
                conn.commit()
                print("ho eseguito la query nel db")

            except Error as e:
                print(e)
                return "è andato in mona tutto."
        
        else:
            return jsonify({"result": "error", "error_text": "Le due password non corrispondono."})

        print("HA FUNZIATO TUTTO")
        user = User(id=user_id)
        user.username = username
        user.email = email
        user.logo = logo
        login_user(user, remember=True)
        return jsonify({"result": "success"})

    else: 
        return render_template('register.html')

@app.route('/logout', methods=['GET'])
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/account')
def account():
    return render_template('account-info.html')

@app.route('/account/security')
def accountsecurity():
    return render_template('account-security.html')

@app.route('/account/danger-zone')
def accountdangerzone():
    return render_template('account-danger.html')

@app.route('/account/changeUsername', methods=['POST'])
def changeUsername():
    newUsername = request.form['newUsername']
    print(newUsername)
    current_password = request.form['currentPassword']

    id = current_user.id

    print(id)

    try:
        cursor.execute('SELECT * FROM users WHERE id = %s', (int(id),))
        result = cursor.fetchone()
    except Error as e:
        print(e)
        return jsonify({"result": "error"})

    storedPassword = result[3]

    if check_password_hash(storedPassword, current_password):
        try:
            cursor.execute('UPDATE users SET username = %s WHERE id = %s', (format(newUsername), int(id)))
            conn.commit()

            return jsonify({"result": "success"})
        except Error as e:
            print(e)
            return jsonify({"result": "error"})
    else:
        return jsonify({"result": "error", "error_text": "Password errata."})

    #return jsonify({'message': 'Username aggiornato con successo', 'new_username': new_username}), 200

@app.route('/account/changeEmail', methods=['POST'])
def changeEmail():
    newEmail = request.form['newEmail']
    print(newEmail)
    current_password = request.form['currentPassword']

    id = current_user.id

    print(id)

    try:
        cursor.execute('SELECT * FROM users WHERE id = %s', (int(id),))
        result = cursor.fetchone()
    except Error as e:
        print(e)
        return jsonify({"result": "error"})

    storedPassword = result[3]

    if check_password_hash(storedPassword, current_password):
        try:
            cursor.execute('UPDATE users SET email = %s WHERE id = %s', (format(newEmail), int(id)))
            conn.commit()

            return jsonify({"result": "success"})
        except Error as e:
            print(e)
            return jsonify({"result": "error"})
    else:
        return jsonify({"result": "error", "error_text": "Password errata."})
    
@app.route('/account/changePassword', methods=['POST'])
def changePassword():
    newPassword = request.form['newPassword']
    print(newPassword)
    current_password = request.form['currentPassword']
    passwordConfirm = request.form['passwordConfirm']

    id = current_user.id

    print(id)

    try:
        cursor.execute('SELECT * FROM users WHERE id = %s', (int(id),))
        result = cursor.fetchone()
    except Error as e:
        print(e)
        return jsonify({"result": "error"})

    storedPassword = result[3]

    if  check_password_hash(storedPassword, current_password):
        passwordConfirm == newPassword,
        hashed_password = generate_password_hash(newPassword, method='scrypt')
        try:
            cursor.execute('UPDATE users SET password = %s WHERE id = %s', (format(hashed_password), int(id)))
            conn.commit()

            return jsonify({"result": "success"})
        except Error as e:
            print(e)
            return jsonify({"result": "error"})
    else:
        return jsonify({"result": "error", "error_text": "Password errata."})

@app.route('/rgb')
def rgb():
    return render_template('rgb.html')

@app.route('/termini_di_servizio')
def termini_di_servizio():
    return render_template('tds.html')

@app.route('/chi_siamo')
def chi_siamo():
    return render_template('NOI.html')

@app.route('/solar')
def solar():
    return render_template('solar.html')

@app.route('/account/accountDelete', methods=['POST'])
def accountDelete():
    id = current_user.id

    try:
        logout_user()
        cursor.execute('DELETE FROM users WHERE id = %s', (int(id),))
        conn.commit()

        result = "success"

        return jsonify({"result": result})

    except Error as e:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8054, debug=True)
