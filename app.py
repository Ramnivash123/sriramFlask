from flask import Flask, request, render_template, redirect, flash, make_response
import firebase_admin
from firebase_admin import credentials, storage, auth
import os
from werkzeug.utils import secure_filename
import sqlite3
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import datetime
from datetime import timedelta


app = Flask(__name__)
app.secret_key = 'secret'  # for flashing messages
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Replace with a secure key
app.config['JWT_TOKEN_LOCATION'] = ['cookies']     # <- tells JWT to look in cookies
app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token'
app.config['JWT_COOKIE_SECURE'] = False  # True if using HTTPS
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Disable for now; enable in production

jwt = JWTManager(app)


# Initialize Firebase
cred = credentials.Certificate("sriram-e212b-firebase-adminsdk-fbsvc-6eff8ab331.json")
firebase_admin.initialize_app(cred, {
    'storageBucket': 'sriram-e212b.firebasestorage.app'  # your Firebase storage bucket
})

bucket = storage.bucket()

conn = sqlite3.connect('users.db')
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
''')

@app.route('/', methods=['GET', 'POST'])
def index():
    
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (name, password) VALUES (?, ?)", (name, password))
        conn.commit()
        conn.close()

        return redirect('/signin')  # Redirect to a success page after signup

    return render_template('signup.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']

        # Check user from DB
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE name = ? AND password = ?", (name, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            # Create JWT token
            access_token = create_access_token(identity=name, expires_delta=datetime.timedelta(hours=1))

            # Create response based on user role
            if name == "Sriram":
                response = make_response(redirect('/admin'))
            else:
                response = make_response(redirect('/dashboard'))

            response.set_cookie('access_token', access_token)
            return response
        else:
            return render_template('signin.html', message='Invalid credentials')

    return render_template('signin.html')

@app.route('/dashboard')
@jwt_required()
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin', methods=['GET', 'POST'])
@jwt_required()
def admin():
    if request.method == 'POST':
        folder = request.form['folder']
        photos = request.files.getlist('photo')  # Get list of uploaded files

        if not photos or photos[0].filename == '':
            flash("No files selected!", "danger")
            return redirect('/')

        for photo in photos:
            if photo:
                filename = secure_filename(photo.filename)
                blob = bucket.blob(f"{folder}/{filename}")
                blob.upload_from_file(photo, content_type=photo.content_type)

        flash(f"{len(photos)} file(s) uploaded to folder '{folder}' successfully!", "success")
        return redirect('/admin')

    return render_template('admin.html')

@app.route('/view_photos')
@jwt_required()
def view_photos():
    name = get_jwt_identity()
    folder = f"{name}/"

    image_urls = []
    blobs = bucket.list_blobs(prefix=folder)

    for blob in blobs:
        if not blob.name.endswith('/'):
            # Generate a signed URL valid for 15 minutes
            url = blob.generate_signed_url(expiration=timedelta(minutes=15))
            image_urls.append(url)

    return render_template('view_photos.html', image_urls=image_urls)

if __name__ == '__main__':
    app.run(debug=True)
