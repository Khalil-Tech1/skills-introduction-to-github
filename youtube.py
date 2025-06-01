from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
import ssl
from werkzeug.utils import secure_filename
from sqlalchemy import or_, func

# Ensure SSL compatibility
ssl._create_default_https_context = ssl._create_unverified_context

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///youtube_clone.db'
app.config['JWT_SECRET_KEY'] = 'your_secret_key_here'  # Change this in production
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Ensure 'instance' directory exists
os.makedirs('instance', exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    filename = db.Column(db.String(200), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    views = db.Column(db.Integer, default=0)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'), nullable=False)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'), nullable=False)

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subscriber_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subscribed_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=func.now())

class Story(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(200), unique=True, nullable=False)
    timestamp = db.Column(db.DateTime, default=func.now())

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=func.now())

@app.route('/')
def home():
    return '<h1>Welcome to the YouTube Clone API!</h1>'

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify({'access_token': access_token})
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/download', methods=['GET'])
def download_app():
    return send_from_directory(directory='instance', path='youtube_clone.db', as_attachment=True)

@app.route('/messages', methods=['POST'])
@jwt_required()
def send_message():
    data = request.get_json()
    new_message = Message(sender_id=get_jwt_identity(), receiver_id=data['receiver_id'], content=data['content'])
    db.session.add(new_message)
    db.session.commit()
    return jsonify({'message': 'Message sent'})

@app.route('/messages/<int:user_id>', methods=['GET'])
@jwt_required()
def get_messages(user_id):
    current_user = get_jwt_identity()
    messages = Message.query.filter(((Message.sender_id == current_user) & (Message.receiver_id == user_id)) | ((Message.sender_id == user_id) & (Message.receiver_id == current_user))).order_by(Message.timestamp).all()
    results = [{'id': msg.id, 'sender_id': msg.sender_id, 'receiver_id': msg.receiver_id, 'content': msg.content, 'timestamp': msg.timestamp} for msg in messages]
    return jsonify(results)

@app.route('/frontend')
def frontend():
    return """
    <h1>Welcome to the YouTube Clone</h1>
    <form id="registerForm">
        <h2>Register</h2>
        <input type="text" id="username" placeholder="Username" required>
        <input type="password" id="password" placeholder="Password" required>
        <button type="submit">Register</button>
    </form>
    <form id="loginForm">
        <h2>Login</h2>
        <input type="text" id="loginUsername" placeholder="Username" required>
        <input type="password" id="loginPassword" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
    <script>
        document.getElementById('registerForm').onsubmit = async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const response = await fetch('/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const result = await response.json();
            alert(result.message);
        };

        document.getElementById('loginForm').onsubmit = async (e) => {
            e.preventDefault();
            const username = document.getElementById('loginUsername').value;
            const password = document.getElementById('loginPassword').value;
            const response = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const result = await response.json();
            if (response.ok) {
                alert('Login successful! Token: ' + result.access_token);
            } else {
                alert(result.message);
            }
        };
    </script>
    """

@app.route('/api-docs')
def api_docs():
    return """
    <h1>API Documentation</h1>
    <ul>
        <li><strong>GET /</strong>: Welcome message</li>
        <li><strong>POST /register</strong>: Register a new user (JSON: {"username": "user", "password": "pass"})</li>
        <li><strong>POST /login</strong>: Login and get a JWT token (JSON: {"username": "user", "password": "pass"})</li>
        <li><strong>POST /messages</strong>: Send a message (JWT required, JSON: {"receiver_id": 1, "content": "Hello"})</li>
        <li><strong>GET /messages/&lt;user_id&gt;</strong>: Get messages with a user (JWT required)</li>
        <li><strong>GET /download</strong>: Download the database file</li>
        <li><strong>GET /frontend</strong>: Access the frontend interface</li>
    </ul>
    """

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
    app.run(debug=True)
