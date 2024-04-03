# app.py
from flask import Flask, jsonify, render_template, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, FileField
from wtforms.validators import DataRequired, Email
from datetime import datetime
from flask_wtf.file import FileAllowed, FileSize
from werkzeug.utils import secure_filename
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from sqlalchemy import or_


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
app.config['UPLOAD_FOLDER'] = 'static/images'
migrate = Migrate(app, db)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    profile_picture = db.Column(db.String(100))
    bio = db.Column(db.Text)  # Tambah kolom bio
    twitter_username = db.Column(db.String(50))  # Tambah kolom username Twitter
    facebook_username = db.Column(db.String(50))  # Tambah kolom username Facebook

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Thread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('threads', lazy=True))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Relasi dengan pengirim
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')

    # Relasi dengan penerima
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')


class MessageForm(FlaskForm):
    content = StringField('Message', validators=[DataRequired()])  # Mengubah TextAreaField menjadi StringField
    submit = SubmitField('Send')

class ThreadForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = StringField('Content', validators=[DataRequired()])
    image = FileField('Image')
    submit = SubmitField('Create Thread')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('comments', lazy=True))
    thread_id = db.Column(db.Integer, db.ForeignKey('thread.id'), nullable=False)
    thread = db.relationship('Thread', backref=db.backref('thread_comments', lazy=True))

class UserProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    profile_picture = FileField('Profile Picture')
    bio = TextAreaField('Bio')  # Tambah bidang bio
    twitter_username = StringField('Twitter Username')  # Tambah bidang username Twitter
    facebook_username = StringField('Facebook Username')  # Tambah bidang username Facebook


class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id1 = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_id2 = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, user_id1, user_id2):
        self.user_id1 = user_id1
        self.user_id2 = user_id2

# Function to add friend
def add_friend(user_id1, user_id2):
    if user_id1 != user_id2:
        friendship = Friendship(user_id1=user_id1, user_id2=user_id2)
        db.session.add(friendship)
        db.session.commit()

with app.app_context():
    db.create_all()

@app.route('/')
@login_required
def home():
    threads = Thread.query.order_by(Thread.created_at.desc()).all()
    all_users = User.query.all()
    return render_template('home.html', threads=threads, all_users=all_users)

@app.route('/create_threads', methods=['GET', 'POST'])
@login_required
def create_threads():
    form = ThreadForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        image = form.image.data
        if image:
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            filename = None
        new_thread = Thread(title=title, content=content, image_filename=filename, user=current_user)
        db.session.add(new_thread)
        db.session.commit()
        flash('Thread created successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('create_threads.html', form=form)

# Halaman login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            error = 'Login Gagal. Silakan cek kembali username dan password.'
            return render_template('login.html', error=error)

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()

        if not existing_user:
            new_user = User(username=username)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))
        else:
            error = 'Username sudah digunakan. Silakan pilih username lain.'
            return render_template('register.html', error=error)

    return render_template('register.html')


@app.route('/thread/<int:thread_id>', methods=['GET', 'POST'])
@login_required
def view_thread(thread_id):
    thread = Thread.query.get_or_404(thread_id)

    if request.method == 'POST':
        content = request.form['content']

        new_comment = Comment(content=content, user=current_user, thread=thread)
        db.session.add(new_comment)
        db.session.commit()

        # Flash message for successful comment
        flash('Comment submitted successfully!', 'success')

        # Redirect to the same thread page after submitting a comment
        return redirect(url_for('view_thread', thread_id=thread.id))

    return render_template('view_thread.html', thread=thread, comments=thread.thread_comments)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    # Ambil informasi terbaru tentang pengguna dari database
    user_threads = Thread.query.filter_by(user=current_user).order_by(Thread.created_at.desc()).all()

    num_friends = Friendship.query.filter(
        (Friendship.user_id1 == current_user.id) | (Friendship.user_id2 == current_user.id)
    ).count()

    # Perbarui informasi pengguna jika ada data yang diubah
    form = UserProfileForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.bio = form.bio.data
        current_user.twitter_username = form.twitter_username.data
        current_user.facebook_username = form.facebook_username.data
        if form.profile_picture.data:
            file = form.profile_picture.data
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            current_user.profile_picture = filename
        db.session.commit()
        flash('Profil berhasil diperbarui', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', title='Profile', user_threads=user_threads, user=current_user, num_friends=num_friends, form=form)


@app.route('/delete_thread/<int:thread_id>', methods=['POST'])
@login_required
def delete_thread(thread_id):
    thread = Thread.query.get_or_404(thread_id)

    if current_user != thread.user:
        flash('You do not have permission to delete this thread.', 'danger')
        return redirect(url_for('view_thread', thread_id=thread.id))

    db.session.delete(thread)
    db.session.commit()

    flash('Thread deleted successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/search_users', methods=['GET'])
@login_required
def search_users():
    query = request.args.get('query')
    found_users = User.query.filter(User.username.ilike(f"%{query}%")).all()
    return render_template('search_results.html', found_users=found_users)

@app.route('/user/<username>')
def user_profile(username):
    user = User.query.filter_by(username=username).first_or_404()

    num_friends = Friendship.query.filter(
        (Friendship.user_id1 == user.id) | (Friendship.user_id2 == user.id)
    ).count()

    is_friend = Friendship.query.filter(
        (or_(Friendship.user_id1 == current_user.id, Friendship.user_id2 == current_user.id)) &
        (or_(Friendship.user_id1 == user.id, Friendship.user_id2 == user.id))
    ).first() is not None

    return render_template('user_profile.html', user=user, is_friend=is_friend, num_friends=num_friends)

@app.route('/conversation/<int:recipient_id>', methods=['GET', 'POST'])
@login_required
def conversation(recipient_id):
    recipient = User.query.get_or_404(recipient_id)
    form = MessageForm()

    if form.validate_on_submit():
        content = form.content.data

        message = Message(sender_id=current_user.id, receiver_id=recipient_id, content=content)
        db.session.add(message)
        db.session.commit()

        flash('Message sent successfully.', 'success')
        return redirect(url_for('conversation', recipient_id=recipient_id))

    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == recipient_id)) |
        ((Message.sender_id == recipient_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()

    
    return render_template('conversation.html', recipient=recipient, messages=messages, form=form)

@app.route('/conversations')
@login_required
def conversations():
    # Mendapatkan daftar percakapan yang melibatkan pengguna saat ini
    conversations = Message.query.filter_by(sender_id=current_user.id).distinct(Message.receiver_id).all()
    return render_template('conversations.html', conversations=conversations)



# Route to add friend
@app.route('/add_friend/<int:friend_id>', methods=['POST'])
@login_required
def add_friend_route(friend_id):
    friend = User.query.get_or_404(friend_id)

    # Check if the user is already friends with the given friend
    existing_friendship = Friendship.query.filter(
        or_(
            (Friendship.user_id1 == current_user.id) & (Friendship.user_id2 == friend_id),
            (Friendship.user_id1 == friend_id) & (Friendship.user_id2 == current_user.id)
        )
    ).first()

    if existing_friendship:
        flash('You are already friends with this user.', 'info')
    else:
        add_friend(current_user.id, friend_id)
        flash('Friend added successfully.', 'success')

    return redirect(url_for('user_profile', username=friend.username))

@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    form = UserProfileForm()
    if form.validate_on_submit():
        user = current_user
        user.username = form.username.data
        user.bio = form.bio.data
        user.twitter_username = form.twitter_username.data
        user.facebook_username = form.facebook_username.data
        if form.profile_picture.data:
            file = form.profile_picture.data
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            user.profile_picture = filename
        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profile'))
    return render_template('update_profile.html', form=form)


@app.errorhandler(404)
def not_found_error(error):
    return render_template('error_pages/404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()  # Mengembalikan sesi database ke keadaan awal
    return render_template('error_pages/500.html'), 500

# Menangani kesalahan umum lainnya
@app.errorhandler(Exception)
def unhandled_exception(error):
    return render_template('error_pages/500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)
