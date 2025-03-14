from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from mcstatus import JavaServer
from markupsafe import Markup
import os
import logging
import sys
import json
from threading import Thread
import time
import requests
import traceback

app = Flask(__name__)
# Налаштування логування
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Використовуємо змінні середовища для конфігурації
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///minecraft_server.db')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads')

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Створюємо папку для завантажень, якщо її немає
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    minecraft_username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    about_me = db.Column(db.Text, default='')
    discord_username = db.Column(db.String(80))
    join_date = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    post_count = db.Column(db.Integer, default=0)
    topics_count = db.Column(db.Integer, default=0)
    is_admin = db.Column(db.Boolean, default=False)
    messages = db.relationship('ForumMessage', backref='author', lazy=True)
    
    # Minecraft statistics
    playtime_minutes = db.Column(db.Integer, default=0)
    deaths = db.Column(db.Integer, default=0)
    mobs_killed = db.Column(db.Integer, default=0)
    blocks_broken = db.Column(db.Integer, default=0)
    blocks_placed = db.Column(db.Integer, default=0)
    distance_walked = db.Column(db.Float, default=0.0)  # в блоках
    last_stats_update = db.Column(db.DateTime)

class ForumTopic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    messages = db.relationship('ForumMessage', backref='topic', lazy=True)

class MessageVote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('forum_message.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    vote_type = db.Column(db.Boolean, nullable=False)  # True для лайка, False для дизлайка
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        db.UniqueConstraint('message_id', 'user_id', name='unique_message_vote'),
    )

class ForumMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    image_path = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    topic_id = db.Column(db.Integer, db.ForeignKey('forum_topic.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('forum_message.id', ondelete='CASCADE'), nullable=True)
    replies = db.relationship('ForumMessage', 
                            backref=db.backref('parent', remote_side=[id]),
                            lazy='dynamic',
                            cascade='all, delete-orphan')
    is_pinned = db.Column(db.Boolean, default=False)
    votes = db.relationship('MessageVote',
                          backref='message',
                          lazy='dynamic',
                          cascade='all, delete-orphan')
    
    @property
    def likes_count(self):
        return self.votes.filter_by(vote_type=True).count()
        
    @property
    def dislikes_count(self):
        return self.votes.filter_by(vote_type=False).count()
        
    @property
    def replies_count(self):
        return self.replies.count()

class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref='news_posts')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def init_forum_topics():
    if ForumTopic.query.count() == 0:
        topics = [
            {
                'title': 'Про наш сервер',
                'description': 'Загальна інформація про сервер, правила та оголошення'
            },
            {
                'title': 'Клієнти, Модифікації і Текстури',
                'description': 'Обговорення клієнтів, модів та ресурспаків'
            },
            {
                'title': 'Проблеми та їх вирішення',
                'description': 'Допомога з технічними проблемами'
            },
            {
                'title': 'Пропозиції та ідеї',
                'description': 'Пропозиції щодо покращення серверу'
            },
            {
                'title': 'Знайомства',
                'description': 'Знайомство з іншими гравцями серверу'
            },
            {
                'title': 'Творчість',
                'description': 'Показуйте свої будівлі, машини та інші творіння'
            },
            {
                'title': 'Івенти',
                'description': 'Інформація про майбутні та минулі події на сервері'
            },
            {
                'title': 'Торгівля',
                'description': 'Купівля, продаж та обмін предметами між гравцями'
            }
        ]
        
        for topic_data in topics:
            topic = ForumTopic(**topic_data)
            db.session.add(topic)
        
        db.session.commit()

def get_server_status():
    try:
        server = JavaServer.lookup("77.120.95.9:25565")
        status = server.status()
        return {
            'online': True,
            'players_online': status.players.online,
            'players_max': status.players.max,
            'latency': round(status.latency, 2)
        }
    except:
        return {
            'online': False,
            'players_online': 0,
            'players_max': 0,
            'latency': 0
        }

@app.before_request
def before_request():
    logger.info(f'Отримано запит: {request.method} {request.path}')

@app.after_request
def after_request(response):
    logger.info(f'Відповідь: {response.status}')
    return response

@app.errorhandler(Exception)
def handle_error(error):
    error_details = traceback.format_exc()
    logger.error(f'Детальна помилка:\n{error_details}')
    return f'Виникла помилка на сервері: {str(error)}', 500

@app.route('/')
def home():
    total_players = User.query.count()
    total_messages = ForumMessage.query.count()
    server_status = get_server_status()
    news = News.query.order_by(News.created_at.desc()).limit(3).all()
    
    return render_template('home.html', 
                         total_players=total_players,
                         total_messages=total_messages,
                         server_status=server_status,
                         news=news)

@app.route('/rules')
def rules():
    return render_template('rules.html')

@app.route('/commands')
def commands():
    return render_template('commands.html')

@app.route('/forum')
def forum():
    topics = ForumTopic.query.all()
    return render_template('forum.html', topics=topics)

@app.route('/forum/topic/<int:topic_id>', methods=['GET', 'POST'])
def forum_topic(topic_id):
    topic = ForumTopic.query.get_or_404(topic_id)
    page = request.args.get('page', 1, type=int)
    
    if request.method == 'POST' and current_user.is_authenticated:
        content = request.form.get('content')
        if not content:
            flash('Повідомлення не може бути порожнім')
            return redirect(url_for('forum_topic', topic_id=topic_id))
            
        message = ForumMessage(
            content=content,
            topic_id=topic_id,
            user_id=current_user.id
        )
        
        if 'image' in request.files:
            image = request.files['image']
            if image.filename:
                filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{image.filename}"
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                message.image_path = filename
        
        try:
            db.session.add(message)
            # Збільшуємо лічильник повідомлень користувача
            current_user.post_count += 1
            db.session.commit()
            flash('Повідомлення додано успішно')
        except Exception as e:
            db.session.rollback()
            logger.error(f'Помилка при додаванні повідомлення: {str(e)}')
            flash('Виникла помилка при додаванні повідомлення')
        return redirect(url_for('forum_topic', topic_id=topic_id))
    
    # Отримуємо всі повідомлення для теми
    messages_query = ForumMessage.query.filter_by(topic_id=topic_id)
    
    # Спочатку отримуємо закріплені повідомлення
    pinned_messages = messages_query.filter_by(is_pinned=True).order_by(ForumMessage.created_at.desc()).all()
    
    # Потім отримуємо звичайні повідомлення з пагінацією
    regular_messages = messages_query.filter_by(is_pinned=False).order_by(ForumMessage.created_at.desc())
    
    # Налаштовуємо пагінацію
    pagination = regular_messages.paginate(
        page=page,
        per_page=10,
        error_out=False
    )
    
    # Об'єднуємо закріплені повідомлення зі звичайними
    all_messages = pinned_messages + pagination.items
    
    # Отримуємо голоси поточного користувача
    if current_user.is_authenticated:
        user_votes = {vote.message_id: vote.vote_type 
                     for vote in MessageVote.query.filter(
                         MessageVote.user_id == current_user.id,
                         MessageVote.message_id.in_([m.id for m in all_messages])
                     ).all()}
    else:
        user_votes = {}
    
    return render_template('forum_topic.html', 
                         topic=topic, 
                         all_messages=all_messages,
                         pagination=pagination,
                         user_votes=user_votes)

@app.route('/forum/message/<int:message_id>/reply', methods=['POST'])
@login_required
def reply_to_message(message_id):
    parent_message = ForumMessage.query.get_or_404(message_id)
    content = request.form.get('content')
    
    if not content:
        flash('Відповідь не може бути порожньою')
        return redirect(url_for('forum_topic', topic_id=parent_message.topic_id))
        
    reply = ForumMessage(
        content=content,
        topic_id=parent_message.topic_id,
        user_id=current_user.id,
        parent_id=message_id
    )
    
    if 'image' in request.files:
        image = request.files['image']
        if image.filename:
            filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{image.filename}"
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            reply.image_path = filename
    
    try:
        db.session.add(reply)
        # Збільшуємо лічильник повідомлень користувача
        current_user.post_count += 1
        db.session.commit()
        flash('Відповідь додано успішно')
    except Exception as e:
        db.session.rollback()
        logger.error(f'Помилка при додаванні відповіді: {str(e)}')
        flash('Виникла помилка при додаванні відповіді')
    
    return redirect(url_for('forum_topic', topic_id=parent_message.topic_id))

@app.route('/forum/message/<int:message_id>/pin', methods=['POST'])
@login_required
def pin_message(message_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Тільки адміністратори можуть закріплювати повідомлення'}), 403
        
    message = ForumMessage.query.get_or_404(message_id)
    message.is_pinned = not message.is_pinned
    
    try:
        db.session.commit()
        return jsonify({
            'success': True,
            'is_pinned': message.is_pinned
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f'Помилка при закріпленні повідомлення: {str(e)}')
        return jsonify({'error': 'Помилка при закріпленні повідомлення'}), 500

@app.route('/forum/message/<int:message_id>/vote', methods=['POST'])
@login_required
def vote_message(message_id):
    message = ForumMessage.query.get_or_404(message_id)
    vote_type = request.form.get('vote_type') == 'like'
    
    existing_vote = MessageVote.query.filter_by(
        message_id=message_id,
        user_id=current_user.id
    ).first()
    
    try:
        if existing_vote:
            if existing_vote.vote_type == vote_type:
                # Якщо користувач натискає на ту ж кнопку - видаляємо голос
                db.session.delete(existing_vote)
            else:
                # Якщо користувач змінює свій голос
                existing_vote.vote_type = vote_type
        else:
            # Створюємо новий голос
            vote = MessageVote(
                message_id=message_id,
                user_id=current_user.id,
                vote_type=vote_type
            )
            db.session.add(vote)
            
        db.session.commit()
        return jsonify({
            'success': True,
            'likes': message.likes_count,
            'dislikes': message.dislikes_count
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f'Помилка при голосуванні: {str(e)}')
        return jsonify({'error': 'Помилка при голосуванні'}), 500

@app.route('/forum/message/<int:message_id>/delete', methods=['POST'])
@login_required
def delete_message(message_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Тільки адміністратори можуть видаляти повідомлення'}), 403
        
    message = ForumMessage.query.get_or_404(message_id)
    
    try:
        # Видаляємо зображення, якщо воно є
        if message.image_path:
            try:
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], message.image_path)
                if os.path.exists(image_path):
                    os.remove(image_path)
            except Exception as e:
                logger.error(f'Помилка при видаленні зображення: {str(e)}')
        
        # Зменшуємо лічильник повідомлень користувача
        message.author.post_count -= 1
        
        # Видаляємо саме повідомлення (каскадно видалить голоси та відповіді)
        db.session.delete(message)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        logger.error(f'Помилка при видаленні повідомлення: {str(e)}')
        return jsonify({'error': 'Помилка при видаленні повідомлення'}), 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        minecraft_username = request.form.get('minecraft_username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Перевірка наявності всіх полів
        if not all([username, minecraft_username, password, confirm_password]):
            flash('Будь ласка, заповніть всі поля')
            return redirect(url_for('register'))
        
        # Перевірка паролів
        if password != confirm_password:
            flash('Паролі не співпадають')
            return redirect(url_for('register'))
            
        # Перевірка довжини пароля
        if len(password) < 6:
            flash('Пароль повинен містити щонайменше 6 символів')
            return redirect(url_for('register'))
            
        # Перевірка унікальності імені користувача
        if User.query.filter_by(username=username).first():
            flash('Це ім\'я користувача вже зайняте')
            return redirect(url_for('register'))
            
        # Перевірка унікальності нікнейму Minecraft
        if User.query.filter_by(minecraft_username=minecraft_username).first():
            flash('Цей нікнейм Minecraft вже зареєстрований')
            return redirect(url_for('register'))
            
        try:
            user = User(
                username=username,
                password_hash=generate_password_hash(password),
                minecraft_username=minecraft_username
            )
            db.session.add(user)
            db.session.commit()
            flash('Реєстрація успішна! Тепер ви можете увійти.')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Помилка при реєстрації. Спробуйте ще раз.')
            return redirect(url_for('register'))
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Неправильне ім\'я користувача або пароль')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('profile.html', user=user)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.about_me = request.form['about_me']
        current_user.discord_username = request.form['discord_username']
        db.session.commit()
        flash('Ваш профіль було оновлено!')
        return redirect(url_for('profile', username=current_user.username))
    return render_template('edit_profile.html')

@app.route('/search')
def search_users():
    query = request.args.get('q', '')
    if query:
        users = User.query.filter(
            db.or_(
                User.username.ilike(f'%{query}%'),
                User.minecraft_username.ilike(f'%{query}%')
            )
        ).all()
    else:
        users = []
    return render_template('search.html', users=users, query=query)

@app.route('/news/create', methods=['GET', 'POST'])
@login_required
def create_news():
    if not current_user.is_admin:
        flash('У вас немає прав для створення новин')
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        
        if not title or not content:
            flash('Будь ласка, заповніть всі поля')
            return redirect(url_for('create_news'))
            
        news = News(
            title=title,
            content=content,
            author_id=current_user.id
        )
        
        db.session.add(news)
        db.session.commit()
        flash('Новину успішно створено!')
        return redirect(url_for('home'))
        
    return render_template('create_news.html')

@app.route('/news/delete/<int:news_id>', methods=['POST'])
@login_required
def delete_news(news_id):
    if not current_user.is_admin:
        flash('У вас немає прав для видалення новин')
        return redirect(url_for('home'))
        
    news = News.query.get_or_404(news_id)
    db.session.delete(news)
    db.session.commit()
    flash('Новину видалено')
    return redirect(url_for('home'))

def update_post_counts():
    """Оновлює лічильники повідомлень для всіх користувачів"""
    users = User.query.all()
    for user in users:
        post_count = ForumMessage.query.filter_by(user_id=user.id).count()
        user.post_count = post_count
    db.session.commit()

def update_minecraft_stats():
    """Оновлює статистику гравців з серверу Minecraft"""
    while True:
        try:
            with app.app_context():
                server = JavaServer.lookup("77.120.95.9:25565")
                status = server.status()
                
                # Отримуємо список онлайн гравців
                if hasattr(status.players, 'sample') and status.players.sample:
                    online_players = [p.name for p in status.players.sample]
                    
                    for player in online_players:
                        user = User.query.filter_by(minecraft_username=player).first()
                        if user:
                            # Оновлюємо час в грі (додаємо 5 хвилин, бо це інтервал оновлення)
                            if not user.playtime_minutes:
                                user.playtime_minutes = 0
                            user.playtime_minutes += 5
                            user.last_stats_update = datetime.utcnow()
                            
                    db.session.commit()
                    logger.info(f"Оновлено статистику для {len(online_players)} гравців")
                
        except Exception as e:
            logger.error(f"Помилка при оновленні статистики Minecraft: {str(e)}")
        
        # Оновлюємо кожні 5 хвилин
        time.sleep(300)

def start_background_tasks():
    """Запускає фонові задачі"""
    Thread(target=update_minecraft_stats, daemon=True).start()

def create_app():
    with app.app_context():
        # Add nl2br filter
        @app.template_filter('nl2br')
        def nl2br_filter(text):
            if not text:
                return ""
            return Markup(text.replace('\n', '<br>'))
            
        db.create_all()
        init_forum_topics()
        update_post_counts()
        start_background_tasks()  # Запускаємо фонові задачі
    return app

@app.route('/plugins')
def plugins():
    return render_template('plugins.html')

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000)