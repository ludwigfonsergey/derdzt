import sqlite3
import os
import json
import re
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, 'static')

app = Flask(__name__, static_folder=None)
app.secret_key = 'dzt-super-secret-key-change-in-production'
app.config.update(
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
)
CORS(app, supports_credentials=True,
     origins=['http://127.0.0.1:5000', 'http://localhost:5000'])

DB_PATH = os.path.join(BASE_DIR, 'dzt.db')

# ============================================================
# АДМИНЫ
# ============================================================
ADMINS = {'derd', 'greenvestor', 'uspix', 'pepsilord420'}

def is_admin(username):
    return username in ADMINS


# ============================================================
# БАЗА ДАННЫХ
# ============================================================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_banned INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS levels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            cover TEXT,
            yt_link TEXT,
            gd_link TEXT,
            rating_type TEXT NOT NULL DEFAULT 'both',
            added_by INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (added_by) REFERENCES users(id)
        )
    ''')

    # Оценка админа = официальная оценка уровня (одна на уровень, от админа)
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin_ratings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            level_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            gameplay_data TEXT,
            decoration_data TEXT,
            gameplay_total INTEGER DEFAULT 0,
            decoration_total INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (level_id) REFERENCES levels(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Оценки обычных пользователей, привязанные к рецензиям
    c.execute('''
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            level_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            text TEXT NOT NULL,
            gameplay_data TEXT,
            decoration_data TEXT,
            gameplay_total INTEGER DEFAULT 0,
            decoration_total INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            UNIQUE(level_id, user_id),
            FOREIGN KEY (level_id) REFERENCES levels(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Миграции для старых баз
    c.execute("PRAGMA table_info(users)")
    user_cols = [row[1] for row in c.fetchall()]
    if 'is_banned' not in user_cols:
        c.execute("ALTER TABLE users ADD COLUMN is_banned INTEGER DEFAULT 0")

    c.execute("PRAGMA table_info(reviews)")
    rev_cols = [row[1] for row in c.fetchall()]
    for col, typ in [
        ('gameplay_data', 'TEXT'),
        ('decoration_data', 'TEXT'),
        ('gameplay_total', 'INTEGER DEFAULT 0'),
        ('decoration_total', 'INTEGER DEFAULT 0'),
    ]:
        if col not in rev_cols:
            c.execute(f"ALTER TABLE reviews ADD COLUMN {col} {typ}")

    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def extract_yt_id(url):
    if not url:
        return None
    reg = r'(?:youtu\.be\/|v\/|u\/\w\/|embed\/|watch\?v=|&v=)([^#&?]{11})'
    m = re.search(reg, url)
    return m.group(1) if m else None


# ============================================================
# ДЕКОРАТОРЫ
# ============================================================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Требуется авторизация'}), 401
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT is_banned FROM users WHERE id = ?', (session['user_id'],))
        u = c.fetchone()
        conn.close()
        if not u:
            session.clear()
            return jsonify({'error': 'Пользователь не найден'}), 401
        if u['is_banned']:
            return jsonify({'error': 'Ваш аккаунт заблокирован администратором'}), 403
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Требуется авторизация'}), 401
        if session.get('username') not in ADMINS:
            return jsonify({'error': 'Только администраторы'}), 403
        return f(*args, **kwargs)
    return decorated


# ============================================================
# РЕГИСТРАЦИЯ / ВХОД / ВЫХОД
# ============================================================
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if len(username) < 3 or len(username) > 30:
        return jsonify({'error': 'Имя должно быть от 3 до 30 символов'}), 400
    if len(password) < 4:
        return jsonify({'error': 'Пароль должен быть минимум 4 символа'}), 400

    conn = get_db()
    c = conn.cursor()
    try:
        c.execute(
            'INSERT INTO users (username, password_hash, is_banned, created_at) VALUES (?, ?, 0, ?)',
            (username, generate_password_hash(password), datetime.utcnow().isoformat())
        )
        conn.commit()
        user_id = c.lastrowid
        session['user_id'] = user_id
        session['username'] = username
        return jsonify({
            'id': user_id,
            'username': username,
            'is_admin': is_admin(username),
        }), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Пользователь с таким именем уже существует'}), 409
    finally:
        conn.close()


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()

    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Неверное имя пользователя или пароль'}), 401

    if user['is_banned']:
        return jsonify({'error': 'Ваш аккаунт заблокирован администратором'}), 403

    session['user_id'] = user['id']
    session['username'] = user['username']
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'is_admin': is_admin(user['username']),
    }), 200


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Вы вышли из системы'}), 200


@app.route('/api/me', methods=['GET'])
def me():
    if 'user_id' not in session:
        return jsonify({'logged_in': False}), 200

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    u = c.fetchone()
    conn.close()
    if not u:
        session.clear()
        return jsonify({'logged_in': False}), 200

    return jsonify({
        'logged_in': True,
        'id': u['id'],
        'username': u['username'],
        'is_admin': is_admin(u['username']),
        'is_banned': bool(u['is_banned']),
    }), 200


# ============================================================
# УРОВНИ
# ============================================================
@app.route('/api/levels', methods=['GET'])
def get_levels():
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT l.*,
            (SELECT COUNT(*) FROM reviews WHERE level_id = l.id) AS reviews_count,
            (SELECT AVG((gameplay_total + decoration_total) / 2.0)
                FROM reviews WHERE level_id = l.id) AS avg_reviews,
            (SELECT AVG((gameplay_total + decoration_total) / 2.0)
                FROM admin_ratings WHERE level_id = l.id) AS avg_admin
        FROM levels l
        ORDER BY l.created_at DESC
    ''')
    rows = c.fetchall()
    conn.close()

    levels = []
    for r in rows:
        levels.append({
            'id': r['id'],
            'title': r['title'],
            'author': r['author'],
            'cover': r['cover'],
            'yt_link': r['yt_link'],
            'gd_link': r['gd_link'],
            'rating_type': r['rating_type'],
            'created_at': r['created_at'],
            'reviews_count': r['reviews_count'],
            'avg_reviews': round(r['avg_reviews']) if r['avg_reviews'] is not None else None,
            'avg_admin': round(r['avg_admin']) if r['avg_admin'] is not None else None,
            'avg_total': round(r['avg_admin']) if r['avg_admin'] is not None else (round(r['avg_reviews']) if r['avg_reviews'] is not None else None),
        })
    return jsonify(levels), 200


@app.route('/api/levels', methods=['POST'])
@admin_required
def create_level():
    data = request.get_json() or {}
    title = (data.get('title') or '').strip()
    author = (data.get('author') or '').strip()
    cover = (data.get('cover') or '').strip()
    yt_link = (data.get('yt_link') or '').strip()
    gd_link = (data.get('gd_link') or '').strip()
    rating_type = data.get('rating_type') or 'both'

    if not title or not author:
        return jsonify({'error': 'Название и автор обязательны'}), 400
    if rating_type not in ('gameplay', 'decoration', 'both'):
        return jsonify({'error': 'Неверный тип оценивания'}), 400

    if yt_link and not cover:
        vid = extract_yt_id(yt_link)
        if vid:
            cover = f'https://img.youtube.com/vi/{vid}/maxresdefault.jpg'

    conn = get_db()
    c = conn.cursor()
    c.execute('''
        INSERT INTO levels (title, author, cover, yt_link, gd_link, rating_type, added_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (title, author, cover, yt_link, gd_link, rating_type, session['user_id'], datetime.utcnow().isoformat()))
    conn.commit()
    level_id = c.lastrowid
    conn.close()
    return jsonify({'id': level_id, 'message': 'Уровень добавлен'}), 201


@app.route('/api/levels/<int:level_id>', methods=['GET'])
def get_level(level_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM levels WHERE id = ?', (level_id,))
    r = c.fetchone()
    if not r:
        conn.close()
        return jsonify({'error': 'Уровень не найден'}), 404

    # Админские оценки
    c.execute('''
        SELECT ar.*, u.username FROM admin_ratings ar
        JOIN users u ON u.id = ar.user_id
        WHERE ar.level_id = ?
        ORDER BY ar.created_at DESC
    ''', (level_id,))
    admin_rows = c.fetchall()

    # Рецензии (с оценками)
    c.execute('''
        SELECT rv.*, u.username FROM reviews rv
        JOIN users u ON u.id = rv.user_id
        WHERE rv.level_id = ?
        ORDER BY rv.created_at DESC
    ''', (level_id,))
    review_rows = c.fetchall()

    def avg_of(rows, prefix):
        gp_avg = {k: 0 for k in ['music', 'composition', 'variety', 'atmosphere', 'originality']}
        dc_avg = {k: 0 for k in ['composition', 'color', 'theme', 'quality', 'atmosphere', 'originality']}
        gp_cnt, dc_cnt = 0, 0
        gp_sum, dc_sum = 0, 0
        for rr in rows:
            if rr['gameplay_data']:
                gd = json.loads(rr['gameplay_data'])
                for k in gp_avg: gp_avg[k] += gd.get(k, 0)
                gp_cnt += 1
                gp_sum += rr['gameplay_total']
            if rr['decoration_data']:
                dd = json.loads(rr['decoration_data'])
                for k in dc_avg: dc_avg[k] += dd.get(k, 0)
                dc_cnt += 1
                dc_sum += rr['decoration_total']
        if gp_cnt > 0:
            gp_avg = {k: round(v / gp_cnt, 1) for k, v in gp_avg.items()}
        if dc_cnt > 0:
            dc_avg = {k: round(v / dc_cnt, 1) for k, v in dc_avg.items()}
        return {
            f'{prefix}gameplay_avg': gp_avg,
            f'{prefix}decoration_avg': dc_avg,
            f'{prefix}gameplay_count': gp_cnt,
            f'{prefix}decoration_count': dc_cnt,
            f'{prefix}gameplay_total_avg': round(gp_sum / gp_cnt) if gp_cnt else 0,
            f'{prefix}decoration_total_avg': round(dc_sum / dc_cnt) if dc_cnt else 0,
        }

    admin_stats = avg_of(admin_rows, 'admin_')
    user_stats = avg_of(review_rows, '')

    # Моя оценка (админ или рецензия)
    my_admin_rating = None
    my_review = None
    if 'user_id' in session:
        c.execute('SELECT * FROM admin_ratings WHERE level_id = ? AND user_id = ?',
                  (level_id, session['user_id']))
        mr = c.fetchone()
        if mr:
            my_admin_rating = {
                'gameplay_data': json.loads(mr['gameplay_data']) if mr['gameplay_data'] else None,
                'decoration_data': json.loads(mr['decoration_data']) if mr['decoration_data'] else None,
                'gameplay_total': mr['gameplay_total'],
                'decoration_total': mr['decoration_total'],
            }
        c.execute('SELECT * FROM reviews WHERE level_id = ? AND user_id = ?',
                  (level_id, session['user_id']))
        rv = c.fetchone()
        if rv:
            my_review = {
                'id': rv['id'],
                'text': rv['text'],
                'gameplay_data': json.loads(rv['gameplay_data']) if rv['gameplay_data'] else None,
                'decoration_data': json.loads(rv['decoration_data']) if rv['decoration_data'] else None,
                'gameplay_total': rv['gameplay_total'],
                'decoration_total': rv['decoration_total'],
                'created_at': rv['created_at'],
            }

    conn.close()

    return jsonify({
        'id': r['id'],
        'title': r['title'],
        'author': r['author'],
        'cover': r['cover'],
        'yt_link': r['yt_link'],
        'gd_link': r['gd_link'],
        'rating_type': r['rating_type'],
        'created_at': r['created_at'],
        'admin_stats': admin_stats,
        'user_stats': user_stats,
        'reviews': [{
            'id': rv['id'],
            'user': rv['username'],
            'text': rv['text'],
            'gameplay_data': json.loads(rv['gameplay_data']) if rv['gameplay_data'] else None,
            'decoration_data': json.loads(rv['decoration_data']) if rv['decoration_data'] else None,
            'gameplay_total': rv['gameplay_total'],
            'decoration_total': rv['decoration_total'],
            'created_at': rv['created_at'],
        } for rv in review_rows],
        'admin_reviews': [{
            'id': ar['id'],
            'user': ar['username'],
            'gameplay_data': json.loads(ar['gameplay_data']) if ar['gameplay_data'] else None,
            'decoration_data': json.loads(ar['decoration_data']) if ar['decoration_data'] else None,
            'gameplay_total': ar['gameplay_total'],
            'decoration_total': ar['decoration_total'],
            'created_at': ar['created_at'],
        } for ar in admin_rows],
        'my_admin_rating': my_admin_rating,
        'my_review': my_review,
    }), 200


@app.route('/api/levels/<int:level_id>', methods=['DELETE'])
@admin_required
def delete_level(level_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id FROM levels WHERE id = ?', (level_id,))
    if not c.fetchone():
        conn.close()
        return jsonify({'error': 'Уровень не найден'}), 404
    c.execute('DELETE FROM admin_ratings WHERE level_id = ?', (level_id,))
    c.execute('DELETE FROM reviews WHERE level_id = ?', (level_id,))
    c.execute('DELETE FROM levels WHERE id = ?', (level_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Уровень удалён'}), 200


# ============================================================
# АДМИНСКАЯ ОЦЕНКА УРОВНЯ (главная)
# ============================================================
@app.route('/api/levels/<int:level_id>/admin_rate', methods=['POST'])
@admin_required
def admin_rate_level(level_id):
    data = request.get_json() or {}
    gameplay_data = data.get('gameplay_data')
    decoration_data = data.get('decoration_data')

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM levels WHERE id = ?', (level_id,))
    level = c.fetchone()
    if not level:
        conn.close()
        return jsonify({'error': 'Уровень не найден'}), 404

    rt = level['rating_type']
    if rt == 'gameplay' and not gameplay_data:
        conn.close()
        return jsonify({'error': 'Только геймплей'}), 400
    if rt == 'decoration' and not decoration_data:
        conn.close()
        return jsonify({'error': 'Только декорации'}), 400
    if rt == 'both' and not gameplay_data and not decoration_data:
        conn.close()
        return jsonify({'error': 'Оцени хотя бы одну категорию'}), 400

    gp_total = sum(gameplay_data.values()) if gameplay_data else 0
    dc_total = sum(decoration_data.values()) if decoration_data else 0

    # Админ может перезаписать свою оценку
    c.execute('SELECT id FROM admin_ratings WHERE level_id = ? AND user_id = ?',
              (level_id, session['user_id']))
    existing = c.fetchone()
    if existing:
        c.execute('''
            UPDATE admin_ratings
            SET gameplay_data = ?, decoration_data = ?, gameplay_total = ?, decoration_total = ?, created_at = ?
            WHERE id = ?
        ''', (
            json.dumps(gameplay_data) if gameplay_data else None,
            json.dumps(decoration_data) if decoration_data else None,
            gp_total, dc_total, datetime.utcnow().isoformat(),
            existing['id']
        ))
    else:
        c.execute('''
            INSERT INTO admin_ratings (level_id, user_id, gameplay_data, decoration_data,
                                       gameplay_total, decoration_total, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            level_id, session['user_id'],
            json.dumps(gameplay_data) if gameplay_data else None,
            json.dumps(decoration_data) if decoration_data else None,
            gp_total, dc_total, datetime.utcnow().isoformat()
        ))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Админская оценка сохранена'}), 201


# ============================================================
# РЕЦЕНЗИИ (с оценками)
# ============================================================
@app.route('/api/levels/<int:level_id>/reviews', methods=['POST'])
@login_required
def add_review(level_id):
    data = request.get_json() or {}
    text = (data.get('text') or '').strip()
    gameplay_data = data.get('gameplay_data')
    decoration_data = data.get('decoration_data')

    if len(text) < 10:
        return jsonify({'error': 'Рецензия должна быть не короче 10 символов'}), 400
    if len(text) > 2000:
        return jsonify({'error': 'Рецензия не должна превышать 2000 символов'}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM levels WHERE id = ?', (level_id,))
    level = c.fetchone()
    if not level:
        conn.close()
        return jsonify({'error': 'Уровень не найден'}), 404

    rt = level['rating_type']
    if rt == 'gameplay' and not gameplay_data:
        conn.close()
        return jsonify({'error': 'Нужно оценить геймплей'}), 400
    if rt == 'decoration' and not decoration_data:
        conn.close()
        return jsonify({'error': 'Нужно оценить декорации'}), 400
    if rt == 'both' and not gameplay_data and not decoration_data:
        conn.close()
        return jsonify({'error': 'Нужно оценить хотя бы одну категорию'}), 400

    gp_total = sum(gameplay_data.values()) if gameplay_data else 0
    dc_total = sum(decoration_data.values()) if decoration_data else 0

    # Один пользователь = одна рецензия на уровень (можно перезаписать)
    c.execute('SELECT id FROM reviews WHERE level_id = ? AND user_id = ?',
              (level_id, session['user_id']))
    existing = c.fetchone()
    if existing:
        c.execute('''
            UPDATE reviews
            SET text = ?, gameplay_data = ?, decoration_data = ?,
                gameplay_total = ?, decoration_total = ?, created_at = ?
            WHERE id = ?
        ''', (
            text,
            json.dumps(gameplay_data) if gameplay_data else None,
            json.dumps(decoration_data) if decoration_data else None,
            gp_total, dc_total, datetime.utcnow().isoformat(),
            existing['id']
        ))
        conn.commit()
        review_id = existing['id']
    else:
        c.execute('''
            INSERT INTO reviews (level_id, user_id, text, gameplay_data, decoration_data,
                                 gameplay_total, decoration_total, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            level_id, session['user_id'], text,
            json.dumps(gameplay_data) if gameplay_data else None,
            json.dumps(decoration_data) if decoration_data else None,
            gp_total, dc_total, datetime.utcnow().isoformat()
        ))
        conn.commit()
        review_id = c.lastrowid

    conn.close()
    return jsonify({'id': review_id, 'message': 'Рецензия сохранена'}), 201


@app.route('/api/levels/<int:level_id>/reviews/<int:review_id>', methods=['DELETE'])
@login_required
def delete_review(level_id, review_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT user_id FROM reviews WHERE id = ? AND level_id = ?', (review_id, level_id))
    r = c.fetchone()
    if not r:
        conn.close()
        return jsonify({'error': 'Рецензия не найдена'}), 404
    if r['user_id'] != session['user_id'] and session.get('username') not in ADMINS:
        conn.close()
        return jsonify({'error': 'Нет прав'}), 403
    c.execute('DELETE FROM reviews WHERE id = ?', (review_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Рецензия удалена'}), 200


# ============================================================
# БАНЫ (только админы)
# ============================================================
@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_list_users():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, username, is_banned, created_at FROM users ORDER BY created_at DESC')
    rows = c.fetchall()
    conn.close()
    return jsonify([{
        'id': r['id'],
        'username': r['username'],
        'is_banned': bool(r['is_banned']),
        'created_at': r['created_at'],
        'is_admin': is_admin(r['username']),
    } for r in rows]), 200


@app.route('/api/admin/users/<int:user_id>/ban', methods=['POST'])
@admin_required
def admin_ban_user(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    u = c.fetchone()
    if not u:
        conn.close()
        return jsonify({'error': 'Пользователь не найден'}), 404
    if u['username'] in ADMINS:
        conn.close()
        return jsonify({'error': 'Нельзя забанить администратора'}), 403
    c.execute('UPDATE users SET is_banned = 1 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Пользователь забанен'}), 200


@app.route('/api/admin/users/<int:user_id>/unban', methods=['POST'])
@admin_required
def admin_unban_user(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE users SET is_banned = 0 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Пользователь разбанен'}), 200


# ============================================================
# СТАТИКА
# ============================================================
@app.route('/')
def index():
    return send_from_directory(STATIC_DIR, 'index.html')


@app.route('/level')
@app.route('/level.html')
def level_page():
    return send_from_directory(STATIC_DIR, 'level.html')


@app.route('/admin')
def admin_page():
    return send_from_directory(STATIC_DIR, 'admin.html')


@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(STATIC_DIR, filename)


if __name__ == '__main__':
    init_db()
    print('=' * 60)
    print('  DZT Backend запущен!')
    print('  Папка static:', STATIC_DIR)
    print('  index.html существует:', os.path.exists(os.path.join(STATIC_DIR, 'index.html')))
    print('  level.html существует:', os.path.exists(os.path.join(STATIC_DIR, 'level.html')))
    print('  Админы:', ', '.join(sorted(ADMINS)))
    print('  Открой: http://127.0.0.1:5000/')
    print('=' * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)