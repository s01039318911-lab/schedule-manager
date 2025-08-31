from firebase_functions import https_fn
from firebase_admin import initialize_app, firestore
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from datetime import datetime
import hashlib
import secrets
import os

# Firebase 앱 초기화
initialize_app()
db = firestore.client()

# Flask 앱 생성
flask_app = Flask(__name__)
flask_app.config['SECRET_KEY'] = secrets.token_hex(16)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@flask_app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@flask_app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        # 띄어쓰기 제거
        username = username.strip().replace(' ', '') if username else ''
        password = password.strip().replace(' ', '') if password else ''
        
        # Firestore에서 사용자 확인
        users_ref = db.collection('users')
        query = users_ref.where('username', '==', username).limit(1)
        users = query.stream()
        
        for user_doc in users:
            user_data = user_doc.to_dict()
            if user_data.get('password_hash') == hash_password(password):
                session['user_id'] = user_doc.id
                session['username'] = user_data['username']
                session['is_admin'] = user_data.get('is_admin', False)
                return jsonify({'success': True})
        
        return jsonify({'success': False, 'message': '잘못된 사용자명 또는 비밀번호입니다.'})
    
    return render_template('login.html')

@flask_app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # 띄어쓰기 제거
    username = username.strip().replace(' ', '') if username else ''
    password = password.strip().replace(' ', '') if password else ''
    
    # 중복 확인
    users_ref = db.collection('users')
    existing = users_ref.where('username', '==', username).limit(1).stream()
    
    if any(existing):
        return jsonify({'success': False, 'message': '이미 존재하는 사용자명입니다.'})
    
    # 새 사용자 생성
    is_admin = username == '이뿌니'
    user_data = {
        'username': username,
        'password_hash': hash_password(password),
        'is_admin': is_admin,
        'created_at': datetime.utcnow()
    }
    
    doc_ref = users_ref.add(user_data)
    user_id = doc_ref[1].id
    
    session['user_id'] = user_id
    session['username'] = username
    session['is_admin'] = is_admin
    return jsonify({'success': True})

@flask_app.route('/logout')
def logout():
    session.clear()
    response = redirect(url_for('login'))
    response.headers['Clear-Site-Data'] = '"storage"'
    return response

@https_fn.on_request()
def app(req: https_fn.Request) -> https_fn.Response:
    # Flask 앱을 Firebase Functions에서 실행
    with flask_app.test_request_context(req.path, method=req.method, 
                                        data=req.data, headers=req.headers):
        try:
            response = flask_app.full_dispatch_request()
            return https_fn.Response(
                response.get_data(as_text=True),
                status=response.status_code,
                headers=dict(response.headers)
            )
        except Exception as e:
            return https_fn.Response(f"Error: {str(e)}", status=500)