from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from datetime import datetime
import hashlib
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///schedule_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    events = db.relationship('Event', backref='creator', lazy=True)
    shared_events = db.relationship('SharedEvent', backref='user', lazy=True)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    shared_users = db.relationship('SharedEvent', backref='event', lazy=True)

class SharedEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    can_edit = db.Column(db.Boolean, default=False)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        # 띄어쓰기 제거
        username = username.strip().replace(' ', '') if username else ''
        password = password.strip().replace(' ', '') if password else ''
        
        user = User.query.filter_by(username=username).first()
        if user and user.password_hash == hash_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': '잘못된 사용자명 또는 비밀번호입니다.'})
    
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # 띄어쓰기 제거
    username = username.strip().replace(' ', '') if username else ''
    password = password.strip().replace(' ', '') if password else ''
    
    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': '이미 존재하는 사용자명입니다.'})
    
    is_admin = username == '이뿌니'
    user = User(username=username, password_hash=hash_password(password), is_admin=is_admin)
    db.session.add(user)
    db.session.commit()
    
    session['user_id'] = user.id
    session['username'] = user.username
    session['is_admin'] = user.is_admin
    return jsonify({'success': True})

@app.route('/logout')
def logout():
    session.clear()
    # localStorage의 자동 로그인 정보도 제거
    response = redirect(url_for('login'))
    response.headers['Clear-Site-Data'] = '"storage"'
    return response

@app.route('/api/events', methods=['GET'])
def get_events():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_id = session['user_id']
    
    own_events = Event.query.filter_by(creator_id=user_id).all()
    shared_event_ids = [se.event_id for se in SharedEvent.query.filter_by(user_id=user_id).all()]
    shared_events = Event.query.filter(Event.id.in_(shared_event_ids)).all()
    
    all_events = own_events + shared_events
    
    events_data = []
    for event in all_events:
        events_data.append({
            'id': event.id,
            'title': event.title,
            'description': event.description,
            'start_time': event.start_time.isoformat(),
            'end_time': event.end_time.isoformat(),
            'creator': event.creator.username,
            'is_owner': event.creator_id == user_id
        })
    
    return jsonify(events_data)

@app.route('/api/events', methods=['POST'])
def create_event():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    start_time = datetime.fromisoformat(data['start_time'].replace('Z', ''))
    end_time = datetime.fromisoformat(data['end_time'].replace('Z', ''))
    user_id = session['user_id']
    
    # 시간 중복 검사
    conflicting_events = db.session.query(Event).filter(
        or_(
            Event.creator_id == user_id,
            Event.id.in_(
                db.session.query(SharedEvent.event_id).filter(SharedEvent.user_id == user_id)
            )
        ),
        Event.start_time < end_time,
        Event.end_time > start_time
    ).all()
    
    if conflicting_events:
        return jsonify({
            'error': '해당 시간에 이미 다른 일정이 있습니다.',
            'conflicts': [{'id': e.id, 'title': e.title, 'start_time': e.start_time.isoformat()} for e in conflicting_events]
        }), 400
    
    event = Event(
        title=data['title'],
        description=data.get('description', ''),
        start_time=start_time,
        end_time=end_time,
        creator_id=user_id
    )
    
    db.session.add(event)
    db.session.commit()
    
    return jsonify({
        'id': event.id,
        'title': event.title,
        'description': event.description,
        'start_time': event.start_time.isoformat(),
        'end_time': event.end_time.isoformat(),
        'creator': event.creator.username,
        'is_owner': True
    })

@app.route('/api/events/<int:event_id>', methods=['PUT'])
def update_event(event_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    event = Event.query.get_or_404(event_id)
    user_id = session['user_id']
    is_admin = session.get('is_admin', False)
    
    # 관리자이거나, 본인 일정이거나, 편집 권한이 있는 공유 일정인 경우만 수정 가능
    if not is_admin and event.creator_id != user_id:
        shared = SharedEvent.query.filter_by(event_id=event_id, user_id=user_id, can_edit=True).first()
        if not shared:
            return jsonify({'error': 'Permission denied'}), 403
    
    data = request.get_json()
    new_start_time = datetime.fromisoformat(data['start_time'].replace('Z', ''))
    new_end_time = datetime.fromisoformat(data['end_time'].replace('Z', ''))
    
    # 시간 중복 검사 (자기 자신 제외)
    conflicting_events = db.session.query(Event).filter(
        or_(
            Event.creator_id == user_id,
            Event.id.in_(
                db.session.query(SharedEvent.event_id).filter(SharedEvent.user_id == user_id)
            )
        ),
        Event.id != event_id,  # 자기 자신 제외
        Event.start_time < new_end_time,
        Event.end_time > new_start_time
    ).all()
    
    if conflicting_events:
        return jsonify({
            'error': '해당 시간에 이미 다른 일정이 있습니다.',
            'conflicts': [{'id': e.id, 'title': e.title, 'start_time': e.start_time.isoformat()} for e in conflicting_events]
        }), 400
    
    event.title = data['title']
    event.description = data.get('description', '')
    event.start_time = new_start_time
    event.end_time = new_end_time
    
    db.session.commit()
    
    return jsonify({
        'id': event.id,
        'title': event.title,
        'description': event.description,
        'start_time': event.start_time.isoformat(),
        'end_time': event.end_time.isoformat(),
        'creator': event.creator.username,
        'is_owner': event.creator_id == user_id
    })

@app.route('/api/events/<int:event_id>', methods=['DELETE'])
def delete_event(event_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    event = Event.query.get_or_404(event_id)
    user_id = session['user_id']
    is_admin = session.get('is_admin', False)
    
    # 관리자이거나 본인 일정인 경우만 삭제 가능
    if not is_admin and event.creator_id != user_id:
        return jsonify({'error': 'Permission denied'}), 403
    
    SharedEvent.query.filter_by(event_id=event_id).delete()
    db.session.delete(event)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/share', methods=['POST'])
def share_event():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    event_id = data['event_id']
    username = data['username']
    can_edit = data.get('can_edit', False)
    
    event = Event.query.get_or_404(event_id)
    if event.creator_id != session['user_id']:
        return jsonify({'error': 'Permission denied'}), 403
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': '사용자를 찾을 수 없습니다.'}), 404
    
    if SharedEvent.query.filter_by(event_id=event_id, user_id=user.id).first():
        return jsonify({'error': '이미 공유된 사용자입니다.'}), 400
    
    shared_event = SharedEvent(event_id=event_id, user_id=user.id, can_edit=can_edit)
    db.session.add(shared_event)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/events/all', methods=['GET'])
def get_all_events():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # 모든 사용자의 일정 가져오기
    all_events = Event.query.all()
    
    events_data = []
    for event in all_events:
        events_data.append({
            'id': event.id,
            'title': event.title,
            'description': event.description,
            'start_time': event.start_time.isoformat(),
            'end_time': event.end_time.isoformat(),
            'creator': event.creator.username,
            'is_owner': event.creator_id == session['user_id']
        })
    
    return jsonify(events_data)

@app.route('/api/current-user')
def get_current_user():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = User.query.get(session['user_id'])
    if user:
        return jsonify({
            'username': user.username,
            'is_admin': user.is_admin
        })
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/users')
def get_users():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    users = User.query.all()
    return jsonify([{'id': u.id, 'username': u.username} for u in users if u.id != session['user_id']])

@app.route('/api/admin/users')
def get_all_users():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    users = User.query.all()
    return jsonify([{
        'id': u.id, 
        'username': u.username,
        'is_admin': u.is_admin,
        'created_at': u.created_at.isoformat(),
        'event_count': len(u.events)
    } for u in users])

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    # 관리자 자신은 삭제할 수 없음
    if user_id == session['user_id']:
        return jsonify({'error': '관리자는 자신을 삭제할 수 없습니다.'}), 400
    
    user = User.query.get_or_404(user_id)
    
    # 사용자의 모든 일정과 공유 정보 삭제
    SharedEvent.query.filter_by(user_id=user_id).delete()
    for event in user.events:
        SharedEvent.query.filter_by(event_id=event.id).delete()
    Event.query.filter_by(creator_id=user_id).delete()
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/admin/users/<int:user_id>/password', methods=['PUT'])
def change_user_password(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    new_password = data.get('new_password')
    
    if not new_password:
        return jsonify({'error': '새 비밀번호를 입력해주세요.'}), 400
    
    user = User.query.get_or_404(user_id)
    user.password_hash = hash_password(new_password)
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'{user.username}의 비밀번호가 변경되었습니다.'})

@app.route('/api/admin/users/<int:user_id>/username', methods=['PUT'])
def change_username(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    new_username = data.get('new_username')
    
    # 띄어쓰기 제거
    new_username = new_username.strip().replace(' ', '') if new_username else ''
    
    if not new_username:
        return jsonify({'error': '새 사용자명을 입력해주세요.'}), 400
    
    # 중복 사용자명 검사
    existing_user = User.query.filter_by(username=new_username).first()
    if existing_user and existing_user.id != user_id:
        return jsonify({'error': '이미 존재하는 사용자명입니다.'}), 400
    
    user = User.query.get_or_404(user_id)
    old_username = user.username
    user.username = new_username
    
    # 새 사용자명이 '이뿌니'인 경우 관리자 권한 부여
    if new_username == '이뿌니':
        user.is_admin = True
    
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'{old_username}의 사용자명이 {new_username}로 변경되었습니다.'})

if __name__ == '__main__':
    import os
    with app.app_context():
        db.create_all()
    
    port = int(os.environ.get('PORT', 5001))
    app.run(debug=False, host='0.0.0.0', port=port)