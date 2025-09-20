# auth_server.py - 放在和你主程序同一目录
from flask import Flask, request, jsonify
import jwt
import datetime
import hashlib
import os
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # 允许跨域，方便本地程序调用

# 🔑 秘钥（生产环境请从环境变量读取）
SECRET_KEY = os.getenv("JWT_SECRET", "JWT_SECRET")

# 🗃️ 模拟用户数据库（实际项目请用 SQLite/MySQL）
USERS = {
    "user1": hashlib.sha256("password123".encode()).hexdigest(),  # 用户名: 密码哈希
    "admin": hashlib.sha256("admin456".encode()).hexdigest(),
"liyang": hashlib.sha256("138204".encode()).hexdigest(),
"wangrong": hashlib.sha256("138204".encode()).hexdigest(),
"cuixiyi": hashlib.sha256("138224".encode()).hexdigest(),
"yuemaozheng": hashlib.sha256("138254".encode()).hexdigest(),}

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({"error": "用户名和密码不能为空"}), 400

    if username in USERS:
        return jsonify({"error": "用户已存在"}), 409

    # 密码哈希存储
    USERS[username] = hashlib.sha256(password.encode()).hexdigest()
    return jsonify({"message": "注册成功"}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({"error": "用户名和密码不能为空"}), 400

    user_hash = USERS.get(username)
    if not user_hash or user_hash != hashlib.sha256(password.encode()).hexdigest():
        return jsonify({"error": "用户名或密码错误"}), 401

    # 生成 JWT Token（1小时有效期）
    token = jwt.encode({
        'sub': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, SECRET_KEY, algorithm='HS256')

    return jsonify({
        "token": token,
        "username": username,
        "message": "登录成功"
    })

@app.route('/api/validate', methods=['POST'])
def validate_token():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return jsonify({"valid": False}), 401

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return jsonify({
            "valid": True,
            "username": payload['sub']
        })
    except jwt.ExpiredSignatureError:
        return jsonify({"valid": False, "error": "Token已过期"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"valid": False, "error": "无效Token"}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
