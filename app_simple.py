from flask import Flask
import os

app = Flask(__name__)

@app.route('/')
def index():
    # Firebase HTML 파일을 직접 서빙
    with open('public/index.html', 'r', encoding='utf-8') as f:
        return f.read()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(debug=False, host='0.0.0.0', port=port)