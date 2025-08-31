from firebase_functions import https_fn
from firebase_admin import initialize_app

# Firebase 앱 초기화
initialize_app()

@https_fn.on_request()
def app(req: https_fn.Request) -> https_fn.Response:
    # public/index.html 파일을 읽어서 반환
    try:
        with open('../public/index.html', 'r', encoding='utf-8') as f:
            html_content = f.read()
    except FileNotFoundError:
        html_content = "<h1>스케줄 관리 앱</h1><p>HTML 파일을 찾을 수 없습니다.</p>"
    
    return https_fn.Response(html_content, headers={"Content-Type": "text/html; charset=utf-8"})