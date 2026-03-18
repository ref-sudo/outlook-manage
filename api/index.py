import json
import urllib.parse
import urllib.request
import imaplib
import email
from email.header import decode_header
import ssl
from http.server import BaseHTTPRequestHandler

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            # 1. 接收 POST 请求发来的纯文本 (账号----占位----ClientID----RefreshToken)
            content_length = int(self.headers.get('Content-Length', 0))
            raw_text = self.rfile.read(content_length).decode('utf-8')
            
            parts = raw_text.strip().split('----')
            if len(parts) < 4:
                self._send_json({"error": "格式错误，需要以 ---- 分隔的4个部分"}, 400)
                return
                
            email_address = parts[0]
            client_id = parts[2]
            refresh_token = parts[3]

            # 2. 换取 Access Token
            token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
            data = urllib.parse.urlencode({
                'client_id': client_id,
                'refresh_token': refresh_token,
                'grant_type': 'refresh_token'
            }).encode('utf-8')

            req = urllib.request.Request(token_url, data=data)
            with urllib.request.urlopen(req) as response:
                token_data = json.loads(response.read().decode('utf-8'))
                access_token = token_data['access_token']

            # 3. IMAP 登录与读取
            ssl_context = ssl._create_unverified_context()
            mail = imaplib.IMAP4_SSL('outlook.office365.com', 993, ssl_context=ssl_context)
            auth_string = f"user={email_address}\x01auth=Bearer {access_token}\x01\x01"
            mail.authenticate('XOAUTH2', lambda x: auth_string.encode('utf-8'))
            
            # 选择收件箱并搜索全部邮件
            mail.select('INBOX')
            status, messages = mail.search(None, 'ALL')
            mail_ids = messages[0].split()
            
            # 取出最新的 3 封
            latest_ids = mail_ids[-3:]
            latest_ids.reverse()
            
            results = []
            for num in latest_ids:
                status, data = mail.fetch(num, '(RFC822)')
                raw_email = data[0][1]
                msg = email.message_from_bytes(raw_email)
                
                # 解析标题（防乱码）
                subject, encoding = decode_header(msg["Subject"])[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding if encoding else "utf-8", errors="ignore")
                    
                results.append({
                    "date": msg.get("Date"),
                    "from": msg.get("From"),
                    "subject": subject
                })
                
            # 断开连接
            mail.logout()
            
            # 4. 返回 JSON 数据
            self._send_json({"success": True, "emails": results}, 200)

        except Exception as e:
            # 遇到错误时，返回错误信息
            self._send_json({"error": "代码运行出错", "details": str(e)}, 500)

    def _send_json(self, data, status_code):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        # 允许跨域（可选，如果你要在网页端调用的话）
        self.send_header('Access-Control-Allow-Origin', '*') 
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode('utf-8'))
