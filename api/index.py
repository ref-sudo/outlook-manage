import hashlib
import hmac
import html
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import imaplib
import email
from datetime import datetime, timezone
from email.header import decode_header
from email.parser import BytesParser
from email.policy import default
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from http import cookies
from http.server import BaseHTTPRequestHandler

try:
    from vercel.blob import list_objects, put
except Exception:
    list_objects = None
    put = None


class handler(BaseHTTPRequestHandler):
    TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    IMAP_HOST = "outlook.office365.com"
    IMAP_PORT = 993
    SESSION_COOKIE = "outlook_manage_session"
    CREDENTIAL_PREFIX = "credentials/"
    MAX_EMAIL_LIMIT = 20

    def do_GET(self):
        try:
            query = self._query()

            if self._wants_mailbox_page(query):
                self._render_mailbox_page(query)
                return

            if self._wants_message_page(query):
                self._render_message_page(query)
                return

            if self._wants_email_json(query):
                self._handle_email_lookup(query)
                return

            if self._is_authenticated():
                self._render_dashboard(query)
                return

            self._render_login_page(query)
        except Exception as exc:
            self._send_json(
                {"error": "请求处理失败", "details": self._stringify_error(exc)},
                500,
            )

    def do_POST(self):
        try:
            body = self._read_body()
            form = self._parse_request_body(body)
            action = (form.get("action") or "").strip().lower()

            if not action and "----" in form.get("_raw_text", ""):
                action = "save"

            if action == "login":
                self._handle_login(form)
                return

            if action == "logout":
                self._handle_logout()
                return

            if action == "save":
                self._handle_save_credential(form)
                return

            self._send_json({"error": "未知操作"}, 400)
        except Exception as exc:
            self._send_json(
                {"error": "提交失败", "details": self._stringify_error(exc)},
                500,
            )

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_common_headers()
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, X-Admin-Password, X-Requested-With",
        )
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def _handle_login(self, form):
        if not self._password_matches(form.get("password", "")):
            self._redirect("/?error=login_failed")
            return

        self._redirect("/", cookies_to_set=[self._session_cookie_value()])

    def _handle_logout(self):
        self._redirect("/", cookies_to_set=[self._expired_session_cookie()])

    def _handle_save_credential(self, form):
        if not self._is_authenticated() and not self._password_matches(
            form.get("password", "")
        ):
            self._redirect("/?error=unauthorized")
            return

        if self._storage_warning():
            self._redirect("/?error=storage")
            return

        record = self._extract_credential_record(form)
        self._save_credential_record(record)
        lookup_email = urllib.parse.quote(record["lookup_email"], safe="")
        self._redirect(f"/?saved={lookup_email}")

    def _handle_email_lookup(self, query, response_mode="processed"):
        if not self._request_is_authorized(query):
            self._send_json({"error": "密码错误或未登录"}, 401)
            return

        lookup_email = self._query_email_key(query)
        if not lookup_email:
            self._send_json({"error": "缺少 email 参数，必须传完整邮箱"}, 400)
            return

        record = self._load_credential_record(lookup_email)
        if not record:
            self._send_json({"error": f"未找到邮箱 {lookup_email} 的凭证"}, 404)
            return

        requested_mail_id = self._query_mail_id(query)
        if requested_mail_id:
            emails = self._fetch_emails(
                record,
                1,
                query,
                response_mode=response_mode,
                mail_id=requested_mail_id,
            )
            if not emails:
                self._send_json({"error": f"未找到邮件 id={requested_mail_id}"}, 404)
                return
            limit = 1
        else:
            limit = self._parse_limit(query)
            emails = self._fetch_emails(record, limit, query, response_mode=response_mode)

        self._send_json(
            {
                "success": True,
                "email": lookup_email,
                "email_address": record["email_address"],
                "requested_limit": limit,
                "returned": len(emails),
                "mode": response_mode,
                "mail_id": requested_mail_id,
                "compact": self._query_flag(query, "compact", "simple"),
                "emails": emails,
            },
            200,
        )

    def _render_page(self, title, content, extra_head=""):
        page = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{title}} - Outlook Manage</title>
  <style>
    :root {{
      --primary: #2563eb;
      --primary-hover: #1d4ed8;
      --bg: #f9fafb;
      --card-bg: #ffffff;
      --text-main: #111827;
      --text-muted: #4b5563;
      --border: #e5e7eb;
      --success-bg: #f0fdf4;
      --success-text: #166534;
      --error-bg: #fef2f2;
      --error-text: #991b1b;
      --radius: 12px;
      --shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1);
      --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif;
      color: var(--text-main);
      background-color: var(--bg);
      line-height: 1.5;
    }}
    .container {{
      max-width: 1000px;
      margin: 0 auto;
      padding: 2rem 1rem;
    }}
    .card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }}
    h1, h2, h3 {{
      margin-top: 0;
      color: var(--text-main);
    }}
    h1 {{ font-size: 1.875rem; font-weight: 700; margin-bottom: 1.5rem; }}
    h2 {{ font-size: 1.25rem; font-weight: 600; margin-bottom: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
    p {{ margin-bottom: 1rem; color: var(--text-muted); }}
    
    .btn {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0.5rem 1rem;
      font-size: 0.875rem;
      font-weight: 600;
      border-radius: var(--radius);
      cursor: pointer;
      transition: all 0.2s;
      text-decoration: none;
      border: 1px solid transparent;
    }}
    .btn-primary {{
      background-color: var(--primary);
      color: white;
    }}
    .btn-primary:hover {{
      background-color: var(--primary-hover);
    }}
    .btn-secondary {{
      background-color: white;
      border-color: var(--border);
      color: var(--text-main);
    }}
    .btn-secondary:hover {{
      background-color: var(--bg);
    }}
    .btn-block {{ width: 100%; }}
    .btn-sm {{ padding: 0.25rem 0.5rem; font-size: 0.75rem; }}
    
    .form-group {{ margin-bottom: 1rem; }}
    label {{ display: block; font-size: 0.875rem; font-weight: 500; margin-bottom: 0.25rem; color: var(--text-main); }}
    input[type="text"], input[type="password"], input[type="number"], textarea, select {{
      width: 100%;
      padding: 0.625rem;
      border: 1px solid var(--border);
      border-radius: var(--radius);
      font-size: 0.875rem;
      outline: none;
      transition: border-color 0.2s;
    }}
    input:focus, textarea:focus {{ border-color: var(--primary); }}
    
    .notice {{
      padding: 1rem;
      border-radius: var(--radius);
      margin-bottom: 1.5rem;
      font-size: 0.875rem;
    }}
    .notice-success {{ background-color: var(--success-bg); color: var(--success-text); border: 1px solid #bbf7d0; }}
    .notice-error {{ background-color: var(--error-bg); color: var(--error-text); border: 1px solid #fecaca; }}
    
    code {{
      background-color: #f3f4f6;
      padding: 0.2rem 0.4rem;
      border-radius: 4px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 0.875rem;
      word-break: break-all;
    }}
    .code-block {{
      display: block;
      padding: 1rem;
      margin: 0.5rem 0;
      overflow-x: auto;
    }}
    
    .grid {{ display: grid; grid-template-columns: 1fr; gap: 1.5rem; }}
    @media (min-width: 768px) {{
      .grid {{ grid-template-columns: repeat(2, 1fr); }}
    }}
    
    .badge {{
      display: inline-block;
      padding: 0.125rem 0.375rem;
      font-size: 0.75rem;
      font-weight: 600;
      border-radius: 9999px;
      background-color: #e5e7eb;
      color: #374151;
    }}
    
    .nav {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }}
    .nav-brand {{ font-size: 1.25rem; font-weight: 700; color: var(--primary); text-decoration: none; }}
    
    .saved-list {{ list-style: none; padding: 0; margin: 0; }}
    .saved-item {{
      border-bottom: 1px solid var(--border);
      padding: 1rem 0;
    }}
    .saved-item:last-child {{ border-bottom: none; }}
    .saved-item-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }}
    .saved-item-email {{ font-weight: 600; font-size: 0.95rem; }}
    .actions-row {{ display: flex; gap: 0.5rem; flex-wrap: wrap; }}
    
    .mail-list {{ list-style: none; padding: 0; margin: 0; }}
    .mail-item {{
      padding: 1rem;
      border-bottom: 1px solid var(--border);
      transition: background-color 0.2s;
    }}
    .mail-item:hover {{ background-color: #f9fafb; }}
    .mail-item:last-child {{ border-bottom: none; }}
    .mail-item-title {{ font-weight: 600; font-size: 1.1rem; margin-bottom: 0.25rem; }}
    .mail-item-meta {{ font-size: 0.875rem; color: var(--text-muted); margin-bottom: 0.5rem; }}
    .mail-item-preview {{ font-size: 0.875rem; color: #6b7280; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }}
    
    .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
    .meta-box {{ background: #f9fafb; padding: 0.75rem; border-radius: var(--radius); border: 1px solid var(--border); }}
    .meta-label {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; margin-bottom: 0.25rem; }}
    .meta-value {{ font-size: 0.875rem; font-weight: 500; word-break: break-all; }}
    
    iframe {{ width: 100%; border: 1px solid var(--border); border-radius: var(--radius); min-height: 600px; background: white; }}
  </style>
  {{extra_head}}
</head>
<body>
  <div class="container">
    {{content}}
  </div>
</body>
</html>"""
        return page

    def _render_login_page(self, query):
        password_missing = not self._admin_password()
        storage_warning = self._storage_warning()
        error = (query.get("error") or [""])[0]
        saved = urllib.parse.unquote((query.get("saved") or [""])[0]).strip()

        notices = []
        if error == "login_failed":
            notices.append(self._notice("密码不正确，请重新登录。", kind="error"))
        elif error == "unauthorized":
            notices.append(self._notice("请先登录后再保存凭证。", kind="error"))
        elif password_missing:
            notices.append(self._notice("还没有配置 APP_PASSWORD 或 ADMIN_PASSWORD，请到 Vercel 环境变量里添加。", kind="error"))
        elif saved:
            notices.append(self._notice(f"邮箱 {html.escape(saved)} 的凭证已保存。", kind="success"))

        content = f"""
    <div style="max-width: 450px; margin: 5rem auto;">
      <div class="card" style="padding: 2.5rem;">
        <div style="text-align: center; margin-bottom: 2rem;">
          <div style="font-size: 0.875rem; font-weight: 700; color: var(--primary); text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 0.5rem;">Outlook Manage</div>
          <h1 style="margin-bottom: 0.5rem;">欢迎回来</h1>
          <p>请登录以管理您的邮件凭证</p>
        </div>
        
        {''.join(notices)}
        {storage_warning}
        
        <form method="post" action="/api">
          <input type="hidden" name="action" value="login">
          <div class="form-group">
            <label for="password">管理密码</label>
            <input id="password" name="password" type="password" placeholder="输入 APP_PASSWORD 或 ADMIN_PASSWORD" required autofocus>
          </div>
          <button class="btn btn-primary btn-block" type="submit" style="height: 3rem; font-size: 1rem;">登录</button>
        </form>
        
        <div style="margin-top: 2rem; padding-top: 1.5rem; border-top: 1px solid var(--border); font-size: 0.8125rem; color: var(--text-muted);">
          <p style="margin-bottom: 0.5rem;"><strong>配置提示：</strong></p>
          <ul style="padding-left: 1.25rem; margin: 0;">
            <li style="margin-bottom: 0.25rem;">需设置 <code>APP_PASSWORD</code> 或 <code>ADMIN_PASSWORD</code></li>
            <li>需连接 <code>Vercel Blob</code> 存储</li>
          </ul>
        </div>
      </div>
    </div>
"""
        self._send_html(self._render_page("登录", content), 200)

    def _render_dashboard(self, query):
        saved_email = urllib.parse.unquote((query.get("saved") or [""])[0]).strip()
        error = (query.get("error") or [""])[0]
        notices = []

        if saved_email:
            notices.append(self._notice(f"凭证保存成功：{html.escape(saved_email)}", kind="success"))
        if error == "storage":
            notices.append(self._notice("当前未配置 Blob 存储，无法保存凭证。", kind="error"))

        storage_warning = self._storage_warning()
        saved_items = self._saved_emails()
        list_html = self._saved_email_list_html(saved_items)
        base_lookup_url = self._lookup_base_url()
        raw_lookup_url = self._raw_lookup_base_url()
        display_password = self._admin_password() or "未配置"
        browser_default_email = self._query_email_key(query) or (saved_items[0] if saved_items else "")

        content = f"""
    <nav class="nav">
      <a href="/" class="nav-brand">Outlook Manage</a>
      <form method="post" action="/api">
        <input type="hidden" name="action" value="logout">
        <button class="btn btn-secondary btn-sm" type="submit">退出登录</button>
      </form>
    </nav>

    <header style="margin-bottom: 2rem;">
      <h1>控制台</h1>
      <p style="font-size: 1.125rem;">管理您的 Outlook IMAP 凭证并轻松查询邮件内容。</p>
      {''.join(notices)}
      {storage_warning}
    </header>

    <div class="grid">
      <div class="card">
        <h2>保存凭证</h2>
        <p>格式：<code>邮箱----占位----ClientID----RefreshToken</code></p>
        <form method="post" action="/api" enctype="multipart/form-data">
          <input type="hidden" name="action" value="save">
          
          <div class="form-group">
            <label for="credential_file">上传 .txt 文件</label>
            <input id="credential_file" name="credential_file" type="file" accept=".txt,.text">
          </div>
          
          <div class="form-group">
            <label for="credential_text">或粘贴原始文本</label>
            <textarea id="credential_text" name="credential_text" placeholder="邮箱----占位----ClientID----RefreshToken" style="min-height: 80px;"></textarea>
          </div>

          <div class="form-group">
            <label for="email_address">邮箱地址 (可选)</label>
            <input id="email_address" name="email_address" type="text" placeholder="name@outlook.com">
          </div>

          <div class="form-group">
            <label for="client_id">Client ID (可选)</label>
            <input id="client_id" name="client_id" type="text" placeholder="Azure App Client ID">
          </div>

          <div class="form-group">
            <label for="refresh_token">Refresh Token (可选)</label>
            <textarea id="refresh_token" name="refresh_token" placeholder="如有单独的 Refresh Token 可填于此" style="min-height: 60px;"></textarea>
          </div>

          <button class="btn btn-primary btn-block" type="submit">保存凭证</button>
        </form>
      </div>

      <div class="card">
        <h2>邮件浏览器</h2>
        <p>快速查看指定邮箱的最近邮件列表。</p>
        <form method="get" action="/api">
          <input type="hidden" name="ui" value="browser">
          
          <div class="form-group">
            <label for="browse_email">完整邮箱地址</label>
            <input id="browse_email" name="email" type="text" value="{html.escape(browser_default_email)}" placeholder="name@outlook.com" required>
          </div>

          <div class="form-group">
            <label for="browse_limit">获取数量</label>
            <input id="browse_limit" name="limit" type="number" min="1" max="{self.MAX_EMAIL_LIMIT}" value="10">
          </div>

          <button class="btn btn-primary btn-block" type="submit">打开浏览器</button>
        </form>
      </div>

      <div class="card">
        <h2>已保存邮箱</h2>
        <p>当前存储中的所有邮箱凭证。</p>
        {list_html}
      </div>

      <div class="card">
        <h2>API 快速参考</h2>
        <div style="font-size: 0.875rem;">
          <p><strong>查询密码:</strong> <code>{html.escape(display_password)}</code></p>
          
          <p><strong>整理后的 JSON:</strong></p>
          <code class="code-block">{html.escape(base_lookup_url)}?password=...&amp;email=...</code>
          
          <p><strong>原始邮件 JSON:</strong></p>
          <code class="code-block">{html.escape(raw_lookup_url)}?password=...&amp;email=...</code>
          
          <div style="margin-top: 1rem;">
            <span class="badge">提示</span>
            <span class="small" style="color: var(--text-muted); margin-left: 0.5rem;">支持参数 <code>limit=5</code>, <code>compact=1</code>, <code>raw=1</code>。</span>
          </div>
        </div>
      </div>
    </div>
"""
        self._send_html(self._render_page("控制台", content), 200)

    def _render_mailbox_page(self, query):
        if not self._request_is_authorized(query):
            self._redirect("/?error=unauthorized")
            return

        lookup_email = self._query_email_key(query)
        limit = self._parse_limit(query, default=10)
        list_html = '<div style="text-align: center; padding: 3rem; color: var(--text-muted);"><p>请输入邮箱地址并点击刷新</p></div>'
        notice_html = ""

        if lookup_email:
            record = self._load_credential_record(lookup_email)
            if not record:
                notice_html = self._notice(f"未找到邮箱 {lookup_email} 的凭证。", kind="error")
            else:
                emails = self._fetch_emails(record, limit, query, response_mode="processed", force_compact=True)
                list_html = self._mailbox_list_html(lookup_email, emails, limit)

        content = f"""
    <nav class="nav">
      <a href="/" class="nav-brand">Outlook Manage</a>
      <a href="/" class="btn btn-secondary btn-sm">返回管理台</a>
    </nav>

    <div class="card">
      <h1>邮件浏览器</h1>
      {notice_html}
      <form method="get" action="/api" class="grid" style="grid-template-columns: 1fr auto auto; align-items: flex-end;">
        <input type="hidden" name="ui" value="browser">
        <div class="form-group" style="margin-bottom: 0;">
          <label for="email">完整邮箱地址</label>
          <input id="email" name="email" type="text" value="{html.escape(lookup_email)}" placeholder="name@outlook.com" required>
        </div>
        <div class="form-group" style="margin-bottom: 0; width: 100px;">
          <label for="limit">数量</label>
          <input id="limit" name="limit" type="number" min="1" max="{self.MAX_EMAIL_LIMIT}" value="{limit}">
        </div>
        <button class="btn btn-primary" type="submit" style="height: 42px;">刷新列表</button>
      </form>
    </div>

    <div class="card" style="padding: 0; overflow: hidden;">
      <div style="padding: 1rem 1.5rem; border-bottom: 1px solid var(--border);">
        <h2 style="margin: 0; border: none; padding: 0;">邮件列表</h2>
      </div>
      {list_html}
    </div>
"""
        self._send_html(self._render_page("邮件浏览器", content), 200)

    def _render_message_page(self, query):
        if not self._request_is_authorized(query):
            self._redirect("/?error=unauthorized")
            return

        lookup_email = self._query_email_key(query)
        requested_mail_id = self._query_mail_id(query)
        if not lookup_email or not requested_mail_id:
            self._send_html("<h1>缺少 email 或 mail_id 参数</h1>", 400)
            return

        record = self._load_credential_record(lookup_email)
        if not record:
            self._send_html("<h1>未找到对应邮箱凭证</h1>", 404)
            return

        emails = self._fetch_emails(record, 1, query, response_mode="processed", mail_id=requested_mail_id, force_compact=False)
        if not emails:
            self._send_html("<h1>未找到对应邮件</h1>", 404)
            return

        email_item = emails[0]
        iframe_doc = self._message_iframe_document(email_item.get("body_html", ""), email_item.get("body", ""))
        raw_url = self._raw_email_url(lookup_email, requested_mail_id)
        api_url = self._processed_email_url(lookup_email, requested_mail_id)
        browser_url = self._browser_page_url(lookup_email, self._parse_limit(query, default=10))

        content = f"""
    <nav class="nav">
      <a href="/" class="nav-brand">Outlook Manage</a>
      <div class="actions-row">
        <a href="{html.escape(browser_url)}" class="btn btn-secondary btn-sm">返回列表</a>
        <a href="{html.escape(api_url)}" target="_blank" class="btn btn-secondary btn-sm">整理 JSON</a>
        <a href="{html.escape(raw_url)}" target="_blank" class="btn btn-secondary btn-sm">原始 JSON</a>
      </div>
    </nav>

    <div class="card">
      <h1 style="margin-bottom: 1rem;">{html.escape(email_item.get("subject") or "无标题邮件")}</h1>
      
      <div class="meta-grid">
        <div class="meta-box">
          <div class="meta-label">发件人</div>
          <div class="meta-value">{html.escape(email_item.get("from") or "")}</div>
        </div>
        <div class="meta-box">
          <div class="meta-label">收件人</div>
          <div class="meta-value">{html.escape(email_item.get("to") or "")}</div>
        </div>
        <div class="meta-box">
          <div class="meta-label">时间</div>
          <div class="meta-value">{html.escape(email_item.get("date") or "")}</div>
        </div>
        <div class="meta-box">
          <div class="meta-label">IMAP ID</div>
          <div class="meta-value">{html.escape(email_item.get("id") or "")}</div>
        </div>
      </div>
    </div>

    <div class="card" style="padding: 0; overflow: hidden;">
      <iframe sandbox="allow-popups allow-popups-to-escape-sandbox" referrerpolicy="no-referrer" srcdoc="{html.escape(iframe_doc, quote=True)}"></iframe>
    </div>
"""
        self._send_html(self._render_page(email_item.get("subject") or "邮件详情", content), 200)

    def _read_body(self):
        content_length = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(content_length) if content_length > 0 else b""

    def _parse_request_body(self, body):
        content_type = self.headers.get("Content-Type", "")
        parsed = {"_raw_text": body.decode("utf-8", errors="ignore")}

        if "application/json" in content_type:
            try:
                payload = json.loads(parsed["_raw_text"] or "{}")
                if isinstance(payload, dict):
                    parsed.update({k: str(v) for k, v in payload.items() if v is not None})
            except json.JSONDecodeError:
                pass
            return parsed

        if "application/x-www-form-urlencoded" in content_type:
            data = urllib.parse.parse_qs(parsed["_raw_text"], keep_blank_values=True)
            parsed.update({key: values[-1] for key, values in data.items()})
            return parsed

        if "multipart/form-data" in content_type:
            mime_message = (
                f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode(
                    "utf-8"
                )
                + body
            )
            message = BytesParser(policy=default).parsebytes(mime_message)
            for part in message.iter_parts():
                field_name = part.get_param("name", header="Content-Disposition")
                if not field_name:
                    continue

                payload = part.get_payload(decode=True) or b""
                filename = part.get_filename()
                if filename:
                    parsed[field_name] = {
                        "filename": filename,
                        "content": payload,
                        "content_type": part.get_content_type(),
                    }
                else:
                    charset = part.get_content_charset() or "utf-8"
                    parsed[field_name] = payload.decode(charset, errors="ignore")
            return parsed

        return parsed

    def _extract_credential_record(self, form):
        raw_text = ""
        file_field = form.get("credential_file")
        if isinstance(file_field, dict):
            raw_text = file_field.get("content", b"").decode("utf-8", errors="ignore")
        elif form.get("credential_text"):
            raw_text = form.get("credential_text", "")
        elif form.get("_raw_text"):
            raw_text = form.get("_raw_text", "")

        email_address = (form.get("email_address") or "").strip()
        client_id = (form.get("client_id") or "").strip()
        refresh_token = (form.get("refresh_token") or "").strip()

        if raw_text and (not email_address or not client_id or not refresh_token):
            parsed = self._parse_credential_line(raw_text)
            email_address = email_address or parsed["email_address"]
            client_id = client_id or parsed["client_id"]
            refresh_token = refresh_token or parsed["refresh_token"]

        if not email_address or not client_id or not refresh_token:
            raise ValueError("凭证不完整，需要邮箱、Client ID 和 Refresh Token")

        lookup_email = self._normalize_email_address(email_address)
        if not lookup_email:
            raise ValueError("无法识别完整邮箱地址，请检查 email_address")

        return {
            "lookup_email": lookup_email,
            "email_address": email_address,
            "client_id": client_id,
            "refresh_token": refresh_token,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }

    def _parse_credential_line(self, raw_text):
        line = next((item.strip() for item in raw_text.splitlines() if item.strip()), "")
        parts = [item.strip() for item in line.split("----")]
        if len(parts) < 4:
            raise ValueError("凭证格式错误，需要：邮箱----占位----ClientID----RefreshToken")

        return {
            "email_address": parts[0],
            "client_id": parts[2],
            "refresh_token": parts[3],
        }

    def _save_credential_record(self, record):
        self._ensure_storage_ready()
        pathname = self._credential_path(record["lookup_email"])
        payload = json.dumps(record, ensure_ascii=False).encode("utf-8")
        put(
            pathname,
            payload,
            access="private",
            content_type="application/json; charset=utf-8",
            overwrite=True,
            add_random_suffix=False,
            cache_control_max_age=60,
        )

    def _load_credential_record(self, lookup_email):
        self._ensure_storage_ready()
        pathname = self._credential_path(lookup_email)
        target = None
        cursor = None
        has_more = True

        while has_more:
            page = list_objects(prefix=pathname, limit=1000, cursor=cursor)
            for item in page.blobs:
                if item.pathname == pathname:
                    target = item
                    break
            if target:
                break
            has_more = page.has_more
            cursor = page.cursor

        if not target:
            return None

        content = self._download_private_blob(target.url)
        return json.loads(content.decode("utf-8"))

    def _saved_emails(self):
        if self._storage_warning():
            return []

        items = []
        cursor = None
        has_more = True
        seen = set()

        while has_more:
            page = list_objects(prefix=self.CREDENTIAL_PREFIX, limit=1000, cursor=cursor)
            for blob in page.blobs:
                lookup_email = self._email_from_path(blob.pathname)
                if lookup_email and lookup_email not in seen:
                    seen.add(lookup_email)
                    items.append(lookup_email)
            has_more = page.has_more
            cursor = page.cursor

        return sorted(items)

    def _saved_email_list_html(self, items):
        if self._storage_warning():
            return self._notice("未连接 Vercel Blob 存储。", kind="error")

        if not items:
            return '<p style="padding: 1rem; text-align: center; color: var(--text-muted);">暂无已保存的邮箱</p>'

        blocks = []
        for lookup_email in items:
            escaped_email = html.escape(lookup_email)
            processed_url = self._processed_email_url(lookup_email)
            raw_url = self._raw_email_url(lookup_email)
            browser_url = self._browser_page_url(lookup_email, 10)
            blocks.append(f"""
          <li class="saved-item">
            <div class="saved-item-header">
              <span class="saved-item-email">{escaped_email}</span>
              <div class="actions-row">
                <a class="btn btn-secondary btn-sm" href="{html.escape(browser_url)}">浏览</a>
              </div>
            </div>
            <div style="margin-top: 0.5rem;">
              <code style="display: block; font-size: 0.7rem; margin-bottom: 0.25rem;">{html.escape(processed_url)}</code>
              <code style="display: block; font-size: 0.7rem;">{html.escape(raw_url)}</code>
            </div>
          </li>
""")
        return f'<ul class="saved-list">{"".join(blocks)}</ul>'

    def _fetch_emails(
        self,
        record,
        limit,
        query,
        response_mode="processed",
        mail_id="",
        force_compact=None,
    ):
        compact = (
            self._query_flag(query, "compact", "simple")
            if force_compact is None
            else force_compact
        )
        include_raw = self._query_flag(query, "raw", "include_raw")
        access_token = self._exchange_access_token(record)
        ssl_context = ssl._create_unverified_context()
        mail = imaplib.IMAP4_SSL(self.IMAP_HOST, self.IMAP_PORT, ssl_context=ssl_context)

        try:
            auth_string = (
                f"user={record['email_address']}\x01auth=Bearer {access_token}\x01\x01"
            )
            mail.authenticate("XOAUTH2", lambda _: auth_string.encode("utf-8"))

            status, _ = mail.select("INBOX", readonly=True)
            if status != "OK":
                raise RuntimeError("无法选择 INBOX")

            status, messages = mail.search(None, "ALL")
            if status != "OK":
                raise RuntimeError("邮件搜索失败")

            mail_ids = [item for item in messages[0].split() if item]
            if mail_id:
                latest_ids = [mail_id.encode("utf-8")]
            else:
                latest_ids = list(reversed(mail_ids[-limit:]))
            results = []

            for num in latest_ids:
                status, data = mail.fetch(num, "(RFC822)")
                if status != "OK" or not data or data[0] is None:
                    continue

                raw_email = data[0][1]
                message = email.message_from_bytes(raw_email)
                raw_body_text, body_html = self._extract_message_bodies(message)
                body_text = self._preferred_body_text(raw_body_text, body_html)
                subject = self._decode_mime_header(message.get("Subject"))
                raw_from = self._decode_mime_header(message.get("From"))
                raw_to = self._decode_mime_header(message.get("To"))
                raw_cc = self._decode_mime_header(message.get("Cc"))
                from_entry = self._parse_address_header(raw_from)
                to_list = self._parse_address_list(raw_to)
                cc_list = self._parse_address_list(raw_cc)
                results.append(
                    self._build_email_item(
                        num.decode("utf-8", errors="ignore"),
                        message,
                        subject,
                        raw_from,
                        raw_to,
                        raw_cc,
                        from_entry,
                        to_list,
                        cc_list,
                        body_text,
                        raw_body_text,
                        body_html,
                        compact,
                        include_raw,
                        response_mode,
                    )
                )

            return results
        finally:
            try:
                mail.logout()
            except Exception:
                pass

    def _build_email_item(
        self,
        message_id,
        message,
        subject,
        raw_from,
        raw_to,
        raw_cc,
        from_entry,
        to_list,
        cc_list,
        body_text,
        raw_body_text,
        body_html,
        compact,
        include_raw,
        response_mode,
    ):
        if response_mode == "raw":
            return {
                "id": message_id,
                "message_id": message.get("Message-ID", ""),
                "date": message.get("Date"),
                "from": raw_from,
                "to": raw_to,
                "cc": raw_cc,
                "title": subject,
                "subject": subject,
                "body_text": raw_body_text,
                "body_html": body_html,
            }

        email_item = {
            "id": message_id,
            "message_id": message.get("Message-ID", ""),
            "date": message.get("Date"),
            "date_iso": self._date_to_iso(message.get("Date")),
            "from": raw_from,
            "from_name": from_entry["name"],
            "from_email": from_entry["email"],
            "to": raw_to,
            "to_list": to_list,
            "cc": raw_cc,
            "cc_list": cc_list,
            "title": subject,
            "subject": subject,
            "preview": self._preview_text(body_text),
            "body": body_text,
            "body_text": body_text,
            "has_html": bool(body_html),
        }

        if not compact:
            email_item["body_html"] = body_html

        if include_raw:
            email_item["body_text_raw"] = raw_body_text
            if compact:
                email_item["body_html_raw"] = body_html

        return email_item

    def _exchange_access_token(self, record):
        payload = urllib.parse.urlencode(
            {
                "client_id": record["client_id"],
                "refresh_token": record["refresh_token"],
                "grant_type": "refresh_token",
            }
        ).encode("utf-8")
        request = urllib.request.Request(self.TOKEN_URL, data=payload)
        with urllib.request.urlopen(request, timeout=30) as response:
            token_data = json.loads(response.read().decode("utf-8"))

        access_token = token_data.get("access_token")
        if not access_token:
            raise RuntimeError("没有从微软返回 access_token")
        return access_token

    def _extract_message_bodies(self, message):
        text_parts = []
        html_parts = []

        if message.is_multipart():
            for part in message.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                if part.get_content_disposition() == "attachment":
                    continue

                content_type = part.get_content_type()
                payload = part.get_payload(decode=True)
                content = self._decode_bytes(payload, part.get_content_charset())
                if not content:
                    continue

                if content_type == "text/plain":
                    text_parts.append(content)
                elif content_type == "text/html":
                    html_parts.append(content)
        else:
            payload = message.get_payload(decode=True)
            content = self._decode_bytes(payload, message.get_content_charset())
            if not content and isinstance(message.get_payload(), str):
                content = message.get_payload()

            if message.get_content_type() == "text/html":
                html_parts.append(content)
            else:
                text_parts.append(content)

        body_text = "\n\n".join(item.strip() for item in text_parts if item and item.strip())
        body_html = "\n\n".join(item.strip() for item in html_parts if item and item.strip())

        if not body_text and body_html:
            body_text = self._strip_html(body_html)

        return body_text, body_html

    def _preferred_body_text(self, raw_text, raw_html):
        html_text = self._clean_plain_text(self._strip_html(raw_html)) if raw_html else ""
        plain_text = self._clean_plain_text(raw_text)
        if html_text:
            return html_text
        return plain_text

    def _decode_mime_header(self, value):
        if not value:
            return ""

        parts = []
        for chunk, encoding in decode_header(value):
            if isinstance(chunk, bytes):
                parts.append(self._decode_bytes(chunk, encoding))
            else:
                parts.append(str(chunk))
        return "".join(parts).strip()

    def _decode_bytes(self, data, charset=None):
        if data is None:
            return ""
        if isinstance(data, str):
            return data

        charsets = [charset, "utf-8", "gb18030", "latin-1"]
        for item in charsets:
            if not item:
                continue
            try:
                return data.decode(item, errors="ignore")
            except (LookupError, UnicodeDecodeError):
                continue
        return data.decode("utf-8", errors="ignore")

    def _strip_html(self, content):
        def _anchor_to_text(match):
            href = html.unescape(match.group(1).strip())
            label = re.sub(r"<[^>]+>", "", match.group(2))
            label = html.unescape(label).strip()
            if label and label != href:
                return f"{label} ({href})"
            return href

        cleaned = re.sub(
            r"<a\b[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
            _anchor_to_text,
            content,
            flags=re.I | re.S,
        )
        cleaned = re.sub(r"<(script|style).*?>.*?</\1>", "", cleaned, flags=re.I | re.S)
        cleaned = re.sub(r"<br\s*/?>", "\n", cleaned, flags=re.I)
        cleaned = re.sub(r"</p\s*>", "\n\n", cleaned, flags=re.I)
        cleaned = re.sub(r"<[^>]+>", "", cleaned)
        cleaned = html.unescape(cleaned)
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
        return cleaned.strip()

    def _query(self):
        return urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)

    def _wants_mailbox_page(self, query):
        return (query.get("ui") or [""])[0].strip().lower() == "browser"

    def _wants_message_page(self, query):
        return (query.get("ui") or [""])[0].strip().lower() == "message"

    def _wants_email_json(self, query):
        return bool(self._query_email_key(query))

    def _query_email_key(self, query):
        candidate = (query.get("email") or [""])[0] or (query.get("suffix") or [""])[0]
        return self._normalize_email_address(candidate)

    def _query_mail_id(self, query):
        return ((query.get("mail_id") or [""])[0] or (query.get("id") or [""])[0]).strip()

    def _parse_limit(self, query, default=1):
        raw_value = (
            (query.get("limit") or [""])[0]
            or (query.get("count") or [""])[0]
            or (query.get("params") or [""])[0]
        )
        if not raw_value:
            return default

        try:
            limit = int(raw_value)
        except ValueError as exc:
            raise ValueError("limit/count/params 必须是整数") from exc

        return max(1, min(limit, self.MAX_EMAIL_LIMIT))

    def _request_is_authorized(self, query):
        password = (
            (query.get("password") or [""])[0]
            or self.headers.get("X-Admin-Password", "")
            or self.headers.get("X-Password", "")
        )
        return self._password_matches(password) or self._is_authenticated()

    def _query_flag(self, query, *names):
        truthy = {"1", "true", "yes", "on"}
        return any((query.get(name) or [""])[0].strip().lower() in truthy for name in names)

    def _parse_address_header(self, raw_value):
        decoded = self._decode_mime_header(raw_value)
        name, email_address = parseaddr(decoded)
        return {
            "name": self._decode_mime_header(name).strip(),
            "email": email_address.strip(),
        }

    def _parse_address_list(self, raw_value):
        decoded = self._decode_mime_header(raw_value)
        items = []
        for name, email_address in getaddresses([decoded]):
            if not name and not email_address:
                continue
            items.append(
                {
                    "name": self._decode_mime_header(name).strip(),
                    "email": email_address.strip(),
                }
            )
        return items

    def _date_to_iso(self, value):
        if not value:
            return ""
        try:
            parsed = parsedate_to_datetime(value)
            if parsed and parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat()
        except Exception:
            return ""

    def _preview_text(self, value, limit=200):
        value = (value or "").strip()
        if len(value) <= limit:
            return value
        return value[: limit - 3].rstrip() + "..."

    def _clean_plain_text(self, value):
        value = (value or "").replace("\r\n", "\n").replace("\r", "\n")
        filtered_lines = []
        in_css_block = False

        for raw_line in value.split("\n"):
            line = raw_line.strip()
            if not line:
                if filtered_lines and filtered_lines[-1] != "":
                    filtered_lines.append("")
                continue

            lower = line.lower()

            if in_css_block:
                if "}" in line:
                    in_css_block = False
                continue

            if self._looks_like_css_selector(line):
                in_css_block = True
                continue

            if self._looks_like_css_property(lower):
                continue

            filtered_lines.append(line)

        cleaned = "\n".join(filtered_lines)
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
        return cleaned.strip()

    def _looks_like_css_selector(self, value):
        if not value.endswith("{"):
            return False
        selector = value[:-1].strip().lower()
        if not selector:
            return False
        selector_prefixes = (
            ".",
            "#",
            "p",
            "a",
            "body",
            "div",
            "span",
            "img",
            "table",
            "td",
            "th",
            "tr",
            "h1",
            "h2",
            "h3",
            "pre",
            "ul",
            "ol",
            "li",
            "strong",
            "code",
        )
        return selector.startswith(selector_prefixes) or "," in selector

    def _looks_like_css_property(self, value):
        css_prefixes = (
            "color:",
            "font-",
            "line-height:",
            "padding:",
            "margin:",
            "border",
            "background",
            "word-break:",
            "overflow",
            "text-",
            "display:",
            "width:",
            "height:",
            "max-width:",
            "min-width:",
            "border-radius:",
            "letter-spacing:",
        )
        return value.startswith(css_prefixes)

    def _password_matches(self, submitted):
        expected = self._admin_password()
        if not expected or not submitted:
            return False
        return hmac.compare_digest(expected, submitted)

    def _admin_password(self):
        return os.getenv("APP_PASSWORD") or os.getenv("ADMIN_PASSWORD") or ""

    def _is_authenticated(self):
        expected = self._session_signature()
        if not expected:
            return False

        cookie_header = self.headers.get("Cookie", "")
        if not cookie_header:
            return False

        jar = cookies.SimpleCookie()
        jar.load(cookie_header)
        morsel = jar.get(self.SESSION_COOKIE)
        if not morsel:
            return False

        return hmac.compare_digest(morsel.value, expected)

    def _session_signature(self):
        password = self._admin_password()
        if not password:
            return ""
        return hashlib.sha256(f"outlook-manage::{password}".encode("utf-8")).hexdigest()

    def _session_cookie_value(self):
        secure = self._should_use_secure_cookie()
        parts = [
            f"{self.SESSION_COOKIE}={self._session_signature()}",
            "Path=/",
            "HttpOnly",
            "SameSite=Lax",
            "Max-Age=2592000",
        ]
        if secure:
            parts.append("Secure")
        return "; ".join(parts)

    def _expired_session_cookie(self):
        secure = self._should_use_secure_cookie()
        parts = [
            f"{self.SESSION_COOKIE}=",
            "Path=/",
            "HttpOnly",
            "SameSite=Lax",
            "Max-Age=0",
        ]
        if secure:
            parts.append("Secure")
        return "; ".join(parts)

    def _should_use_secure_cookie(self):
        proto = self.headers.get("X-Forwarded-Proto", "").lower()
        host = self.headers.get("Host", "").lower()
        return proto == "https" or ("localhost" not in host and "127.0.0.1" not in host)

    def _storage_warning(self):
        if not self._admin_password():
            return ""
        if not os.getenv("BLOB_READ_WRITE_TOKEN"):
            return self._notice(
                "当前没有检测到 BLOB_READ_WRITE_TOKEN。请先在 Vercel 里创建并连接一个 Private Blob Store，凭证保存功能才能持久化。",
                kind="error",
            )
        if put is None or list_objects is None:
            return self._notice(
                "Python 依赖还没安装好，部署前请确保 requirements.txt 已生效。",
                kind="error",
            )
        return ""

    def _ensure_storage_ready(self):
        if not os.getenv("BLOB_READ_WRITE_TOKEN"):
            raise RuntimeError("缺少 BLOB_READ_WRITE_TOKEN，请先连接 Vercel Blob 私有存储")
        if put is None or list_objects is None:
            raise RuntimeError("缺少 vercel Python SDK，请先安装 requirements.txt 中的依赖")

    def _download_private_blob(self, url):
        token = os.getenv("BLOB_READ_WRITE_TOKEN")
        request = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()

    def _credential_path(self, lookup_email):
        encoded_email = urllib.parse.quote(lookup_email, safe="")
        return f"{self.CREDENTIAL_PREFIX}{encoded_email}.json"

    def _email_from_path(self, pathname):
        if not pathname.startswith(self.CREDENTIAL_PREFIX) or not pathname.endswith(".json"):
            return ""
        encoded = pathname[len(self.CREDENTIAL_PREFIX) : -5]
        return urllib.parse.unquote(encoded)

    def _normalize_email_address(self, value):
        value = (value or "").strip().lower()
        if not value:
            return ""
        if value.count("@") != 1:
            return ""
        local, domain = value.split("@", 1)
        if not local or not domain:
            return ""
        return f"{local}@{domain}"

    def _lookup_base_url(self):
        proto = self.headers.get("X-Forwarded-Proto", "https")
        host = self.headers.get("Host", "")
        return f"{proto}://{host}/api"

    def _raw_lookup_base_url(self):
        return f"{self._lookup_base_url()}/raw"

    def _processed_email_url(self, lookup_email, mail_id=""):
        encoded_password = urllib.parse.quote(self._admin_password(), safe="") or "你的密码"
        query = f"password={encoded_password}&email={urllib.parse.quote(lookup_email, safe='')}"
        if mail_id:
            query += f"&mail_id={urllib.parse.quote(mail_id, safe='')}"
        return f"{self._lookup_base_url()}?{query}"

    def _raw_email_url(self, lookup_email, mail_id=""):
        encoded_password = urllib.parse.quote(self._admin_password(), safe="") or "你的密码"
        query = f"password={encoded_password}&email={urllib.parse.quote(lookup_email, safe='')}"
        if mail_id:
            query += f"&mail_id={urllib.parse.quote(mail_id, safe='')}"
        return f"{self._raw_lookup_base_url()}?{query}"

    def _browser_page_url(self, lookup_email, limit=10):
        query = urllib.parse.urlencode(
            {"ui": "browser", "email": lookup_email, "limit": str(limit)}
        )
        return f"/api?{query}"

    def _message_page_url(self, lookup_email, mail_id, limit=10):
        query = urllib.parse.urlencode(
            {
                "ui": "message",
                "email": lookup_email,
                "mail_id": str(mail_id),
                "limit": str(limit),
            }
        )
        return f"/api?{query}"

    def _mailbox_list_html(self, lookup_email, emails, limit):
        if not emails:
            return '<p style="padding: 3rem; text-align: center; color: var(--text-muted);">暂无邮件</p>'

        blocks = []
        for item in emails:
            subject = html.escape(item.get("subject") or "无标题邮件")
            from_value = html.escape(item.get("from") or "")
            date_value = html.escape(item.get("date") or "")
            preview = html.escape(item.get("preview") or "")
            message_url = self._message_page_url(lookup_email, item.get("id", ""), limit)
            processed_url = self._processed_email_url(lookup_email, item.get("id", ""))
            blocks.append(f"""
        <li class="mail-item">
          <a href="{html.escape(message_url)}" style="text-decoration: none; color: inherit;">
            <div class="mail-item-title">{subject}</div>
            <div class="mail-item-meta">{from_value} • {date_value}</div>
            <p class="mail-item-preview">{preview}</p>
          </a>
          <div class="actions-row" style="margin-top: 0.75rem;">
             <a class="btn btn-secondary btn-sm" style="font-size: 0.7rem; padding: 0.2rem 0.4rem;" href="{html.escape(processed_url)}" target="_blank">JSON</a>
          </div>
        </li>
""")
        return f'<ul class="mail-list">{"".join(blocks)}</ul>'

    def _message_iframe_document(self, body_html, fallback_text):
        if body_html and "<html" in body_html.lower():
            document = body_html
        else:
            html_body = (
                body_html
                if body_html
                else f"<pre>{html.escape(fallback_text or '这封邮件没有 HTML 正文')}</pre>"
            )
            document = (
                "<!doctype html><html><head><meta charset='utf-8'>"
                "<base target='_blank'>"
                "<style>body{margin:0;padding:16px;font-family:Arial,sans-serif;background:#fff;color:#111;}pre{white-space:pre-wrap;word-break:break-word;}</style>"
                f"</head><body>{html_body}</body></html>"
            )
        return document

    def _notice(self, text, kind="success"):
        safe_kind = "error" if kind == "error" else "success"
        return f'<div class="notice notice-{safe_kind}">{html.escape(text)}</div>'

    def _redirect(self, location, cookies_to_set=None):
        self.send_response(303)
        self._send_common_headers()
        self.send_header("Location", location)
        for cookie in cookies_to_set or []:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def _send_html(self, content, status_code=200):
        body = content.encode("utf-8")
        self.send_response(status_code)
        self._send_common_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, data, status_code):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self._send_common_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_common_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")

    def _stringify_error(self, exc):
        if isinstance(exc, urllib.error.HTTPError):
            try:
                detail = exc.read().decode("utf-8", errors="ignore")
                if detail:
                    return f"{exc.reason}: {detail}"
            except Exception:
                pass
            return f"{exc.code} {exc.reason}"
        return str(exc)
