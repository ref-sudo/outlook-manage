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

    def _handle_email_lookup(self, query):
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

        limit = self._parse_limit(query)
        emails = self._fetch_latest_emails(record, limit, query)
        self._send_json(
            {
                "success": True,
                "email": lookup_email,
                "email_address": record["email_address"],
                "requested_limit": limit,
                "returned": len(emails),
                "compact": self._query_flag(query, "compact", "simple"),
                "emails": emails,
            },
            200,
        )

    def _render_login_page(self, query):
        password_missing = not self._admin_password()
        storage_warning = self._storage_warning()
        error = (query.get("error") or [""])[0]
        saved = urllib.parse.unquote((query.get("saved") or [""])[0]).strip()

        message_html = ""
        if error == "login_failed":
            message_html = self._notice("密码不正确，请重新登录。", kind="error")
        elif error == "unauthorized":
            message_html = self._notice("请先登录后再保存凭证。", kind="error")
        elif password_missing:
            message_html = self._notice(
                "还没有配置 APP_PASSWORD 或 ADMIN_PASSWORD，先到 Vercel 环境变量里补上。",
                kind="error",
            )
        elif saved:
            message_html = self._notice(
                f"邮箱 {html.escape(saved)} 的凭证已保存。", kind="success"
            )

        page = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Outlook 凭证管理</title>
  <style>
    :root {{
      --bg: #f5efe4;
      --panel: rgba(255,255,255,0.88);
      --ink: #1d2733;
      --muted: #5c6876;
      --accent: #d9653b;
      --accent-deep: #9f3c18;
      --line: rgba(29,39,51,0.12);
      --success: #1f7a52;
      --error: #b33a3a;
      --shadow: 0 22px 60px rgba(40, 31, 16, 0.12);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      font-family: "Avenir Next", "PingFang SC", "Microsoft YaHei", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(217, 101, 59, 0.22), transparent 28%),
        radial-gradient(circle at right 20%, rgba(37, 104, 184, 0.14), transparent 24%),
        linear-gradient(135deg, #f7f1e5, #efe6d4 45%, #f6f3eb);
      display: grid;
      place-items: center;
      padding: 24px;
    }}
    .panel {{
      width: min(520px, 100%);
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 24px;
      box-shadow: var(--shadow);
      padding: 30px;
      backdrop-filter: blur(14px);
    }}
    .eyebrow {{
      display: inline-block;
      font-size: 12px;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: var(--accent-deep);
      margin-bottom: 12px;
    }}
    h1 {{
      margin: 0 0 12px;
      font-size: clamp(28px, 4vw, 40px);
      line-height: 1.05;
    }}
    p {{
      margin: 0 0 18px;
      color: var(--muted);
      line-height: 1.7;
    }}
    label {{
      display: block;
      font-weight: 600;
      margin-bottom: 8px;
    }}
    input {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 14px 16px;
      font-size: 15px;
      background: rgba(255,255,255,0.92);
    }}
    button {{
      width: 100%;
      border: 0;
      border-radius: 14px;
      padding: 14px 16px;
      font-size: 15px;
      font-weight: 700;
      color: white;
      background: linear-gradient(135deg, var(--accent), var(--accent-deep));
      cursor: pointer;
      margin-top: 14px;
    }}
    .notice {{
      border-radius: 14px;
      padding: 12px 14px;
      margin-bottom: 18px;
      font-size: 14px;
    }}
    .notice.error {{
      background: rgba(179, 58, 58, 0.1);
      color: var(--error);
    }}
    .notice.success {{
      background: rgba(31, 122, 82, 0.1);
      color: var(--success);
    }}
    .tip {{
      margin-top: 18px;
      padding-top: 18px;
      border-top: 1px solid var(--line);
      font-size: 14px;
    }}
    code {{
      background: rgba(29,39,51,0.06);
      padding: 2px 6px;
      border-radius: 8px;
      word-break: break-all;
    }}
  </style>
</head>
<body>
  <main class="panel">
    <div class="eyebrow">Outlook Manage</div>
    <h1>登录后保存邮箱凭证</h1>
    <p>登录使用你在 Vercel 环境变量里设置的密码。登录成功后可以上传或粘贴邮件凭证，系统会按完整邮箱保存，后续可直接通过 URL 查询该邮箱的完整邮件内容。</p>
    {message_html}
    {storage_warning}
    <form method="post" action="/api">
      <input type="hidden" name="action" value="login">
      <label for="password">登录密码</label>
      <input id="password" name="password" type="password" placeholder="输入 APP_PASSWORD 或 ADMIN_PASSWORD" required>
      <button type="submit">进入管理页</button>
    </form>
    <div class="tip">
      <p>部署前至少需要两个配置：</p>
      <p><code>APP_PASSWORD</code> 或 <code>ADMIN_PASSWORD</code></p>
      <p><code>BLOB_READ_WRITE_TOKEN</code>（把 Vercel Blob 私有存储连到项目后会自动生成）</p>
    </div>
  </main>
</body>
</html>"""

        self._send_html(page, 200)

    def _render_dashboard(self, query):
        saved_email = urllib.parse.unquote((query.get("saved") or [""])[0]).strip()
        error = (query.get("error") or [""])[0]
        notices = []

        if saved_email:
            notices.append(
                self._notice(
                    f"凭证保存成功，当前邮箱：{html.escape(saved_email)}。",
                    kind="success",
                )
            )

        if error == "storage":
            notices.append(
                self._notice("当前未配置 Blob 存储，无法保存凭证。", kind="error")
            )

        storage_warning = self._storage_warning()
        saved_items = self._saved_emails()
        list_html = self._saved_email_list_html(saved_items)
        base_lookup_url = self._lookup_base_url()
        display_password = self._admin_password() or "未配置"
        encoded_password = urllib.parse.quote(self._admin_password(), safe="") or "你的密码"

        page = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Outlook 凭证管理台</title>
  <style>
    :root {{
      --bg: #f3efe7;
      --panel: rgba(255,255,255,0.86);
      --panel-strong: rgba(255,255,255,0.95);
      --ink: #1c2430;
      --muted: #5b6672;
      --accent: #cd5a2a;
      --accent-dark: #8f3414;
      --line: rgba(28, 36, 48, 0.12);
      --shadow: 0 26px 80px rgba(41, 31, 18, 0.12);
      --success: #1f7a52;
      --error: #b33a3a;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Avenir Next", "PingFang SC", "Microsoft YaHei", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(205, 90, 42, 0.24), transparent 22%),
        radial-gradient(circle at right top, rgba(23, 104, 168, 0.12), transparent 18%),
        linear-gradient(180deg, #f6f0e3, #f0e8d8 48%, #f8f6f2);
      min-height: 100vh;
      padding: 28px 18px 40px;
    }}
    .shell {{
      width: min(1120px, 100%);
      margin: 0 auto;
    }}
    .hero {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 28px;
      box-shadow: var(--shadow);
      padding: 26px;
      backdrop-filter: blur(16px);
      margin-bottom: 20px;
    }}
    .eyebrow {{
      font-size: 12px;
      letter-spacing: 0.16em;
      text-transform: uppercase;
      color: var(--accent-dark);
    }}
    h1 {{
      margin: 10px 0 12px;
      font-size: clamp(30px, 5vw, 52px);
      line-height: 1.02;
    }}
    .lead {{
      margin: 0;
      color: var(--muted);
      line-height: 1.75;
      max-width: 780px;
    }}
    .hero-actions {{
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-top: 18px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 18px;
      align-items: start;
    }}
    .card {{
      background: var(--panel-strong);
      border: 1px solid var(--line);
      border-radius: 24px;
      box-shadow: var(--shadow);
      padding: 22px;
    }}
    h2 {{
      margin: 0 0 12px;
      font-size: 22px;
    }}
    p {{
      margin: 0 0 14px;
      color: var(--muted);
      line-height: 1.7;
    }}
    label {{
      display: block;
      font-size: 14px;
      font-weight: 700;
      margin-bottom: 8px;
    }}
    input, textarea {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 13px 14px;
      font-size: 15px;
      background: rgba(255,255,255,0.95);
      margin-bottom: 14px;
    }}
    textarea {{
      min-height: 120px;
      resize: vertical;
    }}
    button {{
      border: 0;
      border-radius: 14px;
      padding: 13px 18px;
      font-size: 15px;
      font-weight: 700;
      cursor: pointer;
    }}
    .primary {{
      color: #fff;
      background: linear-gradient(135deg, var(--accent), var(--accent-dark));
    }}
    .ghost {{
      color: var(--ink);
      background: rgba(28,36,48,0.06);
    }}
    .notice {{
      border-radius: 14px;
      padding: 12px 14px;
      margin-bottom: 16px;
      font-size: 14px;
    }}
    .notice.error {{
      background: rgba(179, 58, 58, 0.1);
      color: var(--error);
    }}
    .notice.success {{
      background: rgba(31, 122, 82, 0.1);
      color: var(--success);
    }}
    .saved-list {{
      display: grid;
      gap: 12px;
      margin: 0;
      padding: 0;
      list-style: none;
    }}
    .saved-item {{
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 14px;
      background: rgba(243,239,231,0.72);
    }}
    code {{
      display: block;
      margin-top: 8px;
      padding: 10px 12px;
      border-radius: 12px;
      background: rgba(28,36,48,0.06);
      overflow-x: auto;
      word-break: break-all;
      font-size: 13px;
    }}
    .small {{
      font-size: 13px;
      color: var(--muted);
    }}
    @media (max-width: 720px) {{
      .hero, .card {{
        border-radius: 20px;
      }}
    }}
  </style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <div class="eyebrow">Outlook Manage Console</div>
      <h1>上传凭证后，直接按完整邮箱取信</h1>
      <p class="lead">保存格式兼容你现在已有的文本凭证：<code style="display:inline; margin:0; padding:2px 6px;">邮箱----占位----ClientID----RefreshToken</code>。保存后即可用 <code style="display:inline; margin:0; padding:2px 6px;">email</code> 参数传完整邮箱查询最新邮件，默认 1 封，也支持 <code style="display:inline; margin:0; padding:2px 6px;">limit</code>、<code style="display:inline; margin:0; padding:2px 6px;">count</code> 或 <code style="display:inline; margin:0; padding:2px 6px;">params</code> 查看多封。</p>
      {''.join(notices)}
      {storage_warning}
      <div class="hero-actions">
        <form method="post" action="/api">
          <input type="hidden" name="action" value="logout">
          <button class="ghost" type="submit">退出登录</button>
        </form>
      </div>
    </section>

    <section class="grid">
      <div class="card">
        <h2>保存邮件凭证</h2>
        <p>你可以上传 `.txt` 凭证文件，也可以直接粘贴原始内容。如果上传文件和文本都存在，优先使用上传文件。</p>
        <form method="post" action="/api" enctype="multipart/form-data">
          <input type="hidden" name="action" value="save">

          <label for="credential_file">上传凭证文件</label>
          <input id="credential_file" name="credential_file" type="file" accept=".txt,.text">

          <label for="credential_text">或粘贴原始凭证文本</label>
          <textarea id="credential_text" name="credential_text" placeholder="邮箱----占位----ClientID----RefreshToken"></textarea>

          <label for="email_address">完整邮箱地址（可选，留空时从原始凭证解析）</label>
          <input id="email_address" name="email_address" type="text" placeholder="name@outlook.com">

          <label for="client_id">Client ID（可选）</label>
          <input id="client_id" name="client_id" type="text" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx">

          <label for="refresh_token">Refresh Token（可选）</label>
          <textarea id="refresh_token" name="refresh_token" placeholder="如果你不想上传文件，也可以直接填在这里"></textarea>

          <button class="primary" type="submit">保存凭证</button>
        </form>
        <p class="small">同一个完整邮箱再次保存会覆盖旧凭证。凭证会写入 Vercel Blob 私有存储，不暴露在公开 URL 上。</p>
      </div>

      <div class="card">
        <h2>已保存邮箱</h2>
        <p>这里显示当前已经保存过的完整邮箱。查询邮件时直接把完整邮箱带到 URL 里即可。</p>
        {list_html}
      </div>

      <div class="card">
        <h2>调用方式</h2>
        <p>当前查询密码：</p>
        <code>{html.escape(display_password)}</code>
        <p>默认返回最新 1 封完整邮件，JSON 中包含标题、主题、发件人、收件人、纯文本正文和 HTML 正文。</p>
        <code>{html.escape(base_lookup_url)}?password={html.escape(encoded_password)}&amp;email=name@outlook.com</code>
        <p>如果要多取几封，补一个数量参数即可：</p>
        <code>{html.escape(base_lookup_url)}?password={html.escape(encoded_password)}&amp;email=name@outlook.com&amp;limit=5</code>
        <p class="small">出于你的需求我保留了 URL 密码方式，同时也支持登录后的 cookie 访问。若后面你想更安全一点，我们可以再改成 Header 或签名 token。</p>
      </div>
    </section>
  </div>
</body>
</html>"""

        self._send_html(page, 200)

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
            return self._notice(
                "还没连上 Vercel Blob 私有存储，先配置好以后这里才会出现邮箱列表。",
                kind="error",
            )

        if not items:
            return "<p>还没有保存任何凭证。</p>"

        blocks = []
        encoded_password = urllib.parse.quote(self._admin_password(), safe="") or "你的密码"
        for lookup_email in items:
            escaped_email = html.escape(lookup_email)
            url = f"{self._lookup_base_url()}?password={encoded_password}&email={urllib.parse.quote(lookup_email, safe='')}"
            blocks.append(
                f'<li class="saved-item"><strong>{escaped_email}</strong><code>{html.escape(url)}</code></li>'
            )
        return f'<ul class="saved-list">{"".join(blocks)}</ul>'

    def _fetch_latest_emails(self, record, limit, query):
        compact = self._query_flag(query, "compact", "simple")
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

                email_item = {
                    "id": num.decode("utf-8", errors="ignore"),
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

                results.append(email_item)

            return results
        finally:
            try:
                mail.logout()
            except Exception:
                pass

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

    def _wants_email_json(self, query):
        return bool(self._query_email_key(query))

    def _query_email_key(self, query):
        candidate = (query.get("email") or [""])[0] or (query.get("suffix") or [""])[0]
        return self._normalize_email_address(candidate)

    def _parse_limit(self, query):
        raw_value = (
            (query.get("limit") or [""])[0]
            or (query.get("count") or [""])[0]
            or (query.get("params") or [""])[0]
        )
        if not raw_value:
            return 1

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

    def _notice(self, text, kind="success"):
        safe_kind = "error" if kind == "error" else "success"
        return f'<div class="notice {safe_kind}">{html.escape(text)}</div>'

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
