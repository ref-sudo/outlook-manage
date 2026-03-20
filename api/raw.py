from .index import handler as BaseHandler


class handler(BaseHandler):
    def do_GET(self):
        try:
            query = self._query()
            self._handle_email_lookup(query, response_mode="raw")
        except Exception as exc:
            self._send_json(
                {"error": "请求处理失败", "details": self._stringify_error(exc)},
                500,
            )
