import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse


HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8080"))
MAX_REQUEST_BYTES = 1_000_000


class EmailAnalysisHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/health":
            self.send_json_response(200, {"status": "ok"})
            return

        self.send_json_response(404, {"error": "Not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/analyze":
            self.send_json_response(404, {"error": "Not found"})
            return

        try:
            payload = self.read_json_body()
        except ValueError as error:
            self.send_json_response(400, {"error": str(error)})
            return

        response = analyze_email_payload(payload)
        self.send_json_response(200, response)

    def read_json_body(self) -> dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0:
            raise ValueError("Request body is required.")
        if content_length > MAX_REQUEST_BYTES:
            raise ValueError("Request body is too large.")

        raw_body = self.rfile.read(content_length)
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError as error:
            raise ValueError("Request body must be valid JSON.") from error

        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object.")

        return payload

    def send_json_response(self, status_code: int, payload: dict[str, Any]) -> None:
        response_body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, format: str, *args: Any) -> None:
        return


def analyze_email_payload(payload: dict[str, Any]) -> dict[str, Any]:
    subject, sender, body, attachments = extract_email_data(payload)

    return {
        "status": "ok",
        "score": 0,
        "verdict": "not_analyzed",
        "reasoning": "Email data was received successfully. Scoring logic will be added next.",
        "received": {
            "subject": subject,
            "sender": sender,
            "bodyLength": len(body),
            "attachmentCount": len(attachments),
            "attachments": attachments,
        },
    }


def extract_email_data(payload: dict[str, Any]) -> tuple[str, str, str, list[dict[str, Any]]]:
    subject = to_text(payload.get("subject"))
    sender = to_text(payload.get("sender"))
    body = to_text(payload.get("body"))
    attachments = normalize_attachments(payload.get("attachments"))

    return subject, sender, body, attachments


def normalize_attachments(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    attachments = []
    for item in value:
        if not isinstance(item, dict):
            continue

        attachments.append(
            {
                "name": to_text(item.get("name")),
                "contentType": to_text(item.get("contentType")),
                "size": to_int(item.get("size")),
            }
        )

    return attachments


def to_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def to_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def run_server() -> None:
    server = ThreadingHTTPServer((HOST, PORT), EmailAnalysisHandler)
    print(f"Server listening on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
