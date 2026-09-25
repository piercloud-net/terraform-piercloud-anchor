#!/usr/bin/env python3
"""Mock S3 listing endpoint for tests/recording-witness (offline, cred-free).

Serves only the two list operations the witness may use:

    GET /<bucket>?list-type=2&prefix=... [&continuation-token=...]
    GET /<bucket>?uploads[&prefix=...] [&key-marker=...&upload-id-marker=...]

Every request is appended to the request log as one JSON line (method, path,
auth-header presence, a note) so the harness can prove the witness is strictly
list-only and SigV4-signs every call. Any other method (HEAD/PUT/POST/DELETE)
or any object-shaped path is recorded as a violation and rejected.

The fixture is JSON:

    {
      "bucket": "pc-admin-dr",
      "page_size": 2,                      # optional, forces pagination
      "fail": null | "list" | "all",       # list calls return HTTP 500
      "fail_objects": null | "malformed" | "error-doc" | "truncated-no-token",
      "fail_uploads": null | "malformed" | "error-doc" | "truncated-no-token",
      "signature": {                       # optional; when present every
        "key_id": "...", "key": "...", "region": "..."
      },                                   # request is SigV4-verified
      "objects": [{"key": "...", "ago": 60}],
      "uploads": [{"key": "...", "upload_id": "u1", "ago": 3600}]
    }

`ago` is seconds before serve time, so the harness never does clock math.
"""

import hashlib
import hmac
import json
import sys
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

FIXTURE = {}
REQUEST_LOG = ""
PAGE_SIZE = 1000


def xml_escape(value):
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def iso_from_ago(ago):
    moment = time.time() - float(ago)
    return datetime.fromtimestamp(moment, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # keep the harness output quiet
        pass

    def record(self, method, ok, note):
        authorization = self.headers.get("Authorization") or ""
        entry = {
            "method": method,
            "path": self.path,
            "ok": ok,
            "note": note,
            "auth": authorization.startswith("AWS4-HMAC-SHA256 Credential="),
            "signed_headers": authorization,
            "x_amz_date": bool(self.headers.get("x-amz-date")),
            "x_amz_content_sha256": bool(self.headers.get("x-amz-content-sha256")),
            "sig_check": getattr(self, "sig_status", "disabled"),
        }
        with open(REQUEST_LOG, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")

    def verify_signature(self, fixture_signature):
        """Recompute the SigV4 signature from the received request."""
        authorization = self.headers.get("Authorization") or ""
        prefix = "AWS4-HMAC-SHA256 Credential="
        if not authorization.startswith(prefix):
            return "missing SigV4 Authorization"
        try:
            credential_part, signed_part, signature_part = authorization[len(prefix):].split(", ")
            credential = credential_part.split("/")
            key_id, date, region, service = credential[0], credential[1], credential[2], credential[3]
            scope = "/".join(credential[1:])
            signed_headers = signed_part.split("=", 1)[1]
            signature = signature_part.split("=", 1)[1]
        except (IndexError, ValueError):
            return "malformed Authorization header"
        if key_id != fixture_signature["key_id"]:
            return "unexpected key id"
        target = urlsplit(self.path)
        pairs = []
        if target.query:
            for chunk in target.query.split("&"):
                name, _, value = chunk.partition("=")
                pairs.append((name, value))
        canonical_query = "&".join("%s=%s" % pair for pair in sorted(pairs))
        canonical_headers = ""
        for name in signed_headers.split(";"):
            value = self.headers.get(name)
            if value is None:
                return "signed header missing: %s" % name
            canonical_headers += "%s:%s\n" % (name, value.strip())
        payload_hash = self.headers.get("x-amz-content-sha256") or ""
        canonical_request = "\n".join(
            ["GET", target.path, canonical_query, canonical_headers, signed_headers, payload_hash]
        )
        amz_date = self.headers.get("x-amz-date") or ""
        string_to_sign = "\n".join(
            ["AWS4-HMAC-SHA256", amz_date, scope,
             hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()]
        )
        signing_key = hmac.new(
            ("AWS4" + fixture_signature["key"]).encode("utf-8"), date.encode("utf-8"), hashlib.sha256
        ).digest()
        signing_key = hmac.new(signing_key, region.encode("utf-8"), hashlib.sha256).digest()
        signing_key = hmac.new(signing_key, service.encode("utf-8"), hashlib.sha256).digest()
        signing_key = hmac.new(signing_key, b"aws4_request", hashlib.sha256).digest()
        expected = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return "signature mismatch"
        return ""

    def send_body(self, status, body):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def reject(self, method):
        self.record(method, False, "non-list method - the witness must be list-only")
        self.send_body(400, "<Error><Code>ListOnly</Code></Error>")

    def do_HEAD(self):
        self.reject("HEAD")

    def do_PUT(self):
        self.reject("PUT")

    def do_POST(self):
        self.reject("POST")

    def do_DELETE(self):
        self.reject("DELETE")

    def do_GET(self):
        self.sig_status = "disabled"
        parts = urlsplit(self.path)
        query = parse_qs(parts.query, keep_blank_values=True)
        expected_path = "/" + FIXTURE.get("bucket", "pc-admin-dr")
        if parts.path != expected_path:
            self.record("GET", False, "object-shaped path - the witness must never GET an object")
            self.send_body(400, "<Error><Code>UnexpectedPath</Code></Error>")
            return
        fixture_signature = FIXTURE.get("signature")
        if fixture_signature:
            problem = self.verify_signature(fixture_signature)
            self.sig_status = "failed: %s" % problem if problem else "ok"
            if problem:
                self.record("GET", False, "SigV4 verification failed: %s" % problem)
                self.send_body(403, "<Error><Code>SignatureDoesNotMatch</Code></Error>")
                return
        if FIXTURE.get("fail") in ("list", "all"):
            self.record("GET", False, "fixture failure mode")
            self.send_body(500, "<Error><Code>InternalError</Code></Error>")
            return
        kind = "objects" if query.get("list-type") == ["2"] else ("uploads" if "uploads" in query else "")
        failure = FIXTURE.get("fail_%s" % kind, "") if kind else ""
        if failure == "malformed":
            self.record("GET", False, "fixture: malformed XML")
            self.send_body(200, "this is not XML <<<")
            return
        if failure == "error-doc":
            self.record("GET", False, "fixture: error document")
            self.send_body(403, "<Error><Code>AccessDenied</Code><Message>denied</Message></Error>")
            return
        if kind == "objects":
            self.handle_objects(query)
        elif kind == "uploads":
            self.handle_uploads(query)
        else:
            self.record("GET", False, "not a list operation")
            self.send_body(400, "<Error><Code>NotListOperation</Code></Error>")

    def handle_objects(self, query):
        prefix = query.get("prefix", [""])[0]
        token = query.get("continuation-token", [""])[0]
        offset = int(token) if token.isdigit() else 0
        matching = sorted(
            (obj for obj in FIXTURE.get("objects", []) if obj["key"].startswith(prefix)),
            key=lambda obj: obj["key"],
        )
        suppress_token = FIXTURE.get("fail_objects") == "truncated-no-token"
        page = matching[offset:offset + PAGE_SIZE]
        next_offset = offset + PAGE_SIZE
        truncated = suppress_token or next_offset < len(matching)
        next_token = ""
        if truncated and not suppress_token:
            next_token = "<NextContinuationToken>%d</NextContinuationToken>" % next_offset
        rows = "".join(
            "<Contents><Key>%s</Key><LastModified>%s</LastModified>"
            "<ETag>&quot;mock&quot;</ETag><Size>1</Size>"
            "<StorageClass>STANDARD</StorageClass></Contents>"
            % (xml_escape(obj["key"]), iso_from_ago(obj["ago"]))
            for obj in page
        )
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            "<Name>%s</Name><Prefix>%s</Prefix><KeyCount>%d</KeyCount>"
            "<MaxKeys>%d</MaxKeys><IsTruncated>%s</IsTruncated>%s%s</ListBucketResult>"
            % (
                xml_escape(FIXTURE.get("bucket", "")),
                xml_escape(prefix),
                len(page),
                PAGE_SIZE,
                "true" if truncated else "false",
                next_token,
                rows,
            )
        )
        self.record("GET", True, "list-type=2 prefix=%s" % prefix)
        self.send_body(200, body)

    def handle_uploads(self, query):
        prefix = query.get("prefix", [""])[0]
        key_marker = query.get("key-marker", [""])[0]
        upload_marker = query.get("upload-id-marker", [""])[0]
        matching = sorted(
            (upload for upload in FIXTURE.get("uploads", []) if upload["key"].startswith(prefix)),
            key=lambda upload: (upload["key"], upload.get("upload_id", "u")),
        )
        if FIXTURE.get("fail_uploads") == "truncated-no-token":
            page = matching[:PAGE_SIZE]
            truncated = True
            next_key = ""
            next_upload = ""
        else:
            start = 0
            if key_marker or upload_marker:
                marker = (key_marker, upload_marker)
                start = next(
                    (index for index, upload in enumerate(matching)
                     if (upload["key"], upload.get("upload_id", "u")) > marker),
                    len(matching),
                )
            page = matching[start:start + PAGE_SIZE]
            truncated = start + PAGE_SIZE < len(matching)
            next_key = page[-1]["key"] if truncated else ""
            next_upload = page[-1].get("upload_id", "u") if truncated else ""
        rows = "".join(
            "<Upload><Key>%s</Key><UploadId>%s</UploadId><Initiated>%s</Initiated></Upload>"
            % (xml_escape(upload["key"]), xml_escape(upload.get("upload_id", "u")), iso_from_ago(upload["ago"]))
            for upload in page
        )
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            "<Bucket>%s</Bucket><KeyMarker></KeyMarker><UploadIdMarker></UploadIdMarker>"
            "<NextKeyMarker>%s</NextKeyMarker><NextUploadIdMarker>%s</NextUploadIdMarker>"
            "<MaxUploads>%d</MaxUploads><IsTruncated>%s</IsTruncated>%s"
            "</ListMultipartUploadsResult>"
            % (
                xml_escape(FIXTURE.get("bucket", "")),
                xml_escape(next_key),
                xml_escape(next_upload),
                PAGE_SIZE,
                "true" if truncated else "false",
                rows,
            )
        )
        self.record("GET", True, "uploads prefix=%s" % prefix)
        self.send_body(200, body)


def main():
    global FIXTURE, REQUEST_LOG, PAGE_SIZE
    fixture_path, port_path, request_log = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(fixture_path, "r", encoding="utf-8") as handle:
        FIXTURE = json.load(handle)
    REQUEST_LOG = request_log
    PAGE_SIZE = int(FIXTURE.get("page_size", 1000))
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    with open(port_path, "w", encoding="utf-8") as handle:
        handle.write(str(server.server_address[1]))
    server.serve_forever()


if __name__ == "__main__":
    main()
