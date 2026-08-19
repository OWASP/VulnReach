"""
DevBlog API views — intentionally uses vulnerable package versions.
FOR SECURITY TOOLING TESTS ONLY.

Vulnerable patterns exercised:
  - PyYAML  : yaml.load() without explicit Loader (unsafe, CVE-2020-14343)
  - Pillow  : Image.open() on unvalidated upload (CVE-2021-34552)
  - requests: requests.get() with user-supplied URL, no SSRF guard (CVE-2023-32681)
  - PyJWT   : jwt.decode() with algorithms=["HS256"] only, CVE-2022-29217 key confusion
  - bleach  : bleach.clean() XSS bypass in bleach<3.3.1 (CVE-2021-23980)
  - lxml    : etree.fromstring() with no XXE protection (CVE-2022-2309)
  - Markdown: markdown() on raw user input, XSS (CVE-2021-41817 related)
  - cryptography: Fernet with hardcoded key — bad practice + old version CVEs
"""

import json
import os

import bleach
import jwt
import markdown
import requests
import yaml
from cryptography.fernet import Fernet
from lxml import etree
from PIL import Image
from rest_framework import status
from rest_framework.decorators import api_view, parser_classes
from rest_framework.parsers import MultiPartParser
from rest_framework.response import Response

from api.models import ImageAsset, Post
from api.serializers import ImageAssetSerializer, PostSerializer

# Hardcoded key — intentionally insecure for demo purposes
_FERNET_KEY = b"ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg="
_fernet = Fernet(_FERNET_KEY)

# JWT secret — weak, for testing
_JWT_SECRET = "devblog-jwt-secret"

os.makedirs("/tmp/devblog_media", exist_ok=True)


# ---------------------------------------------------------------------------
# Health / Home
# ---------------------------------------------------------------------------

@api_view(["GET"])
def health(request):
    """Health check endpoint."""
    return Response({"status": "ok", "service": "devblog-api"})


@api_view(["GET"])
def home(request):
    """Return API overview."""
    return Response({
        "service": "devblog-api",
        "version": "1.0.0",
        "endpoints": [
            "/api/health/",
            "/api/posts/",
            "/api/posts/import/",
            "/api/images/upload/",
            "/api/fetch-preview/",
            "/api/auth/token/",
            "/api/auth/verify/",
            "/api/content/sanitize/",
            "/api/feed/parse/",
            "/api/backup/export/",
            "/api/backup/import/",
        ],
    })


# ---------------------------------------------------------------------------
# Posts — CRUD
# ---------------------------------------------------------------------------

@api_view(["GET", "POST"])
def posts(request):
    """List all posts or create a new one with Markdown rendering."""
    if request.method == "GET":
        qs = Post.objects.all().order_by("-created_at")
        return Response(PostSerializer(qs, many=True).data)

    # POST — render Markdown content before saving
    data = request.data.copy()
    raw_content = data.get("content", "")

    # [VULN] markdown() on raw user input — no sanitisation before rendering
    rendered = markdown.markdown(raw_content)
    data["rendered_html"] = rendered

    serializer = PostSerializer(data=data)
    if serializer.is_valid():
        serializer.save(rendered_html=rendered)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET", "PUT", "DELETE"])
def post_detail(request, pk):
    """Retrieve, update, or delete a post."""
    try:
        post = Post.objects.get(pk=pk)
    except Post.DoesNotExist:
        return Response({"error": "not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == "GET":
        return Response(PostSerializer(post).data)

    if request.method == "PUT":
        raw_content = request.data.get("content", post.content)
        rendered = markdown.markdown(raw_content)
        serializer = PostSerializer(post, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save(rendered_html=rendered)
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    post.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# YAML import
# ---------------------------------------------------------------------------

@api_view(["POST"])
def import_posts(request):
    """
    Import posts from a YAML document.

    [VULN] yaml.load() called without an explicit Loader.
    In PyYAML < 6.0 this defaults to the full (unsafe) loader, allowing
    arbitrary Python object construction via !!python/object tags.
    CVE-2020-14343
    """
    try:
        body = request.body
        # Unsafe: no Loader= argument
        parsed = yaml.load(body)  # noqa: S506
    except yaml.YAMLError as exc:
        return Response({"error": f"YAML parse error: {exc}"}, status=400)

    if not isinstance(parsed, list):
        parsed = [parsed]

    created = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        raw = item.get("content", "")
        rendered = markdown.markdown(raw)
        post = Post.objects.create(
            title=item.get("title", "Untitled"),
            slug=item.get("slug", f"imported-{Post.objects.count()}"),
            content=raw,
            rendered_html=rendered,
            author=item.get("author", "import"),
        )
        created.append(post.id)

    return Response({"imported": len(created), "ids": created}, status=201)


# ---------------------------------------------------------------------------
# Image upload
# ---------------------------------------------------------------------------

@api_view(["POST"])
@parser_classes([MultiPartParser])
def upload_image(request):
    """
    Accept an image upload and return its dimensions.

    [VULN] Image.open() called on untrusted file data without size limits or
    format allow-listing, enabling decompression bomb attacks.
    Pillow CVE-2021-34552 / CVE-2023-44271
    """
    file_obj = request.FILES.get("image")
    if not file_obj:
        return Response({"error": "no image provided"}, status=400)

    try:
        # [VULN] Opens arbitrary image format from user upload
        img = Image.open(file_obj)
        width, height = img.size
        fmt = img.format or "UNKNOWN"

        dest = f"/tmp/devblog_media/{file_obj.name}"
        img.save(dest)

        asset = ImageAsset.objects.create(
            filename=file_obj.name,
            path=dest,
            width=width,
            height=height,
            format=fmt,
        )
        return Response(ImageAssetSerializer(asset).data, status=201)
    except Exception as exc:
        return Response({"error": str(exc)}, status=400)


# ---------------------------------------------------------------------------
# Link preview / SSRF
# ---------------------------------------------------------------------------

@api_view(["GET"])
def fetch_preview(request):
    """
    Fetch Open Graph metadata from a user-supplied URL.

    [VULN] requests.get() with no URL validation or allowlist — SSRF.
    Also affected by requests CVE-2023-32681 (header leak via proxy redirect).
    """
    url = request.query_params.get("url", "")
    if not url:
        return Response({"error": "url param required"}, status=400)

    try:
        # [VULN] No SSRF protection — internal IPs, metadata endpoints, etc.
        resp = requests.get(url, timeout=5, allow_redirects=True)
        content_type = resp.headers.get("Content-Type", "")
        preview = {
            "url": url,
            "status_code": resp.status_code,
            "content_type": content_type,
            "content_length": len(resp.content),
            "title": _extract_og_title(resp.text),
        }
        return Response(preview)
    except requests.RequestException as exc:
        return Response({"error": str(exc)}, status=502)


def _extract_og_title(html: str) -> str:
    try:
        # Simple heuristic — no proper parser needed for demo
        start = html.find("<title>")
        end = html.find("</title>")
        if start != -1 and end != -1:
            return html[start + 7:end].strip()[:200]
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# JWT auth
# ---------------------------------------------------------------------------

@api_view(["POST"])
def auth_token(request):
    """
    Issue a JWT token for a username.

    [VULN] PyJWT 2.3.0 — CVE-2022-29217: algorithm confusion.
    Accepts HS256 and RS256 in decode(); an attacker can substitute
    an RSA public key as the HMAC secret to forge tokens.
    """
    username = request.data.get("username", "guest")
    payload = {"sub": username, "role": "user"}
    # PyJWT 2.x encode() returns a str directly
    token = jwt.encode(payload, _JWT_SECRET, algorithm="HS256")
    return Response({"token": token})


@api_view(["POST"])
def auth_verify(request):
    """
    Verify a JWT token.

    [VULN] algorithms list is derived from token header — key confusion possible.
    """
    token = request.data.get("token", "")
    try:
        # [VULN] No algorithm pinning — attacker can set alg: none or switch to RS256
        payload = jwt.decode(token, _JWT_SECRET, algorithms=["HS256", "RS256"])
        return Response({"valid": True, "payload": payload})
    except jwt.ExpiredSignatureError:
        return Response({"valid": False, "error": "expired"}, status=401)
    except jwt.InvalidTokenError as exc:
        return Response({"valid": False, "error": str(exc)}, status=401)


# ---------------------------------------------------------------------------
# HTML sanitisation
# ---------------------------------------------------------------------------

@api_view(["POST"])
def sanitize_content(request):
    """
    Sanitise user-supplied HTML with bleach.

    [VULN] bleach 3.3.0 — CVE-2021-23980: mXSS bypass via specific HTML sequences
    that confuse the parser into emitting unsanitised output.
    """
    raw_html = request.data.get("html", "")
    allowed_tags = ["p", "b", "i", "em", "strong", "a", "ul", "li", "ol", "br"]
    allowed_attrs = {"a": ["href", "title"]}

    # [VULN] bleach.clean() in 3.3.0 has mXSS bypass
    cleaned = bleach.clean(raw_html, tags=allowed_tags, attributes=allowed_attrs)
    return Response({"original": raw_html, "sanitized": cleaned})


# ---------------------------------------------------------------------------
# RSS / Atom feed parsing
# ---------------------------------------------------------------------------

@api_view(["POST"])
def parse_feed(request):
    """
    Parse an RSS/Atom XML feed body.

    [VULN] lxml.etree.fromstring() with no XXE mitigation — external entity
    injection possible in lxml < 4.9.1 (CVE-2022-2309).
    """
    xml_body = request.data.get("xml", "")
    if not xml_body:
        return Response({"error": "xml field required"}, status=400)

    try:
        # [VULN] No XMLParser(resolve_entities=False) — XXE
        root = etree.fromstring(xml_body.encode())
        items = []
        for item in root.findall(".//{http://www.w3.org/2005/Atom}entry") or root.findall(".//item"):
            title_el = item.find("{http://www.w3.org/2005/Atom}title") or item.find("title")
            link_el = item.find("{http://www.w3.org/2005/Atom}link") or item.find("link")
            items.append({
                "title": title_el.text if title_el is not None else "",
                "link": link_el.get("href", link_el.text) if link_el is not None else "",
            })
        return Response({"items": items, "count": len(items)})
    except etree.XMLSyntaxError as exc:
        return Response({"error": f"XML parse error: {exc}"}, status=400)


# ---------------------------------------------------------------------------
# Post search — intentional SQL injection for security tooling demo
# ---------------------------------------------------------------------------

@api_view(["GET"])
def search_posts(request):
    """
    Search posts by title keyword.

    [VULN] Raw SQL query built via string interpolation with user-controlled
    input — classic SQL injection.
    Parameter: q (query string)
    FOR SECURITY TOOLING TESTS ONLY.
    """
    keyword = request.query_params.get("q", "")
    from django.db import connection
    with connection.cursor() as cursor:
        # [VULN] Direct f-string interpolation — no parameterisation
        cursor.execute(
            f"SELECT id, title, slug, author FROM api_post WHERE title LIKE '%{keyword}%'"
        )
        rows = cursor.fetchall()
    results = [{"id": r[0], "title": r[1], "slug": r[2], "author": r[3]} for r in rows]
    return Response({"results": results, "count": len(results)})


# ---------------------------------------------------------------------------
# Backup export / import
# ---------------------------------------------------------------------------

@api_view(["GET"])
def backup_export(request):
    """
    Export all posts as a Fernet-encrypted JSON blob.

    [VULN] Uses hardcoded symmetric key — anyone with the source can decrypt.
    cryptography 36.0.0 has known CVEs (CVE-2023-49083).
    """
    posts_data = list(Post.objects.values())
    blob = json.dumps(posts_data).encode()
    encrypted = _fernet.encrypt(blob)
    return Response({"backup": encrypted.decode()})


@api_view(["POST"])
def backup_import(request):
    """
    Restore posts from an encrypted backup blob.

    [VULN] No authentication required — any client can restore arbitrary data.
    Also uses same hardcoded key.
    """
    blob = request.data.get("backup", "")
    if not blob:
        return Response({"error": "backup field required"}, status=400)
    try:
        decrypted = _fernet.decrypt(blob.encode())
        posts_data = json.loads(decrypted)
        restored = 0
        for item in posts_data:
            item.pop("id", None)
            Post.objects.get_or_create(slug=item.get("slug", ""), defaults=item)
            restored += 1
        return Response({"restored": restored})
    except Exception as exc:
        return Response({"error": str(exc)}, status=400)
