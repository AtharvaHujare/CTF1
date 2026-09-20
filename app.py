import os
from flask import Flask, render_template, request

app = Flask(__name__)

# Base challenge directory and directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# Legacy administrator authentication credential
ADMIN_VERIFICATION_CODE = "04712022"


@app.route("/")
def index():
    """Renders the modern Nova Systems employee resource portal."""
    return render_template("index.html")


@app.route("/reports")
def reports():
    """
    Document viewer endpoint.
    Vulnerable to path traversal within the challenge application sandbox.
    """
    filename = request.args.get("file", "welcome.txt")

    # Resolve requested file path relative to reports directory
    target_path = os.path.abspath(os.path.join(REPORTS_DIR, filename))

    # Safety containment: restrict traversal within the challenge project root
    try:
        is_sandboxed = os.path.commonpath([BASE_DIR, target_path]) == BASE_DIR
    except ValueError:
        # Cross-drive resolution on Windows
        is_sandboxed = False

    if not is_sandboxed or not os.path.isfile(target_path):
        return render_template(
            "reports.html",
            filename=filename,
            error="Document not found.",
            content=None
        ), 404

    try:
        with open(target_path, "r", encoding="utf-8", errors="replace") as f:
            file_content = f.read()
        return render_template(
            "reports.html",
            filename=filename,
            content=file_content,
            error=None
        )
    except Exception:
        return render_template(
            "reports.html",
            filename=filename,
            error="Document not found.",
            content=None
        ), 404


@app.route("/legacy-console", methods=["GET", "POST"])
def legacy_console():
    """
    Legacy administrative console route.
    Authenticates administrator using legacy employee verification code.
    """
    if request.method == "POST":
        employee_code = request.form.get("employee_code", "").strip()
        if employee_code == ADMIN_VERIFICATION_CODE:
            return render_template("success.html")
        return render_template("legacy.html", error="Verification failed."), 401

    return render_template("legacy.html", error=None)


@app.errorhandler(404)
def handle_404(e):
    return "404 Not Found", 404


@app.errorhandler(500)
def handle_500(e):
    return "500 Internal Server Error", 500


if __name__ == "__main__":
    # Challenge runs without debug mode to avoid information leakage
    app.run(host="0.0.0.0", port=5000, debug=False)
