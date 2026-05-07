from flask import Flask, render_template, request, send_file, session
import os
import csv
import io
from   analyser_tool import read_logs, filter_by_level, filter_by_keyword

app = Flask(__name__)
app.secret_key = "logtool123"

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/")                     
def index():
    return render_template("index.html")


@app.route("/analyse", methods=["POST"])
def analyse():
    if "logfile" not in request.files:
        return render_template("index.html", error="Please upload a file")

    file = request.files["logfile"]

    if file.filename == "":
        return render_template("index.html", error="No file selected")

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    level_filter = request.form.get("level", "ALL")
    keyword      = request.form.get("keyword", "").strip()

    logs = read_logs(filepath)

    if level_filter != "ALL":
        logs = filter_by_level(logs, level_filter)

    if keyword:
        logs = filter_by_keyword(logs, keyword)

    summary = {
        "total":    len(logs),
        "errors":   sum(1 for l in logs if l["level"] == "ERROR"),
        "warnings": sum(1 for l in logs if l["level"] == "WARNING"),
        "info":     sum(1 for l in logs if l["level"] == "INFO"),
        "critical": sum(1 for l in logs if l["level"] == "CRITICAL"),
        "debug":    sum(1 for l in logs if l["level"] == "DEBUG"),
    }

    session["logs"] = logs
    session["filename"] = file.filename

    return render_template(
        "dashboard.html",
        logs=logs,
        summary=summary,
        filename=file.filename,
        level_filter=level_filter,
        keyword=keyword
    )


@app.route("/export")
def export():
    logs = session.get("logs", [])

    if not logs:
        return "No data to export", 400

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["timestamp", "level", "message", "raw"])
    writer.writeheader()
    writer.writerows(logs)
    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="log_results.csv"
    )


if __name__ == "__main__":
    app.run(debug=True)