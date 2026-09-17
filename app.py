import zipfile

from flask import Flask, render_template, request

from classifier.lab1 import EmailClassification

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods = ["POST"])
async def analyze():
    if "archive" not in request.files:
        return render_template(
            "error.html",
            message = "Архив не загружен!"
        ), 400

    archive = request.files["archive"]

    if archive.filename == "":
        return render_template(
            "error.html",
            message = "Архив не выбран"
        ), 400

    if not archive.filename.endswith(".zip"):
        return render_template(
            "error.html",
            message = "Файл не является .zip архивом!"
        ), 400

    try:
        classifier = EmailClassification(archive)
        results = await classifier.open_zip()
    except zipfile.BadZipFile:
        return render_template(
            "error.html",
            message = "Архив поврежден или не является корректным!"
        ), 400

    normal, suspicious, phishing = [], [], []
    for result in sorted(results, key = lambda x: x.get("coefficient", 0)):
        status = result.get("status")
        if status == "OK":
            normal.append(result)
        elif status == "Подозрительное":
            suspicious.append(result)
        elif status == "Фишинг":
            phishing.append(result)

    return render_template(
        "results.html",
        results = results,
        normal = normal,
        suspicious = suspicious,
        phishing = phishing
    ), 200


if __name__ == "__main__":
    app.run(debug=True)


