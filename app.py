from flask import Flask, render_template, request

from classifier.lab1 import EmailClassification

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods = ["POST"])
def analyze():
    archive = request.files["archive"]

    classifier = EmailClassification(archive)
    results = classifier.open_zip()

    normal = [result for result in results if result.get("status") == "OK"]
    suspicious = [result for result in results if result.get("status") == "Подозрительное"]
    phishing = [result for result in results if result.get("status") == "Фишинг"]

    return render_template(
        "results.html",
        results = results,
        normal = normal,
        suspicious = suspicious,
        phishing = phishing
    )

if __name__ == "__main__":
    app.run(debug=True)


