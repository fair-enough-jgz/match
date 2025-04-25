from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route('/', methods=['GET'])
def index():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Form</title>
    </head>
    <body>
        <form action="/submit" method="get">
            <label for="name">Name:</label>
            <input type="text" id="name" name="name" required><br><br>
            <input type="submit" value="Submit">
        </form>
    </body>
    </html>
    """
    return render_template_string(html)


@app.route('/submit', methods=['post'])
def submit():
    return 'Form submitted!'


if __name__ == '__main__':
    app.run(debug=True)
