from flask import Flask, request, render_template_string\n\napp = Flask(__name__)\n\n@app.route('/register', methods=['GET', 'POST'])\ndef register():\n    if request.method == 'POST':\n        name = request.form['name']\n        email = request.form['email']\n        return f"Registration successful! Name: {name}, Email: {email}"\n    return '''\n        <form method="post">
            Name: <input type="text" name="name"><br>
            Email: <input type="email" name="email"><br>
            <input type="submit" value="Register">
        </form>\n    '''\n\nif __name__ == '__main__':\n    app.run(debug=True)