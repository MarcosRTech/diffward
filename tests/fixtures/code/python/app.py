import hashlib
import os
import pickle
import random
import sqlite3
import subprocess
import tempfile

import requests
import yaml
from flask import Flask, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
db = sqlite3.connect("app.db")


@app.route("/user")
def user():
    user_id = request.args.get("id")
    cur = db.cursor()

    # ruleid: py/sql-injection critical
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")

    # ruleid: py/sql-injection
    cur.execute("SELECT * FROM users WHERE name = '%s'" % request.args["name"])

    # ruleid: py/sql-injection
    cur.execute("DELETE FROM users WHERE id = {}".format(user_id))

    query = "SELECT * FROM orders WHERE user = '" + user_id + "'"
    # ruleid: py/sql-injection
    cur.execute(query)

    # ok: py/sql-injection
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))

    # ok: py/sql-injection
    cur.execute(
        "SELECT * FROM users WHERE id = %s AND active = %s",
        (user_id, True),
    )

    # ruleid: py/sql-injection
    cur.execute(
        f"""
        SELECT *
        FROM users
        WHERE email = '{request.args.get("email")}'
        """
    )
    return "ok"


@app.route("/run")
def run():
    host = request.args.get("host")

    # ruleid: py/command-injection
    os.system("ping -c 1 " + host)

    # ruleid: py/command-injection
    subprocess.run(f"nslookup {host}", shell=True)

    # ok: py/command-injection
    subprocess.run(["ping", "-c", "1", host])

    # ok: py/command-injection
    os.system("uptime")

    # ruleid: py/code-injection
    eval(request.form["expr"])

    # ok: py/code-injection
    eval("1 + 1")
    return "ok"


@app.route("/file")
def file():
    name = request.args.get("name")

    # ruleid: py/path-traversal
    return send_file(os.path.join("/srv/files", name))


@app.route("/file2")
def file2():
    name = secure_filename(request.args.get("name"))
    # ok: py/path-traversal
    return send_file(os.path.join("/srv/files", name))


@app.route("/fetch")
def fetch():
    url = request.args["url"]

    # ruleid: py/ssrf
    r = requests.get(url, timeout=5)

    # ok: py/ssrf
    requests.get(f"https://api.example.com/items/{url}", timeout=5)
    return r.text


class Repo:
    def __init__(self, cur, table):
        self.cur = cur
        self.table = table

    def count(self, status):
        # ruleid: py/sql-injection high
        self.cur.execute(f"SELECT count(*) FROM orders WHERE status = '{status}'")

    def by_column(self, column, value):
        # ruleid: py/sql-injection medium
        self.cur.execute("SELECT * FROM orders WHERE %s = %%s" % quote_name(column), (value,))

    def total(self):
        # ruleid: py/sql-injection medium
        self.cur.execute("SELECT count(*) FROM %s" % self.table)


def load(blob, text, path):
    # ruleid: py/insecure-deserialization
    obj = pickle.loads(blob)

    # ruleid: py/insecure-deserialization
    cfg = yaml.load(text)

    # ok: py/insecure-deserialization
    cfg2 = yaml.load(text, Loader=yaml.SafeLoader)

    # ok: py/insecure-deserialization
    cfg3 = yaml.safe_load(text)
    return obj, cfg, cfg2, cfg3


def crypto():
    # ruleid: py/weak-hash
    h = hashlib.md5(b"x").hexdigest()

    # ok: py/weak-hash
    etag = hashlib.md5(b"x", usedforsecurity=False).hexdigest()

    # ok: py/weak-hash
    h2 = hashlib.sha256(b"x").hexdigest()

    # ruleid: py/tls-verification-disabled
    requests.get("https://internal.example.com", verify=False)

    # ruleid: py/insecure-random
    reset_token = "".join(random.choice("abcdef0123456789") for _ in range(32))

    # ok: py/insecure-random
    delay = random.randint(1, 5)

    # ruleid: py/insecure-tempfile
    tmp = tempfile.mktemp()

    # ok: py/insecure-tempfile
    fd, tmp2 = tempfile.mkstemp()
    return h, etag, h2, reset_token, delay, tmp, fd, tmp2


def docs():
    """
    Never call eval(user_input) or os.system("rm " + path) in production.
    """
    # a comment mentioning cur.execute(f"SELECT {x}") is not code
    return 1


# ruleid: secret/hardcoded-password
DB_PASSWORD = "pr0d-P4ssw0rd-2024"

# ok: secret/hardcoded-password
API_KEY = os.environ["API_KEY"]

if __name__ == "__main__":
    # ruleid: py/debug-enabled
    app.run(host="0.0.0.0", debug=True)
