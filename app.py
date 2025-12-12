from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt
import datetime
import re
from better_profanity import profanity      # THIS HAS A 67% CHANCE OF WORKING (SOMETIMES IT DOESN'T WORK FOR SOME REASON)

profanity.load_censor_words()

app = Flask(__name__)
app.secret_key = "frames-secret-key"

DB_PATH = "PWAFramesDatabase.db"

# DATABASE PROGRAM FROM PREVIOUS USERREGISTRATION.PY FILE + MODIFICATIONS SUCH AS FLASK INTEGRATION. 

def get_db():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS AccountsDetail (
        UserID INTEGER PRIMARY KEY AUTOINCREMENT,
        Username TEXT UNIQUE NOT NULL,
        UserPassword TEXT NOT NULL,
        UserEmail TEXT UNIQUE NOT NULL,
        UserPFP TEXT,
        UserJoinDate TEXT,
        UserReviewCount INTEGER DEFAULT 0,
        UserTitle TEXT,
        UserDescription TEXT,
        UserAuthorityLevel INTEGER DEFAULT 1
    )
    """)
    conn.commit()
    conn.close()

init_db()

# ROUTING OF WEBSITES FOR FLASK 

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]

        if len(username) > 16:
            return render_template("signup.html", error="Username too long")

        if profanity.contains_profanity(username):
            return render_template("signup.html", error="Inappropriate username")

        if len(password) < 8:
            return render_template("signup.html", error="Password must be 8+ chars")

        if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email):
            return render_template("signup.html", error="Invalid email")

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM AccountsDetail WHERE Username=? OR UserEmail=?",
            (username, email)
        )

        if cursor.fetchone():
            conn.close()
            return render_template("signup.html", error="User already exists")

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
        INSERT INTO AccountsDetail
        (Username, UserPassword, UserEmail, UserPFP, UserJoinDate, UserTitle, UserDescription)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (username, hashed, email, "default.png", now, "New User", "No bio yet"))

        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form["identifier"]
        password = request.form["password"]

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
        SELECT Username, UserPassword, UserAuthorityLevel
        FROM AccountsDetail
        WHERE Username=? OR UserEmail=?
        """, (identifier, identifier))

        user = cursor.fetchone()
        conn.close()

        if not user:
            return render_template("login.html", error="User not found")

        username, hashed, level = user

        if not bcrypt.checkpw(password.encode(), hashed.encode()):
            return render_template("login.html", error="Incorrect password")

        session["user"] = username
        session["level"] = level

        return redirect("/browse")

    return render_template("login.html")

#FOLLOWING ROUTES REQUIRE LOGIN TO ACCESS - COOKIES STORE THIS DATA. 
@app.route("/browse")
def browse():
    print("SESSION CONTENTS:", dict(session))
    if "user" not in session:
        return redirect("/login")
    return render_template("browse.html", user=session["user"])



@app.route("/top10")
def top10():
    if "user" not in session:
        return redirect("/login")
    return render_template("top10.html", user=session["user"])


@app.route("/movie")
def movie():
    if "user" not in session:
        return redirect("/login")
    return render_template("movie.html", user=session["user"])


@app.route("/logout")
def logout():
    print("Before logout:", dict(session))
    session.clear()
    print("After logout:", dict(session))
    return redirect("/login")

#PROFILE PAGE ROUTE TO DISPLAY USER INFORMATION - NEEDS LOGIN TO ACCESS.
@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect("/login")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT Username, UserEmail, UserPFP, UserJoinDate,
           UserReviewCount, UserTitle, UserDescription
    FROM AccountsDetail
    WHERE Username=?
    """, (session["user"],))

    user = cursor.fetchone()
    conn.close()

    if not user:
        return redirect("/logout")

    return render_template(
        "profile.html",
        username=user[0],
        email=user[1],
        pfp=user[2],
        joined=user[3],
        reviews=user[4],
        title=user[5],
        bio=user[6]
    )


if __name__ == "__main__":
    app.run(debug=True)
