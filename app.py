from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import sqlite3
import random
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "lost_found_local_development_key"
)

DATABASE = os.environ.get("DATABASE_PATH", "database.db")


# =========================================================
# DATABASE
# =========================================================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():

    conn = get_db()
    cursor = conn.cursor()

    # Create users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT,
            email TEXT,
            phone TEXT,
            password TEXT,
            verified INTEGER DEFAULT 0,
            name TEXT,
            course TEXT,
            year TEXT,
            hostel TEXT
        )
    """)

    # Check existing columns
    cursor.execute("PRAGMA table_info(users)")
    columns = [row["name"] for row in cursor.fetchall()]

    # Add missing columns to old database
    required_columns = {
        "student_id": "TEXT",
        "email": "TEXT",
        "phone": "TEXT",
        "password": "TEXT",
        "verified": "INTEGER DEFAULT 0",
        "name": "TEXT",
        "course": "TEXT",
        "year": "TEXT",
        "hostel": "TEXT"
    }

    for column, datatype in required_columns.items():

        if column not in columns:

            try:
                cursor.execute(
                    f"ALTER TABLE users ADD COLUMN {column} {datatype}"
                )
            except sqlite3.OperationalError:
                pass

    conn.commit()
    conn.close()


# Initialize database
init_db()


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():
    return render_template("index.html")


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        # Supports BOTH:
        # name="contact"
        # name="student_id"

        contact = request.form.get("contact", "").strip()

        student_id = request.form.get(
            "student_id",
            ""
        ).strip()

        login_value = contact or student_id

        password = request.form.get(
            "password",
            ""
        )

        # Validation
        if not login_value or not password:

            flash(
                "Please enter your email/phone/student ID and password."
            )

            return redirect(
                url_for("login")
            )

        conn = get_db()

        # Find account
        user = conn.execute("""
            SELECT *
            FROM users
            WHERE email = ?
               OR phone = ?
               OR student_id = ?
            LIMIT 1
        """, (
            login_value,
            login_value,
            login_value
        )).fetchone()

        conn.close()

        # Account not found
        if user is None:

            flash(
                "Account not found. Please create an account first."
            )

            return redirect(
                url_for("login")
            )

        # Check password
        try:

            password_correct = check_password_hash(
                user["password"],
                password
            )

        except Exception:

            password_correct = False

        if not password_correct:

            flash(
                "Incorrect password."
            )

            return redirect(
                url_for("login")
            )

        # Account not verified
        if user["verified"] != 1:

            session["pending_user_id"] = user["id"]

            otp = str(
                random.randint(
                    100000,
                    999999
                )
            )

            session["verify_otp"] = otp

            print()
            print("====================================")
            print("       LOST & FOUND LOGIN OTP")
            print("       OTP:", otp)
            print("====================================")
            print()

            return redirect(
                url_for("verify")
            )

        # Login successful
        session["user_id"] = user["id"]

        # If profile is incomplete
        if (
            not user["name"]
            or not user["student_id"]
            or not user["course"]
            or not user["year"]
        ):

            return redirect(
                url_for("profile")
            )

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "login.html"
    )


# =========================================================
# REGISTER
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        # register.html uses:
        # name="contact"

        contact = request.form.get(
            "contact",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        # Validation
        if not contact:

            flash(
                "Please enter either email or phone number."
            )

            return redirect(
                url_for("register")
            )

        if not password:

            flash(
                "Please enter a password."
            )

            return redirect(
                url_for("register")
            )

        if password != confirm_password:

            flash(
                "Passwords do not match."
            )

            return redirect(
                url_for("register")
            )

        if len(password) < 6:

            flash(
                "Password must contain at least 6 characters."
            )

            return redirect(
                url_for("register")
            )

        # Determine email or phone
        if "@" in contact:

            email = contact
            phone = None

        else:

            email = None
            phone = contact

        conn = get_db()

        # Check existing account
        existing = conn.execute("""
            SELECT id
            FROM users
            WHERE email = ?
               OR phone = ?
            LIMIT 1
        """, (
            email,
            phone
        )).fetchone()

        if existing:

            conn.close()

            flash(
                "An account with this email or phone already exists."
            )

            return redirect(
                url_for("login")
            )

        # Hash password
        hashed_password = generate_password_hash(
            password
        )

        # Generate OTP
        otp = str(
            random.randint(
                100000,
                999999
            )
        )

        # Store registration details in session
        session["register_email"] = email

        session["register_phone"] = phone

        session["register_password"] = hashed_password

        session["register_otp"] = otp

        conn.close()

        # Demo OTP
        print()
        print("====================================")
        print("       LOST & FOUND REGISTER OTP")
        print("       OTP:", otp)
        print("====================================")
        print()

        return redirect(
            url_for("verify")
        )

    return render_template(
        "register.html"
    )


# =========================================================
# OTP VERIFICATION
# =========================================================

@app.route("/verify", methods=["GET", "POST"])
def verify():

    # =====================================================
    # NEW REGISTRATION
    # =====================================================

    if "register_otp" in session:

        if request.method == "POST":

            entered_otp = request.form.get(
                "otp",
                ""
            ).strip()

            correct_otp = session.get(
                "register_otp"
            )

            # Wrong OTP
            if entered_otp != correct_otp:

                flash(
                    "Invalid OTP. Please try again."
                )

                return redirect(
                    url_for("verify")
                )

            # Get registration details
            email = session.get(
                "register_email"
            )

            phone = session.get(
                "register_phone"
            )

            password = session.get(
                "register_password"
            )

            # Create account
            conn = get_db()

            cursor = conn.execute("""
                INSERT INTO users
                (
                    student_id,
                    email,
                    phone,
                    password,
                    verified
                )
                VALUES (?, ?, ?, ?, 1)
            """, (
                None,
                email,
                phone,
                password
            ))

            user_id = cursor.lastrowid

            conn.commit()
            conn.close()

            # Clear registration session
            session.pop(
                "register_email",
                None
            )

            session.pop(
                "register_phone",
                None
            )

            session.pop(
                "register_password",
                None
            )

            session.pop(
                "register_otp",
                None
            )

            # Automatically login
            session["user_id"] = user_id

            # =================================================
            # IMPORTANT:
            # NEW ACCOUNT -> PROFILE
            # NOT DASHBOARD
            # =================================================

            return redirect(
                url_for("profile")
            )

        # Contact shown on verify page
        contact = session.get(
            "register_email"
        )

        if not contact:

            contact = session.get(
                "register_phone"
            )

        return render_template(
            "verify.html",
            contact=contact,
            otp=session.get("register_otp")
        )


    # =====================================================
    # EXISTING USER VERIFICATION
    # =====================================================

    if "pending_user_id" in session:

        if request.method == "POST":

            entered_otp = request.form.get(
                "otp",
                ""
            ).strip()

            correct_otp = session.get(
                "verify_otp"
            )

            if entered_otp != correct_otp:

                flash(
                    "Invalid OTP. Please try again."
                )

                return redirect(
                    url_for("verify")
                )

            user_id = session.get(
                "pending_user_id"
            )

            conn = get_db()

            conn.execute("""
                UPDATE users
                SET verified = 1
                WHERE id = ?
            """, (
                user_id,
            ))

            conn.commit()

            user = conn.execute("""
                SELECT *
                FROM users
                WHERE id = ?
            """, (
                user_id,
            )).fetchone()

            conn.close()

            # Clear OTP session
            session.pop(
                "pending_user_id",
                None
            )

            session.pop(
                "verify_otp",
                None
            )

            session["user_id"] = user_id

            # Profile incomplete?
            if (
                not user["name"]
                or not user["student_id"]
                or not user["course"]
                or not user["year"]
            ):

                return redirect(
                    url_for("profile")
                )

            return redirect(
                url_for("dashboard")
            )

        return render_template(
            "verify.html",
            contact="your registered contact",
            otp=session.get("verify_otp")
        )

    # No verification session
    return redirect(
        url_for("register")
    )


# =========================================================
# PROFILE DETAILS
# =========================================================

@app.route("/profile", methods=["GET", "POST"])
def profile():

    # User must be logged in
    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    # =====================================================
    # SAVE PROFILE
    # =====================================================

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        student_id = request.form.get(
            "student_id",
            ""
        ).strip()

        course = request.form.get(
            "course",
            ""
        ).strip()

        year = request.form.get(
            "year",
            ""
        ).strip()

        hostel = request.form.get(
            "hostel",
            ""
        ).strip()

        # Required fields
        if not name:

            flash(
                "Please enter your full name."
            )

            return redirect(
                url_for("profile")
            )

        if not student_id:

            flash(
                "Please enter your Student ID."
            )

            return redirect(
                url_for("profile")
            )

        if not course:

            flash(
                "Please enter your course or department."
            )

            return redirect(
                url_for("profile")
            )

        if not year:

            flash(
                "Please select your year."
            )

            return redirect(
                url_for("profile")
            )

        conn = get_db()

        # Check Student ID
        existing = conn.execute("""
            SELECT id
            FROM users
            WHERE student_id = ?
              AND id != ?
            LIMIT 1
        """, (
            student_id,
            session["user_id"]
        )).fetchone()

        if existing:

            conn.close()

            flash(
                "This Student ID is already registered."
            )

            return redirect(
                url_for("profile")
            )

        # Save profile
        conn.execute("""
            UPDATE users
            SET
                name = ?,
                student_id = ?,
                course = ?,
                year = ?,
                hostel = ?
            WHERE id = ?
        """, (
            name,
            student_id,
            course,
            year,
            hostel,
            session["user_id"]
        ))

        conn.commit()
        conn.close()

        # Profile completed
        return redirect(
            url_for("dashboard")
        )

    # =====================================================
    # SHOW PROFILE PAGE
    # =====================================================

    conn = get_db()

    user = conn.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (
        session["user_id"],
    )).fetchone()

    conn.close()

    if user is None:

        session.clear()

        return redirect(
            url_for("login")
        )

    return render_template(
        "profile.html",
        user=user
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    # User must login
    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    conn = get_db()

    user = conn.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (
        session["user_id"],
    )).fetchone()

    conn.close()

    if user is None:

        session.clear()

        return redirect(
            url_for("login")
        )

    # Do not allow incomplete profiles
    if (
        not user["name"]
        or not user["student_id"]
        or not user["course"]
        or not user["year"]
    ):

        return redirect(
            url_for("profile")
        )

    return render_template(
        "dashboard.html",
        user=user
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# 404
# =========================================================

@app.errorhandler(404)
def page_not_found(error):

    return """
    <h2>404 - Page Not Found</h2>

    <p>
        The requested page does not exist.
    </p>

    <a href="/">
        Go Home
    </a>
    """, 404


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    print()
    print("======================================")
    print("      LOST & FOUND APPLICATION")
    print("======================================")
    print("Server: http://127.0.0.1:5000")
    print("======================================")
    print()

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )