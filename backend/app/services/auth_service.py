import sqlite3

from starlette.requests import Request
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse

from app.db.session import get_db
from app.core.security import hash_password, verify_password


def signup(username: str, email: str, password: str):
    if not username or not email or not password:
        return HTMLResponse(
            content="<h3>All fields are required</h3><a href='/signup'>Go back</a>",
            status_code=400,
        )

    hashed = hash_password(password)

    # FIXED: SQL Injection closed by using parameterized query
    query = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)"

    conn = get_db()
    try:
        conn.execute(query, [username, email, hashed])
        conn.commit()
        return RedirectResponse(url="/login", status_code=302)
    except sqlite3.IntegrityError:
        return HTMLResponse(
            content="<h3>Username already exists</h3><a href='/signup'>Go back</a>",
            status_code=400,
        )
    except Exception as e:
        return HTMLResponse(
            content=f"<h3>Error: {str(e)}</h3><a href='/signup'>Go back</a>",
            status_code=400,
        )
    finally:
        conn.close()


def login(request: Request, username: str, password: str):
    if not username or not password:
        return JSONResponse(
            content={"error": "Username and password are required"},
            status_code=401,
        )

    # FIXED: SQL Injection closed by using parameterized query
    # (Password comparison is performed in Python via verify_password
    # because bcrypt hashes cannot be matched with an SQL equality check.)
    query = "SELECT * FROM users WHERE username = ?"

    conn = get_db()
    try:
        cursor = conn.execute(query, [username])
        user = cursor.fetchone()
    except Exception:
        return JSONResponse(
            content={"error": "Invalid username or password"},
            status_code=401,
        )
    finally:
        conn.close()

    if user and verify_password(password, user["password"]):
        request.session["user_id"] = user["id"]
        request.session["username"] = user["username"]
        request.session["email"] = user["email"]
        return JSONResponse(content={"success": True, "redirect": "/welcome"})
    else:
        return JSONResponse(
            content={"error": "Invalid username or password"},
            status_code=401,
        )
