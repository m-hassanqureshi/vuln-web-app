# Email Verification on Signup — Explained in Plain English

This guide explains the **Email Verification** feature (release v1.0.4) from
scratch, assuming you know **nothing** about the jargon. Read it with the code
open next to you: every step points at the exact file and function so you can
say "ah, *this* is where that happens."

There is **no code copied into this file** — only references to it, like
`backend/app/services/verification_service.py → start_verification()`. Open that
file, find that function, and read along.

---

## 1. What does this feature do, in one sentence?

When someone signs up, we **email them a special link**. Their account does not
fully work until they **click that link**. This proves the email address they
typed is real and belongs to them.

**Why bother?** Without it, anyone can sign up as `barackobama@gmail.com`
without owning that inbox. Verification makes sure the person actually controls
the address.

**Our exact rule:** a brand-new account **cannot log in at all** until the link
is clicked. Clicking the link both *verifies* the account **and** logs them in,
dropping them straight on their dashboard.

---

## 2. The words you need to know first

Don't skip these — the rest of the guide uses them constantly.

- **Frontend** = the web pages you see (HTML files in `frontend/templates/`).
- **Backend** = the Python program that runs on the server and decides what to
  do (the `backend/app/` folder). We use **FastAPI**, a popular Python tool for
  building web backends.
- **Route / endpoint** = a specific web address the backend answers, like
  `/signup` or `/verify`. Each route has a **handler** = the Python function
  that runs when someone visits that address. All our handlers live in
  `backend/app/api/routes/auth.py`.
- **GET vs POST** = the two ways a browser talks to a route.
  - **GET** = "show me a page" (typing a URL, clicking a link).
  - **POST** = "here is some data, do something with it" (submitting a form).
- **Database (DB)** = where we permanently store data. We use **SQLite**, a tiny
  database that is just a single file on disk: `vulnerable_app.db`. Our data
  lives in one table called `users` (think: a spreadsheet, one row per user).
- **SQL** = the language used to talk to the database ("INSERT a row",
  "SELECT rows where..."). 
- **Session / cookie** = how the server remembers you are logged in. After you
  log in, the server gives your browser a small signed token called a **cookie**.
  Your browser sends it back on every request, so the server knows "this is the
  logged-in user." We never store passwords in it — just your user id, username,
  and email. The "session" is that bundle of info.
- **SMTP** = **S**imple **M**ail **T**ransfer **P**rotocol. It is simply the
  standard *language email servers speak* to send mail. To send an email from
  code, you connect to an SMTP server (for us, Gmail's: `smtp.gmail.com`), log
  in, and hand it the message. That's it.
- **stdlib** = "standard library" = the toolbox that comes built into Python for
  free. Python *already includes* an SMTP client (`smtplib`) and an email-message
  builder (`email`). So we send mail using **only built-in tools** — we did not
  install any new third-party package. That's what "stdlib only, no new
  dependency" means.
- **Token** = a long, random, unguessable string of characters (ours is 43
  characters like `xJ8k...`). We put it in the verification link. Because it's
  random and long, nobody can guess someone else's link.
- **Hash / bcrypt** = a one-way scramble of a password. We never store the real
  password; we store its scrambled form (the "hash") using a tool called
  **bcrypt**. To check a password later, we scramble the typed one and compare.
  This lives in `backend/app/core/security.py`.
- **Environment variable / `.env` file** = settings that live *outside* the code
  so secrets (like your Gmail password) are never written into the source. They
  sit in a file called `.env` which is **kept out of Git** (never shared). The
  code reads them through `backend/app/core/config.py`.
- **Template** = an HTML page with little `{{placeholders}}` in it. The backend
  reads the file, swaps the placeholders for real values, and sends the result
  to the browser. Example: `{{username}}` becomes your actual username.
- **Middleware** = code that runs *automatically* on every request before/after
  the handler — like a security checkpoint. We have three: one checks for
  CSRF tokens, one limits how often you can hit the server (rate limit), one
  manages the session cookie. We did **not** touch these; our feature just
  benefits from them.
- **Background thread** = doing a slow job "on the side" so the user doesn't
  wait. More on this in Step 6.

---

## 3. The files — what we created and what we changed

### Files we CREATED (brand new)

| File | What it is |
|------|------------|
| `backend/app/core/mailer.py` | The "email sender." Knows how to connect to Gmail and send the verification email. |
| `backend/app/services/verification_service.py` | The "brain" of the feature: makes the token, saves it, checks it, handles resends. |
| `frontend/templates/check_email.html` | The "we sent you an email, check your inbox" page shown right after signup. |
| `frontend/templates/verify_result.html` | The page shown only when a link is **expired or broken**. |
| `frontend/templates/email_not_configured.html` | A friendly "email isn't set up yet, see the README" page. |
| `.claude/specs/email-verification-on-signup.md` + `-plan.md` | The design document and step-by-step build plan (written before the code). |

### Files we CHANGED (already existed)

| File | What we added |
|------|---------------|
| `backend/app/core/config.py` | Reads the SMTP settings from `.env`; adds `is_email_configured()` to check if email is set up. |
| `backend/app/db/session.py` | Added 3 new columns to the `users` table to track verification. |
| `backend/app/services/auth_service.py` | `signup()` now creates an *unverified* account and triggers the email; `login()` now *blocks* unverified accounts. |
| `backend/app/services/oauth_service.py` | Google sign-in users are marked verified automatically. |
| `backend/app/api/routes/auth.py` | New routes `/check-email`, `/verify`, `/verify/resend`; the signup routes now refuse to run if email isn't configured. |
| `frontend/templates/login.html` | Shows a "Resend verification email" button when login is blocked for being unverified. |
| `.env.example` | A template listing the SMTP settings you should fill in. |
| `README.md`, `CLAUDE.md` | Documentation. |

### The 3 new columns in the `users` table

Look at `backend/app/db/session.py → init_db()`. We added these to the `users`
table (a "column" is just a field on each user row):

- **`is_verified`** — `0` means "email not confirmed yet", `1` means "confirmed."
- **`verification_token`** — the random token from the link, or empty once used.
- **`verification_token_expires`** — the moment in time the token stops working
  (we set it to 1 hour after creation).

Adding columns to an existing database is called a **migration**. Ours is in the
same `init_db()` function and is *safe to run repeatedly*: it only adds a column
if it's missing, and never deletes anyone's data.

---

## 4. One-time setup: telling the app how to send email

Before any of this works, the app needs Gmail login details. You put them in the
`.env` file (`SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD`, etc. — see `.env.example`
for the template, and the README's "Email Verification — Setup" section for how
to get a Gmail App Password).

When the app starts, `backend/app/core/config.py` reads those values. The
function `is_email_configured()` there returns `True` only if the host, user,
and password are all filled in. If they're not, the whole signup flow politely
refuses to run (see Step 5b). This is the same "fail gracefully when not set up"
idea the Google login feature uses.

---

## 5. THE MAIN FLOW: what happens when you click "Create Account"

Here is every single step, in order. Open the referenced files as you go.

### Step 5a — You open the signup page (a GET request)

You visit `/signup`. The handler `signup_page()` in
`backend/app/api/routes/auth.py` runs.

1. **First thing it does:** checks `config.is_email_configured()`. If email is
   NOT set up, it shows `email_not_configured.html` and stops here — no signup
   form at all. (Covered in 5b below.)
2. If email *is* set up, it reads the `frontend/templates/signup.html` file,
   inserts a fresh **CSRF token** into the hidden form field (a CSRF token is an
   anti-forgery code the security middleware checks later), and sends the page to
   your browser. You see the signup form.

### Step 5b — (Only if email isn't configured) the friendly stop page

If `is_email_configured()` is `False`, both the GET and the POST of `/signup`
return `email_not_configured.html` and **create no account**. Nothing is logged,
nothing leaks. This is why a fresh copy of the app without Gmail set up won't let
people sign up — it tells them to configure email first.

### Step 5c — You fill the form and click "Create Account" (a POST request)

The form sends your username, email, password (and the hidden CSRF token) as a
**POST** to `/signup`. Before your data even reaches our code, the **middleware**
checkpoints run automatically:

1. **Rate-limit middleware** (`backend/app/core/rate_limit.py`) — makes sure you
   aren't spamming the server with too many requests.
2. **CSRF middleware** (`backend/app/core/csrf.py`) — checks the hidden CSRF
   token matches your session, proving the form really came from our site.

If those pass, the handler `signup_post()` in `auth.py` runs. It *also*
double-checks `is_email_configured()` (defense in depth), then calls the real
worker: `auth_service.signup(username, email, password)`.

### Step 5d — Creating the account (still no email yet)

Now we're in `backend/app/services/auth_service.py → signup()`. Step by step:

1. **Validate:** if any field is empty, it returns a small "all fields required"
   error page and stops.
2. **Scramble the password:** it calls `hash_password()` (from
   `backend/app/core/security.py`), which uses **bcrypt** to turn the plain
   password into a safe, scrambled hash. The real password is never stored.
3. **Insert the new user:** it runs an SQL `INSERT` to add a row to the `users`
   table, explicitly setting `is_verified = 0` (unverified). Notice the SQL uses
   `?` placeholders, not the typed text glued directly into the query — this is a
   **parameterized query**, which prevents a hacking technique called SQL
   injection.
4. **Grab the new user's id:** right after inserting, it reads `cursor.lastrowid`
   — the unique id the database just assigned to this new user. We need it for
   the next step.
5. **If the username already exists**, the database complains and we show a
   "username already exists" page instead.

### Step 5e — Make the token and send the email

Still in `signup()`, after the account is safely created, it calls:

`verification_service.start_verification(user_id, username, email, background=True)`

Open `backend/app/services/verification_service.py → start_verification()`. It:

1. **Creates the token:** `secrets.token_urlsafe(32)` makes a 43-character random
   string. (`secrets` is a Python built-in tool for *cryptographically strong*
   randomness — i.e., genuinely unguessable.)
2. **Sets the expiry:** "now plus 1 hour", stored as a number.
3. **Saves both** into that user's row (`verification_token` and
   `verification_token_expires`) with another parameterized SQL `UPDATE`.
4. **Builds the link:** something like
   `http://localhost:3001/verify?token=xJ8k...`. The base part comes from the
   `APP_BASE_URL` setting in `.env`.
5. **Sends the email — on the side.** Because `background=True`, it does **not**
   wait for Gmail. See Step 6 for why. It hands the actual sending to a
   background helper and immediately returns.

### Step 6 — Why the email is sent "in the background"

Talking to Gmail takes a few seconds (connect, secure handshake, log in, send).
If we did that *while you waited*, the "Create Account" button would feel frozen
for several seconds — exactly the slowness you noticed earlier.

So in `start_verification()`, when `background=True`, we start a **daemon thread**
— a little worker running *alongside* the main program — to do the slow Gmail
part. The signup page returns to you **instantly**, and the email goes out a
moment later from that side-worker.

Important: the token is **saved to the database first**, *before* the thread
starts. So even if the email is slow or fails, your account and its token are
safely stored — you can always resend later. Sending email never blocks signup
and can never crash the server (the sender catches all its own errors).

### Step 7 — The actual email sending

The background worker calls
`backend/app/core/mailer.py → send_verification_email(to_email, username, verify_url)`.
This function:

1. **Double-checks** email is configured; if not, it just logs a note and stops.
2. **Builds the message** using Python's built-in `email` tool — a subject line,
   a plain-text version, and an HTML version (with the clickable link). The
   username and link are **HTML-escaped** first, meaning any special characters
   are made safe so they can't inject anything into the email.
3. **Connects to Gmail** using Python's built-in `smtplib`:
   - It opens a connection to `smtp.gmail.com` on port `587`.
   - It runs **STARTTLS**, which upgrades the connection to **encrypted** (so the
     password and message aren't sent in the clear).
   - It **logs in** with your Gmail address and App Password.
   - It **sends** the message.
4. **Returns True/False** (success/failure). It *never* throws an error that
   could crash anything — on any problem it logs the cause and returns `False`.

### Step 8 — You see "Check your inbox"

Back in `signup()` (Step 5e), after firing off the email, it returns a
**redirect** to `/check-email`. A redirect tells your browser "go to this other
page now." Your browser requests `/check-email`, the `check_email_page()` handler
in `auth.py` runs and shows `frontend/templates/check_email.html` — the "we sent
you a link, go click it" page. **Your account exists now, but is still
unverified.**

### Step 9 — The email arrives; you click the link (a GET request)

In your inbox is the email with the "Verify my email" link. Clicking it is a
plain **GET** request to `/verify?token=xJ8k...`. The `?token=xJ8k...` part is how
the token travels back to us.

The handler `verify_email()` in `auth.py` runs:

1. It reads the `token` out of the web address.
2. It calls `verification_service.verify_email_token(token)`.

### Step 10 — Checking the token

Open `verification_service.py → verify_email_token()`. It:

1. If the token is empty → result is **"invalid"**.
2. It looks in the `users` table for a row whose `verification_token` matches
   (parameterized SQL again). If none matches → **"invalid"** (this also covers a
   token that was *already used*, because we erase the token after use).
3. It checks the expiry time. If the 1 hour has passed → **"expired"**.
4. Otherwise → success ("ok"). It:
   - Sets that user's `is_verified = 1`.
   - **Erases** the token (`verification_token = NULL`) so the link can never be
     used a second time — this is what "single-use" means.
   - Returns the user's id, username, and email so the next step can log them in.

Notice we **never show the token back** on any page. The verify page shows a
fixed message, not your token — leaking it could let someone reuse the link.

### Step 11 — Auto-login and landing on your dashboard

Back in the `verify_email()` handler, on a **success ("ok")** result, it:

1. **Logs you in** by writing your `user_id`, `username`, and `email` into the
   **session** — the exact same thing a normal login does. (Clicking a link only
   you could receive *is* proof of identity, so logging you in is safe.)
2. **Redirects you to `/welcome`** — your dashboard.

So in one click the link both confirms your email **and** signs you in, and you
land on your account page. You do **not** get bounced to the login screen.

If the result was **"expired"** or **"invalid"** instead, it shows
`verify_result.html` with a clear message and a "Continue to Login" button (from
there you can log in and resend a fresh link).

---

## 6. The "you can't log in until verified" rule

This is the other half of the feature. Look at
`backend/app/services/auth_service.py → login()`.

When you try to log in:

1. It finds your user row and checks your password with bcrypt
   (`verify_password()`), same as always.
2. **New step:** even if the password is correct, it checks `is_verified`. If
   it's `0` (not verified), it does **not** create a session. Instead it returns
   an error: *"Please verify your email before logging in"*, plus a hidden flag
   `unverified: true`.

On the frontend, `frontend/templates/login.html` notices that `unverified` flag
in the response and reveals a **"Resend verification email"** button (it's hidden
the rest of the time).

### Resending the email (when login is blocked)

Because an unverified person isn't logged in, we can't identify them by a
session. So **resend asks for the password again**. When you click "Resend":

1. The login page sends your username + password to `POST /verify/resend`.
2. The handler `verify_resend()` in `auth.py` calls
   `verification_service.resend_for_credentials(username, password)`.
3. That function **re-checks the password** with bcrypt. This is important: it
   means you can only resend to *your own* inbox (you must know the password) —
   nobody can spam a stranger's email. A wrong username/password gets the same
   generic "Invalid username or password" message (so attackers can't tell which
   usernames exist).
4. If the password is right and the account is still unverified, it makes a fresh
   token and sends a new email (this time it waits for the send so it can tell you
   "Verification email sent" or "could not send").
5. If the account was already verified, it just says so.

That resend POST is automatically protected by the same CSRF and rate-limit
middleware as every other POST — we didn't have to add anything.

---

## 7. Special cases (so you understand the edges)

- **Google sign-in users** (`backend/app/services/oauth_service.py`): Google has
  already verified their email, so when we create or link a Google account we set
  `is_verified = 1` immediately. They never see the verification step.
- **People who already had accounts before this feature** (in
  `db/session.py → init_db()`): the first time the migration adds the
  `is_verified` column, it sets every existing user to `1` (verified). This is
  called **grandfathering** — we don't want to suddenly lock out people who
  signed up before the feature existed.
- **Expired link:** after 1 hour the token won't work; you get the "Link expired"
  page and can resend a fresh one from the login page.
- **Used link clicked again:** the token was erased on first use, so a second
  click shows "Invalid link." Your account stays verified.
- **Email isn't set up:** signup shows the friendly setup page and creates no
  account (Step 5b).
- **Email fails to send (wrong Gmail password, network down):** your account is
  still created (the token is saved); you just won't get the email. You can log
  in attempt → see "verify first" → resend.

---

## 8. Why we built it this way (the security reasoning)

- **Token stored in the database, single-use, 1-hour expiry:** the server needs
  something to compare the clicked link against, so it saves the token. Erasing
  it after one use and expiring it after an hour limits the damage if a link
  leaks.
- **`/verify` is a GET, `/verify/resend` is a POST:** the verify link must be
  clickable from an email (that's always a GET), and its security is the
  unguessable token itself. Resend changes things and sends data, so it's a POST,
  which our anti-forgery (CSRF) and rate-limit middleware automatically guard.
- **Parameterized SQL everywhere:** every database command uses `?` placeholders
  so user input can never be treated as commands (prevents SQL injection).
- **HTML-escaping the email and pages:** user-controlled text (like a username)
  is made safe before being placed into HTML, so it can't inject scripts.
- **Secrets only in `.env`:** the Gmail password lives in `.env` (kept out of
  Git), never hard-coded, so it can't leak through the source code.
- **Email sent in the background:** keeps signup fast and never lets a slow or
  broken mail server freeze or crash the app.
- **stdlib only:** using Python's built-in `smtplib`/`email` means no extra
  software to install and one less thing that could break.

---

## 9. Quick map: file → its one-line job

- `frontend/templates/signup.html` — the signup form you fill in.
- `backend/app/api/routes/auth.py` — all the web addresses (routes) and which
  function runs for each. **Start here to trace the flow.**
- `backend/app/services/auth_service.py` — `signup()` (create account + trigger
  email) and `login()` (block unverified).
- `backend/app/services/verification_service.py` — make/check/resend tokens.
- `backend/app/core/mailer.py` — actually send the Gmail email.
- `backend/app/core/config.py` — read SMTP settings from `.env`.
- `backend/app/db/session.py` — the database table and the new columns.
- `frontend/templates/check_email.html` — "check your inbox" page.
- `frontend/templates/verify_result.html` — "expired / invalid link" page.
- `frontend/templates/email_not_configured.html` — "email not set up" page.
- `frontend/templates/login.html` — login form + "Resend" button.

**One-line summary of the whole flow:** Create Account → account saved as
unverified → token saved + email sent in the background → "check your inbox" →
you click the link → token checked, account marked verified, you're logged in →
dashboard. And you can't log in the normal way until that link is clicked.

---

## 10. Bonus: if two users pick the same password, do they get the same hash?

**Short answer: NO.** Two users with the *exact same* password end up with
**completely different** stored hashes. Here's why, in plain English.

All the password code is in `backend/app/core/security.py` — two functions,
`hash_password()` (used at signup) and `verify_password()` (used at login).

### First, what is "hashing" again?

A **hash** is a one-way scramble. You feed in a password, you get out a
fixed-length jumble of characters. It's *one-way*: you can go password → hash,
but you can **not** go hash → password. So even if someone steals the database,
they only see jumbles, not real passwords.

We use a specific, well-respected hashing technique called **bcrypt**.

### The key idea: a "salt"

If hashing were *only* "password in → jumble out," then the same password would
always make the same jumble. That's bad: an attacker could pre-compute the
jumble for millions of common passwords (a "rainbow table") and instantly match
them against your stolen database.

To stop this, bcrypt mixes in a **salt** — a short *random* value generated
**fresh for every single password**. The salt is combined with the password
*before* scrambling. So the real recipe is:

> hash = bcrypt( **your password** + **a random salt** )

Because the salt is different every time, the same password produces a different
hash every time.

### A concrete example

Imagine **Alice** and **Bob** both choose the password `hunter2`.

- When Alice signs up, bcrypt rolls a random salt — say `Xy7...` — and computes
  `bcrypt("hunter2" + Xy7...)` → a hash ending in, say, `...aB9q`.
- When Bob signs up, bcrypt rolls a *different* random salt — say `Qp3...` — and
  computes `bcrypt("hunter2" + Qp3...)` → a totally different hash ending in,
  say, `...7kLm`.

Same password, **two different stored hashes.** An attacker looking at the
database can't even tell that Alice and Bob *share* a password.

In our code, the random salt comes from this part of `hash_password()`:
`bcrypt.gensalt(rounds=BCRYPT_ROUNDS)` — `gensalt()` literally means "generate a
new random salt."

### Where is the salt stored? (Clever part)

You might wonder: "if we need the salt to check the password later, where do we
keep it?" Answer: **bcrypt stores the salt *inside* the hash string itself.** A
bcrypt hash looks like this (one long line saved in the `password` column):

```
$2b$12$N9qo8uLOickgx2ZMRZoMye   IjZAgcfl7p92ldGxad68LJZdL17lhWy
└┬┘ └┬┘ └──────── salt ──────┘   └──────── the actual hash ───────┘
 │   │
 │   └─ "cost factor" = 12  (how slow/strong it is — see below)
 └───── "$2b$" = this is bcrypt
```

So the salt isn't a secret and doesn't need its own database column — it rides
along inside the stored value. That's why our `users` table just has one
`password` column and nothing extra.

### How login checks a password (using the stored salt)

At login, `verify_password()` calls `bcrypt.checkpw(typed_password, stored_hash)`.
Behind the scenes bcrypt:

1. Reads the salt out of the `stored_hash` (it's right there inside it).
2. Re-runs `bcrypt(typed_password + that_same_salt)`.
3. Compares the result to the stored hash. Match → correct password.

So we never "un-scramble" anything — we just scramble the typed password the same
way and check if the jumbles match.

### The "cost factor" 12 (`BCRYPT_ROUNDS`)

See `BCRYPT_ROUNDS = 12` at the top of `security.py`. This is bcrypt's **cost
factor** — basically "how many times to churn the scrambling." 12 makes each hash
take a noticeable fraction of a second on purpose.

Why deliberately slow? Because if a database is ever stolen, an attacker has to
re-compute hashes billions of times to guess passwords. Making each attempt
*slow* turns a few-hours attack into a few-years one — while a real user only
ever waits that tiny fraction of a second once, at login. (Higher number =
slower = stronger.)

### Why this matters for *our* app

This is actually the fix for one of the lab's original vulnerabilities. The
**old** version of the app hashed passwords with an outdated method called **MD5**
with **no salt** — so identical passwords *did* produce identical hashes, and
they were fast to crack. Switching to **bcrypt with a per-password salt** (in
`security.py`) is what closed that hole. Our email-verification feature reuses
this exact same `hash_password()` / `verify_password()` pair — for example, the
"Resend verification email" step re-checks your password with `verify_password()`
before sending — so nothing weakens it.

**One-line answer:** same password → **different** hashes, because bcrypt adds a
fresh random **salt** to every password before scrambling it, and tucks that salt
inside the stored hash for checking later.
