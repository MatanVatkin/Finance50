import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    shares_owned = db.execute(
        "SELECT symbol, shares, comp_name FROM portfolio WHERE user_id = ? GROUP BY symbol", session["user_id"])
    current_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])

    # Get price of each stock
    total_value = 0
    for row in shares_owned:
        quote = lookup(row["symbol"])
        row["price"] = quote["price"]
        row["value"] = row["shares"] * quote["price"]
        total_value += row["value"]

    total_cash = current_cash[0]["cash"] + total_value

    return render_template("index.html", shares_owned=shares_owned, current_cash=current_cash[0]["cash"], total_cash=total_cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        check_shares = request.form.get("shares")
        symbol = request.form.get("symbol").upper()

        # Check user is entering value and buying valid stock
        if not symbol:
            return apology("Please enter a stock symbol", 400)
        elif not lookup(symbol):
            return apology("Please enter valid stock symbol", 400)
        elif check_shares.isdigit() == False:
            return apology("Must buy one or more shares", 400)

        else:

            quoted = lookup(symbol)
            shares = float(request.form.get("shares"))
            purchase = (quoted["price"] * shares)
            cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])

            # Check user cash balance
            if cash[0]["cash"] < purchase:
                return apology("Cannot afford this purchase", 400)

            # Add transaction to table
            db.execute("INSERT INTO transactions (symbol, shares, price, comp_name, user_id, bought_sold) VALUES (?, ?, ?, ?, ?, ?)",
                       quoted["symbol"], shares, quoted["price"], quoted["name"], session["user_id"], 'bought')

            # Add or update portfolio
            exist = db.execute("SELECT symbol FROM portfolio WHERE symbol = ? AND user_id = ?", symbol, session["user_id"])
            if len(exist) == 0:
                db.execute("INSERT INTO portfolio (symbol, shares, comp_name, user_id) VALUES (?, ?, ?, ?)",
                           quoted["symbol"], shares, quoted["name"], session["user_id"])
            else:
                old_shares = db.execute("SELECT shares FROM portfolio WHERE symbol = ? AND user_id = ?", symbol, session["user_id"])
                new_shares = old_shares[0]["shares"] + shares
                db.execute("INSERT OR REPLACE INTO portfolio (symbol, shares, comp_name, user_id) VALUES (?, ?, ?, ?)",
                           quoted["symbol"], new_shares, quoted["name"], session["user_id"])

            # Update user cash balace
            db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", purchase, session["user_id"])

            # Redirect user to home page
            flash("Purchase complete")
            return redirect("/")

    # Handle GET request
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute(
        "SELECT time, symbol, shares, price, comp_name, bought_sold FROM transactions WHERE user_id = ?", session["user_id"])

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User sent form through POST, check for valid stock info and return info
    if request.method == "POST":
        symbol = request.form.get("symbol")
        quoted = lookup(symbol)
        if not symbol:
            return apology("Please enter a stock symbol", 400)
        elif not quoted:
            return apology("Please enter valid stock symbol", 400)
        else:
            return render_template("quoted.html", name=quoted["name"], price=usd(quoted["price"]), symbol=quoted["symbol"])

    # Handle GET request
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    if request.method == "POST":

        username = request.form.get("username")
        name_exist = db.execute("SELECT * FROM users WHERE username = ?", username)
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        # Maybe not allow punc

        # Ensure fields arent empty
        if not username:
            return apology("Missing username", 400)
        elif not password:
            return apology("Missing password", 400)
        elif not confirmation:
            return apology("Verify password", 400)

        # Ensure username exists in db
        elif len(name_exist) != 0:
            return apology("Username already exists", 400)

        # Ensure passwords match
        elif password != confirmation:
            return apology("Password doesn't match", 400)

        else:
            # Hash password
            pass_hash = generate_password_hash(password)

            # Insert username and hashed password to db
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, pass_hash)

            # Remember which user has logged in
            new_id = db.execute("SELECT id FROM users WHERE username = ?", username)
            session["user_id"] = new_id[0]["id"]
            return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    shares_owned = db.execute("SELECT symbol, shares FROM portfolio WHERE user_id = ? GROUP BY symbol", session["user_id"])

    if request.method == "POST":

        sell_amount = request.form.get("shares")
        symbol = request.form.get("symbol")
        shares_amount = db.execute("SELECT shares FROM portfolio WHERE symbol = ? AND user_id = ?", symbol, session["user_id"])
        quoted = lookup(symbol)
        price = db.execute("SELECT price FROM transactions WHERE symbol = ?", symbol)
        shares = float(request.form.get("shares"))
        sale = (price[0]["price"] * shares)

        if not symbol:
            return apology("Please select stock to sell", 400)
        elif int(sell_amount) > shares_amount[0]["shares"] or int(sell_amount) <= 0:
            return apology("Please input valid number of shares", 400)
        else:
            # Add transaction to table
            db.execute("INSERT INTO transactions (symbol, price, user_id, shares, comp_name, bought_sold) VALUES (?, ?, ?, ?, ?, ?)",
                       quoted["symbol"], sale, session["user_id"], shares, quoted["name"], 'sold')

            # Add or update portfolio
            old_shares = db.execute("SELECT shares FROM portfolio WHERE symbol = ? AND user_id = ?", symbol, session["user_id"])
            new_shares = old_shares[0]["shares"] - shares
            db.execute("INSERT OR REPLACE INTO portfolio (symbol, shares, comp_name, user_id) VALUES (?, ?, ?, ?)",
                       quoted["symbol"], new_shares, quoted["name"], session["user_id"])

            # Update user cash balace
            db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", sale, session["user_id"])

            # Redirect user to home page
            flash("Sale complete")
            return redirect("/")

    # Handle GET request
    else:
        return render_template("sell.html", shares_owned=shares_owned)


@app.route("/balance", methods=["GET", "POST"])
@login_required
def balance():
    """Add cash to user"""

    if request.method == "POST":
        cash = request.form.get("cash")

        if cash.isdigit() == False:
            return apology("Please input valid amount", 400)
        else:
            db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", float(cash), session["user_id"])

        # Redirect user to home page
        flash("Cash added")
        return redirect("/")

    # Handle GET request:
    else:
        return render_template("balance.html")