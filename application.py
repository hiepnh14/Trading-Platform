import os
import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    stock = db.execute("SELECT * FROM stock WHERE id = ?", session["user_id"])
    print(stock)
    length = len(stock)
    name = [0 for row in stock]
    price = [0 for row in stock]
    subtotal = [0 for row in stock]
    #name = [lookup(row["symbol"])["name"] for row in stock]
    #price = [lookup(row["symbol"])["price"] for row in stock]
    user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
    cash = user[0]["cash"]
    total = cash
    for i in range(length):
        symbol = stock[i]["symbol"]
        name[i] = lookup(symbol)["name"]
        price[i] = lookup(symbol)["price"]
        subtotal[i] = price[i]*float(stock[i]["shares"])
        total += price[i]*float(stock[i]["shares"])
        price[i] = usd(price[i])
        subtotal[i] = usd(subtotal[i])
    return render_template("index.html", stock=stock, name=name, price=price, length=length, cash=usd(cash), total=usd(total), subtotal=subtotal)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        shares = request.form.get("shares")
        symbol = request.form.get("symbol").capitalize()
        if not shares:
            return apology("Please enter number of stocks", 400)
        if not symbol:
            return apology("Please enter symbol", 400)
        try:
            x = int(shares)
        except:
            return apology("Invalid shares", 400)

        # if isinstance(shares, int):
        #    return apology("Invalid shares", 400)


        if int(shares) <= 0:
            return apology("Invalid shares", 400)

        # A row of lookup
        look = lookup(symbol)
        if look == None:
            return apology("Invalid symbol", 400)

        now = format(datetime.datetime.now())
        userid = session["user_id"]
        stock = db.execute("SELECT * FROM stock WHERE id = ?", userid)

        user = db.execute("SELECT * FROM users WHERE id = ?", userid)
        cash = user[0]["cash"]

        # Check whether enough money or not
        if cash < look["price"]*float(shares):
            return apology("Cannot afford", 402)

        else:
            # Create id in the userstock table
            if stock == None or not stock:
                db.execute("INSERT INTO stock (id, symbol, shares) VALUES(?,?,?)", userid, look["symbol"], 0) #for proper symbol
            # Reduce the cash bank
            cash = cash - look["price"]*float(shares)
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, userid)
            # Check the stock symbol already appearred or not
            check = db.execute("SELECT * FROM stock WHERE id = ? INTERSECT SELECT * FROM stock WHERE symbol = ?",
                                userid, look["symbol"])
            print(check)
            if check == None or check == []:
                db.execute("INSERT INTO stock (id, symbol, shares) VALUES(?, ?, ?)", userid, look["symbol"], shares)
            else:
                current = check[0]["shares"] + int(shares)
                db.execute("UPDATE stock SET shares = ? WHERE id = ? AND symbol = ?", current, userid, look["symbol"])

            #Update history
            db.execute("INSERT INTO trans (id, symbol, shares, price, time) VALUES(?, ?, ?, ?, ?)", userid, look["symbol"], shares, look["price"], now)
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT * FROM trans WHERE id = ?", session["user_id"])
    return render_template("history.html", history=history)


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
    if request.method == "POST":
        if len(request.form.get("symbol")) == 0:
            return apology("MISSING SYMBOL", 400)
        symbol = request.form.get("symbol")
        if lookup(symbol) == None:
            return apology("INVALID SYMBOL", 400)
        return render_template("quoted.html", value=lookup(symbol), money=usd(lookup(symbol)["price"]))
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted and not duplicated
        if not request.form.get("username"):
            return apology("must provide username", 400)
        users = db.execute("SELECT * FROM users")
        for user in users:
            if str(request.form.get("username")) == user["username"]:
                return apology("Username is already registerred", 400)

        # Ensure password and the repassword was submitted
        if not request.form.get("password"):
            return apology("must provide password", 400)
        if not request.form.get("confirmation"):
            return apology("must re type the password", 400)
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("must enter the same passwords", 400)
        # Query database for username


        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", request.form.get("username"),
                    generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8))

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    stocks = db.execute("SELECT * FROM stock WHERE id = ?", session["user_id"])
    userid = session["user_id"]
    symbols = []
    shares = []

    for stock in stocks:
        symbols.append(stock["symbol"])

    if request.method == "POST":
        flag = 0
        symbol = request.form.get("symbol")
        number = int(request.form.get("shares"))
        if isinstance(request.form.get("shares"), int) or int(request.form.get("shares")) < 1:
            return apology("Invalid shares", 400)
        for stock in stocks:

            if symbol == stock["symbol"]:
                flag = 1
                # print(request.form.get("number"))
                if number <= int(stock["shares"]):
                    stock["shares"] = stock["shares"] - int(request.form.get("shares"))
                    user = db.execute("SELECT * FROM users WHERE id = ?", userid)
                    cash = user[0]["cash"]
                    # Send money to the cash
                    cash = cash + lookup(symbol)["price"]*number
                    db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, userid)

                    # update in stock table

                    db.execute("UPDATE stock SET shares = ? WHERE id = ? AND symbol = ?", stock["shares"], userid, symbol)

                    # update history
                    now = format(datetime.datetime.now())
                    db.execute("INSERT INTO trans (id, symbol, shares, price, time) VALUES(?, ?, ?, ?, ?)",
                                userid, symbol, - number, lookup(symbol)["price"], now)
                    return redirect("/")
                else:
                    return apology("Cannot sell more than you have", 400)
        if flag == 0:
            return apology("Wrong logic", 400)
    else:
        return render_template("sell.html", symbols=symbols)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)

# Modify your account
@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        cash_added = request.form.get("cash")
        if isinstance( cash_added, float):
            return apology("Invalid cash", 400)
        cash_added = float(cash_added)
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not cash_added and not password:
            return apology("NO REQUEST", 400)
        if not password:
            # update cash
            user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
            cash = user[0]["cash"]
            # Send money to the cash
            cash = cash + cash_added
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])
            return redirect("/")
        if not cash_added:
            # check password
            # Query database for username
            rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

            # Ensure username exists and password is correct
            if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
                return apology("invalid  password", 403)
            elif not confirmation:
                return apology("Must enter new password", 403)
            else:
                db.execute("UPDATE users SET hash = ? WHERE id = ?",
                generate_password_hash(confirmation, method='pbkdf2:sha256', salt_length=8), session["user_id"])
            return redirect("/")
        else:
            # update cash
            user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
            cash = user[0]["cash"]
            # Send money to the cash
            cash = cash + cash_added
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])
            # check password
            # Query database for username
            rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

            # Ensure username exists and password is correct
            if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
                return apology("invalid  password", 403)
            elif not confirmation:
                return apology("Must enter new password", 403)
            else:
                db.execute("UPDATE users SET hash = ? WHERE id = ?",
                generate_password_hash(confirmation, method='pbkdf2:sha256', salt_length=8), session["user_id"])
            return redirect("/")
    else:
        return render_template("/account.html")
# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
