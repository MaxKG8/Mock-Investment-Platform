import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
# This is a library that does password hash for me
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Jinja Stuff ----- Doesnt een get used(idk)
import jinja2


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


# Homepage
@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Get account cash balance
    cash = float(db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]['cash'])

    # Get account net worth
    shares = db.execute("SELECT symbol, name, price, SUM(shares) as shareSum FROM transactions WHERE user_id = ? GROUP BY symbol", session["user_id"])

    # Initializing net worth as cash on hand and we will add worth in shares after
    net_worth = cash

    # Adding share worth to cash worth which is already included in net_worth variable
    for share in shares:
        net_worth += float(share["price"]) * int(share["shareSum"])

    return render_template("index.html", cash=round(cash, 2), shares=shares, net_worth=round(net_worth, 2) ,usd_function=usd)

# (buy * shares combining each) - (sell * shares combining each)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        stock_quant = request.form.get("shares")
        stock_dict = lookup(request.form.get("symbol"))
        user_id = session["user_id"]

        # Selecting from db always returns a list of dictionaries
        money = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        # So pick the wanted key within the 0th list value to get what u want
        money = float(money[0]['cash'])

        # check if letters were submitted to the stock_quant
        if stock_quant.isnumeric() == False:
            return apology("must provide a valid quantity", 400)

        # If no ticker symbol is inputted
        elif not request.form.get("symbol"):
            return apology("must provide ticker-symbol", 400)
        elif not request.form.get("shares"):
            return apology("must provide quantity", 400)

        # If no valid ticker symbol was inputted
        elif stock_dict == None:
            return apology("must provide a valid ticker-symbol", 400)

        # If invalid quantity inputted
        elif float(stock_quant) <= 0:
            return apology("must provide a positive quantity", 400)
        elif float(stock_quant) % 1 != 0.0:
            return apology("must buy a whole share", 400)

        # If the user has enough money to afford the shares they want
        elif ((int(stock_quant)*float(stock_dict['price'])) > money):
            return apology("YOU ARE BROKE", 400)

        # If all goes well
        else:
            purchase_price = (int(stock_quant)*float(stock_dict['price']))
            db.execute("UPDATE users SET cash = ? WHERE id = ?", money-purchase_price, user_id)

            # This will add to a central database with all transactions done on the website
            # Time and id are auto incremented so ion gotta add to em
            db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES (?, ?, ?, ?, ?, ?)",
                        user_id, stock_dict['name'], int(stock_quant), float(stock_dict['price']), "buy", stock_dict['symbol'])

            # Send user to portfolio page
            return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    history = db.execute("SELECT symbol, name, shares, price, time FROM transactions WHERE user_id = ?", session["user_id"])
    print(history)

    return render_template("history.html", history=history, usd_function=usd)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

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
    # If ticker-symbol form is submitted
    if request.method == "POST":

        # If no ticker symbol is inputted
        if not request.form.get("symbol"):
            return apology("must provide ticker-symbol", 400)
        # If no valid ticker symbol was inputted
        elif lookup(request.form.get("symbol")) == None:
            return apology("must provide a valid ticker-symbol", 400)

        # If the lookup funciton sucessfully finds the ticker
        else:
            # says quote undefined cuz its tryina render it when it still hasent been looked for
            quote_dict = lookup(request.form.get("symbol"))

            # Re-renders the template and returns the variable, quote_dict, to make available in the template.
            # Also imports the usd function into the html to be used there with jinja
            return render_template("quote.html", quote_dict=quote_dict, usd_function=usd)

    # If no form is submitted just display regular page
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure register-username is availible...   This is finding the rows where the username matches the one inputted
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must create username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must create password", 400)

        # Ensure password confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        # Ensure password confirmation matches password
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        # Ensure username doesnt already exist in sql database
        elif len(rows) != 0:
            return apology("Username already taken", 400)

        # ADD PASSWORD AND USERNAME TO SQL DATABASE IF ALL ABOVE IF STATEMENTS ARE SKIPPED (MEANING ERRYTHING GOOD)
        else:
            # Use function to generate password hash
            hash_password = generate_password_hash(request.form.get("password"))

            # Put registered-username and hashed password into sql database
            db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?)",
                request.form.get("username"),
                hash_password
            )

        # Redirect user to home page
        return redirect("/login")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":
        symbol = request.form.get("symbol")
        quant_sell = request.form.get("shares")
        shares = db.execute("SELECT SUM(shares) FROM transactions WHERE user_id = ? AND symbol = ?", session["user_id"], symbol)

        # check if letters were submitted to the stock_quant
        if quant_sell.isnumeric() == False:
            return apology("must provide a valid quantity", 400)

        # If no input in quantity
        elif not quant_sell:
            return apology("must provide quantity", 400)

        # If user doesnt chose a ticker
        if symbol == None:
            return apology("must chose a stock to sell", 400)

        # If invalid quantity inputted
        elif float(quant_sell) <= 0:
            return apology("must provide a positive quantity", 400)
        elif float(quant_sell) % 1 != 0.0:
            return apology("must sell a whole share", 400)

        # If user dont have that many shares
        elif (int(shares[0]['SUM(shares)']) < int(quant_sell)):
            return apology("You don't have enough shares to sell", 400)

        # If all goes well
        else:
            # Get share price
            share_price = lookup(symbol)['price']
            # db.execute gives list of dicts
            user_money = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]['cash']
            db.execute("UPDATE users SET cash = ? WHERE id = ?", float(user_money) + int(quant_sell)*float(share_price), session["user_id"])
            db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES (?, ?, ?, ?, ?, ?)",
                        session["user_id"], lookup(symbol)['name'], -int(quant_sell), float(lookup(symbol)['price']), "sell", symbol)
            # Use -quant_sell so dat when the portfolio iterates through it subtracts shares from the total

            # Send user to portfolio page
            return redirect("/")

    else:
        # Gonna give me a list of dictionaries like [{symbol: 'TSLA'}, {symbol: 'GM'}]
        shares = db.execute("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol", session["user_id"])
        return render_template("sell.html", shares=shares)


# set api_key beefore starting flask ---->   export API_KEY=pk_64ccd2b3b24a450293fe2d2d25a8af68