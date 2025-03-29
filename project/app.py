import re
import smtplib
import random
import datetime
from email.mime.text import MIMEText
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import logging
from marley import apology, login_required, usd
from email.mime.multipart import MIMEMultipart
from werkzeug.utils import secure_filename

# Configure application
app = Flask(__name__)
app.secret_key = "secret_key"

if __name__ == "__main__":


    # Configure session to use filesystem (instead of signed cookies)
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_TYPE"] = "filesystem"
    Session(app)

    # Configure CS50 Library to use SQLite database
    db = SQL("sqlite:///kitchen.db")

    # set up the time as str
    now = datetime.datetime.now()
    time_str = now.strftime("%Y-%m-%d %H:%M:%S")

    # Email configuration (use environment variables for security)
    EMAIL_USERNAME = "paulkossi2007@gmail.com"
    EMAIL_PASSWORD = "jyrwbepbrsvurmbi"

    if not EMAIL_USERNAME or not EMAIL_PASSWORD:
        raise EnvironmentError(
            "Email credentials are not set. Please set EMAIL_USERNAME and EMAIL_PASSWORD environment variables.")


    def generate_verification_code():
        """Generates a 4-digit random verification code"""
        return random.randint(100000, 999999)


    def send_verification_email(email, code):
        """Send a verification email with the given code and a verification link"""
        expiration_time = datetime.datetime.now() + datetime.timedelta(minutes=15)

        msg = MIMEText(
            f"Copy the code to verify your email address to IYA PAUL KITCHEN: {code} The code will expire in 15 minutes.")
        msg['Subject'] = 'Your 6-digit verification code'
        msg['From'] = f"IYA PAUL KITCHEN <{EMAIL_USERNAME}>"
        msg['To'] = email

        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
                server.sendmail(msg['From'], [msg['To']], msg.as_string())
                return True
        except smtplib.SMTPAuthenticationError as e:
            logging.error(f"SMTP Authentication Error: {e}")
            return False
        except smtplib.SMTPConnectError as e:
            logging.error(f"SMTP Connection Error: {e}")
            return False
        except smtplib.SMTPException as e:
            logging.error(f"SMTP Error: {e}")
            return False
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            return False


    def is_valid_email(email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None


    def is_strong_password(password):
        """Check if the password is strong enough"""
        if len(password) < 8:
            return False
        if not re.search(r"\d", password):
            return False
        if not re.search(r"[A-Za-z]", password):
            return False
        return True


    def get_user_by_email(email):
        """Helper function to get user by email"""
        return db.execute("SELECT * FROM users WHERE email = ?", email)


    def get_user_by_username(username):
        """Helper function to get user by username"""
        return db.execute("SELECT * FROM users WHERE username = ?", username)


    def update_verification_code(email, code):
        """Helper function to generate and update verification code and expiration time."""
        expiration_time = datetime.datetime.now() + datetime.timedelta(minutes=15)
        db.execute("UPDATE users SET code = ?, time = ? WHERE email = ?", code, expiration_time, email)
        return code


    def normalize_phone_number(phone_number):
        # Remove spaces, hyphens, and non-breaking spaces
        phone_number = phone_number.strip().replace(" ", "").replace("-", "")
        phone_number = ''.join(c for c in phone_number if c.isnumeric())

        # Normalize international formats to start with "0"
        if phone_number.startswith("+234"):
            phone_number = "0" + phone_number[4:]
        elif phone_number.startswith("234"):
            phone_number = "0" + phone_number[3:]

        return phone_number


    def validate_nigerian_phone_number(phone_number):
        # Normalize input
        phone_number = normalize_phone_number(phone_number)

        # Ensure the number is exactly 11 digits and numeric
        if len(phone_number) != 11 or not phone_number.isdigit():
            print(f"Invalid length or non-numeric input: {phone_number}")
            return False

        pattern = r"^0(701|702|703|704|705|706|707|708|709|802|803|804|805|806|807|808|809|810|811|812|813|814|815|816|817|818|819|901|902|903|904|905|906|907|908|909|915|916|917|918|919)\d{7}$"
        print(f"Pattern: {pattern}")
        print(f"Phone number: {phone_number}")

        match = re.match(pattern, phone_number)
        print(f"Regex match result: {match}")
        return match is not None


    @app.after_request
    def after_request(response):
        """Ensure responses aren't cached"""
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Expires"] = 0
        response.headers["Pragma"] = "no-cache"
        return response


    @app.route("/logout")
    def logout():
        """Log user out"""
        session.clear()
        return redirect("/")


    @app.route("/login", methods=["GET", "POST"])
    def login():
        """Log user in"""
        registered = session.get("registered", None)

        if request.method == "GET":
            return render_template("login.html")

        if request.method == "POST":
            input_value = request.form.get("username")

            if "@" in input_value:
                rows = db.execute("SELECT * FROM users WHERE email = ?", input_value)
            else:
                rows = db.execute("SELECT * FROM users WHERE username = ?", input_value)

            if len(rows) != 1:
                return apology("INVALID NAME/EMAIL", 403)

            if not check_password_hash(rows[0]["hash"], request.form.get("password")):
                return apology("INCORRECT PASSWORD", 403)

            session["user_id"] = rows[0]["id"]

            if registered:
                session["registered"] = True

            return redirect("/")


    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "GET":
            return render_template("register.html")

        elif request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            email2 = request.form.get("email")
            confirmation = request.form.get("confirmation")
            existing_user = db.execute("SELECT * FROM users WHERE email = ?", email2)

            if not username or not email2 or not password or not confirmation:
                print("Missing fields")
                return apology("All fields are required", 400)

            if password != confirmation:
                print("Passwords do not match")
                return apology("Passwords are not the same", 400)

            if not is_valid_email(email2):
                print("Invalid email format")
                return apology("Invalid email address", 400)

            if not is_strong_password(password):
                print("Weak password")
                return apology("Password is not strong enough", 400)

            if existing_user:
                return apology("Email already registered")

            if get_user_by_username(username):
                return apology("Username already taken", 400)

            hashed_password = generate_password_hash(password)

            try:
                db.execute("INSERT INTO users (username, hash, email) VALUES (?, ?, ?)",
                        username, hashed_password, email2)
            except Exception as e:
                print(f"Database error: {e}")
                return apology("Database error", 400)

            session["email"] = email2

            code = generate_verification_code()
            update_verification_code(email2, code)  # Update the code in the database
            send_verification_email(email2, code)  # Send the email

            print("Registration successful")
            return redirect("/verify")


    @app.route("/verify", methods=["GET", "POST"])
    def verify():
        """Verify the user with the code sent to email or entered manually"""

        if request.method == "GET":
            return render_template("verify.html")

        if request.method == "POST":
            code_input = request.form.get("code")

            if not code_input:
                return apology("No verification code entered", 400)

            # Retrieve the user from the database
            user = get_user_by_email(session.get("email"))
            print(session.get("email"))

            if not user:
                return apology("User not found", 404)

            # Check expiration time (convert if necessary)
            expiration_time = user[0]["time"]
            if expiration_time is None:
                return apology("Verification code expired")

            # If the time is stored as a string, convert to datetime:
            if isinstance(expiration_time, str):
                expiration_time = datetime.datetime.strptime(expiration_time, "%Y-%m-%d %H:%M:%S")

            if expiration_time < datetime.datetime.now():
                return apology("Verification code expired")

            # Validate the code
            if user[0]["code"] == int(code_input):
                # Mark the user as verified
                db.execute("UPDATE users SET verified = 1 WHERE email = ?", session.get("email"))
                session.clear()  # Clear session after successful verification
                return redirect("/login")
            else:
                return apology("Invalid verification code")


    @app.route("/resendcode", methods=["GET"])
    def resendcode():
        """Resend verification code if the user requests it."""
        if "email" not in session:
            return redirect("/register")

        email = session["email"]
        user = get_user_by_email(email)

        if not user:
            return apology("User not found", 404)

        # Check if the verification code has expired before resending a new one
        if user[0]["time"] is None:
            return apology("Verification time not set yet. Please wait and try again.")

        if user[0]["time"] > datetime.datetime.now():
            return apology("Verification code not expired yet. Please try again later.")

        # Update the user's verification code and expiration time
        code = update_verification_code(email)

        # Send the new verification code via email
        if not send_verification_email(email, code):
            return apology("Failed to resend the verification email. Please try again.")

        # After successfully resending, redirect to the verification page
        return redirect("/verify")


    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        try:
            if request.method == "GET":
                print("Reached GET request")
                return render_template("forget_password.html")
            elif request.method == "POST":
                email = request.form.get("email")
                user = get_user_by_email(email)
                if not user:
                    return apology("Email not registered", 400)

                reset_code = generate_verification_code()
                print("Reset code generated")
                update_verification_code(email, reset_code)

                print("Sending email to:", email)
                if send_verification_email(email, reset_code):
                    print("Email sent successfully")
                    flash("A reset code has been sent to your email.", "info")
                    return redirect("/reset_password")
                else:
                    return apology("Failed to send email. Try again later.", 500)
        except Exception as e:
            logging.error(f"Unexpected error in forgot_password: {e}")
            return apology("An error occurred. Please try again later.", 500)


    @app.route("/reset_password", methods=["GET", "POST"])
    def reset_password():
        if request.method == "GET":
            return render_template("reset_password.html")

        elif request.method == "POST":
            code = request.form.get("code")
            password2 = request.form.get("password")
            confirmation2 = request.form.get("confirmation")

            # Validate inputs
            if not code or not password2 or not confirmation2:
                return apology("All fields are required", 400)

            if password2 != confirmation2:
                return apology("Passwords do not match", 400)

            if not is_strong_password(password2):
                return apology("Password is not strong enough", 400)

            # Find the user by the verification code
            user = db.execute("SELECT * FROM users WHERE code = ?", code)
            if not user:
                return apology("Invalid code", 400)

            # Check if the code has expired
            if user[0]["time"] < time_str:
                return apology("Verification code expired", 400)

            # Update the password
            print(f"password = {password2}")
            hashed_password = generate_password_hash(password2)
            db.execute("UPDATE users SET hash = ?, code = ?, time = ? WHERE id = ?",
                    hashed_password, code, time_str, user[0]["id"])

            flash("Password reset successfully. You can now log in.", "success")
            return redirect("/login")


    @app.route("/", methods=["GET"])
    @login_required
    def index():
        return render_template("welcome.html")


    @app.route("/menu", methods=["GET", "POST"])
    @login_required
    def menu():
        return render_template("menu.html")


    @app.route("/plate", methods=["POST"])
    @login_required
    def plate():
        order_data = request.form
        total_price = 0

        # Prices for the rice dishes
        menu_prices = {
            "jollof_rice": 500,
            "fried_rice": 500,
            "white_rice": 500,
            "beans": 500,
            "yam": 500
        }

        protein_prices = {
            "egg_qty": 300,
            "meat_qty": 100,
            "fish_qty": 500,
            "ponmo_qty": 100
        }

        # Initialize an empty dictionary to store the protein totals
        protein_totals = {}

        # Calculate the total for each protein and store in protein_totals
        for protein, price in protein_prices.items():
            quantity = order_data.get(protein, 0)
            if quantity:
                total_price += int(quantity) * price
                protein_totals[protein] = int(quantity) * price  # Store the total for this protein

        # Add other order prices (like rice dishes) to the total_price
        for item in ['jollof_rice', 'fried_rice', 'white_rice', 'beans', 'yam']:
            quantity = order_data.get(item, 0)
            if quantity:
                total_price += int(quantity)

        # Enforce minimum plate value
        if total_price < 2000:
            return apology("Plate value must be more than ₦2000")

        # Store the total price and order in the session
        session['total_price'] = total_price
        session['order_data'] = order_data.to_dict()

        # Pass protein_totals and total_price to the template
        return render_template('plate.html', order=order_data, protein_totals=protein_totals, total_price=total_price)


    @app.route("/location", methods=["GET", "POST"])
    def location():
        if request.method == "POST":
            # Collecting data from the form
            country = request.form.get("country", "").strip()
            state = request.form.get("state", "").strip()
            lga = request.form.get("lga", "").strip()
            address = request.form.get("address", "").strip()
            # Save address in session
            session['address'] = address

            phone_number = request.form.get("phone", "").strip()
            print(f"Input phone number: {phone_number}")

            # Check if the phone number is valid
            is_valid = validate_nigerian_phone_number(phone_number)
            print(f"Validation result: {is_valid}")

            if not is_valid:
                return apology("Invalid Nigeria Phone Number")

            # Check if the location is supported
            if country != "Nigeria" or state != "Lagos" or lga not in ["Shomolu", "Kosofe"]:
                return apology(
                    "Sorry, we currently only serve customers in Lagos, Shomolu, and Kosofe. "
                    "Please update your location and try again."
                )

            # Save the phone number in session and render the template
            session['number'] = phone_number
            return render_template("ls.html", lga=lga, address=address, phone_number=phone_number)

        # Render location form for GET request
        return render_template("location.html")


    @app.route("/payment", methods=["GET", "POST"])
    @login_required
    def payment():
        if request.method == "GET":
            return render_template("method.html")

        # Handle POST request
        payment_method = request.form.get("payment_method")
        total_price = session.get("total_price", 0)
        order_data = session.get("order_data", {})

        if not total_price or not order_data:
            return apology("No order found! Please create an order first.")

        if payment_method == "payment_on_delivery":
            process_order("on_delivery")
            return render_template("success2.html")

        elif payment_method == "payment_before_delivery":
            return render_template("payment.html", total_price=total_price)

        return apology("Invalid payment method selected.")


    @app.route("/success", methods=["GET"])
    @login_required
    def success():
        process_order("before_delivery")
        return render_template("success.html")


    # Helper Functions
    def process_order(payment_type):
        """Process the order and send a notification based on payment type."""
        save_order_to_db()
        send_notification(payment_type)


    def save_order_to_db():
        """Save the current order to the database."""
        user_id = session["user_id"]
        address = session.get("address")
        phone = session.get("number")
        total_price = session.get("total_price", 0)
        order_data = session.get("order_data", {})

        db.execute(
            """
            INSERT INTO kitchen (user_id, order_details, address, phone, total_price)
            VALUES (?, ?, ?, ?, ?)
            """,
            user_id, str(order_data), address, phone, total_price
        )


    def send_notification(payment_type):
        """Send an email notification to the kitchen owner."""
        user_id = session["user_id"]
        username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]["username"]
        address = session.get("address")
        phone = session.get("number")
        total_price = session.get("total_price", 0)
        order_data = session.get("order_data", {})

        body = generate_email_body(payment_type, username, order_data, total_price, address, phone)
        send_email(body)


    def generate_email_body(payment_type, username, order_data, total_price, address, phone):
        """Generate the email body content based on payment type."""
        if payment_type == "on_delivery":
            payment_note = f"Payment method is ON delivery. Call the user: {phone} to confirm order and process the order."
        else:
            payment_note = f"Payment method is BEFORE delivery. CONFIRM PAYMENT, call the user: {phone} and process the order."

        return f"""
        Hello,

        A new order has been placed:
        - User Name : {username}
        - Order Details: {order_data}
        - Total Cost: ₦{total_price}
        - Address: {address}
        - Phone: {phone}

        {payment_note}

        Regards,
        IYA PAUL KITCHEN
        """


    def send_email(body):
        """Send the email notification."""
        try:
            msg = MIMEMultipart()
            msg['From'] = f"IYA PAUL KITCHEN <{EMAIL_USERNAME}>"
            msg['To'] = "akpanonpaul6@gmail.com"
            msg['Subject'] = "New Order Notification"
            msg.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
                server.sendmail(msg['From'], msg['To'], msg.as_string())
        except Exception as e:
            logging.error(f"Error sending order notification: {e}")


    @app.route("/us", methods=["GET", "POST"])
    @login_required
    def us():
        return render_template("aboutus.html")


    @app.route("/contact", methods=["GET", "POST"])
    @login_required
    def contact():
        user_id = session.get("user_id")
        if request.method == "GET":
            # Fetch user information
            user_info = db.execute("SELECT username, email FROM users WHERE id = ?", user_id)
            if not user_info:
                return apology("User information not found", 404)

            kitchen_info = db.execute(
                "SELECT timestamp, total_price, order_details FROM kitchen WHERE user_id = ?", user_id)
            if not kitchen_info:
                return render_template("PI.html", username=user_info[0]["username"], email=user_info[0]["email"])
            return render_template("PI.html", username=user_info[0]["username"], email=user_info[0]["email"], time=kitchen_info[0]["timestamp"], amount=kitchen_info[0]["total_price"], order=kitchen_info[0]["order_details"])
        else:
            name = request.form.get("new-username")
            p1 = request.form.get("current-password")
            p2 = request.form.get("new-password")
            if name:
                db.execute("UPDATE users SET username = ? WHERE id = ?", name, user_id)
                return redirect("/contact")
            if p1 and p2:
                # Retrieve the hashed password from the database
                hashed_password = db.execute("SELECT hash FROM users WHERE id = ?", user_id)[0]['hash']

                # Check if the provided password matches the hashed password
                if not check_password_hash(hashed_password, p1):
                    return apology("Invalid user_password")
                else:
                    hashed_password = generate_password_hash(p2)
                    db.execute("UPDATE users SET hash = ? WHERE id = ?", hashed_password, user_id)
                    return redirect("/contact")

    app.run()
