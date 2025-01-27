from bs4 import BeautifulSoup
from flask import Flask, render_template, redirect, url_for, flash, session, request, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import DataRequired, Email, ValidationError, Regexp, Length
import bcrypt
from flask_mysqldb import MySQL
from datetime import datetime, time, timedelta

# Tworzymy instancję aplikacji
app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '2011'
app.config['MYSQL_DB'] = 'arcade_games_system'
app.secret_key = 'b19e77c69a9947c3b34d1a631f3bf431'

mysql = MySQL(app)

HOURS = {
    "Monday": (time(10, 0), time(23, 59)),
    "Tuesday": (time(10, 0), time(23, 59)),
    "Wednesday": (time(10, 0), time(23, 59)),
    "Thursday": (time(10, 0), time(23, 59)),
    "Friday": (time(10, 0), time(23, 59)),
    "Saturday": (time(10, 0), time(23, 59)),
    "Sunday": (time(12, 0), time(23, 59)),
}


@app.route('/system_tests', methods=['GET', 'POST'])  # Zmiana adresu URL i nazwy funkcji
def system_tests():
    test_output = []
    raw_output = ""

    if request.method == 'POST':
        tests = [
            ('Database Connection', test_database_connection),
            ('User Registration', test_registration),
            ('User Login', test_login),
            ('Reservation System', test_reservation),
            ('Game Availability', test_game_availability),
            ('Invalid Registration', test_invalid_registration),
            ('Past Reservation', test_past_reservation)
        ]

        for test_name, test_function in tests:
            try:
                result = test_function()
                test_output.append(format_test_result(test_name, result))
            except Exception as e:
                test_output.append({
                    "name": test_name,
                    "status": "ERROR",
                    "details": f"Test crashed: {str(e)}"
                })

        raw_output = "\n".join([f"{test['name']}: {test['status']} - {test['details']}" for test in test_output])

    return render_template('TestSystem.html', test_output=test_output, raw_output=raw_output)


def format_test_result(name, result):
    if result is True:
        return {"name": name, "status": "PASS", "details": "Operation successful"}
    elif isinstance(result, str):
        return {"name": name, "status": "FAIL", "details": result}
    else:
        return {"name": name, "status": "FAIL", "details": "Unknown error"}


def test_login():
    test_user = {
        'email': 'test_login@example.com',
        'password': 'TestPassword123!'
    }

    cursor = None
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("DELETE FROM users WHERE email = %s", (test_user['email'],))
        mysql.connection.commit()

        hashed_password = bcrypt.hashpw(test_user['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute(
            "INSERT INTO users (first_name, last_name, email, password) VALUES (%s, %s, %s, %s)",
            ('Test', 'User', test_user['email'], hashed_password)
        )
        mysql.connection.commit()

        cursor.execute("SELECT * FROM users WHERE email = %s", (test_user['email'],))
        user = cursor.fetchone()
        if not user:
            return "Test user not inserted"

        with app.test_client() as client:
            # Bezpieczne pobranie aktualnej wartości CSRF
            original_csrf = app.config.get('WTF_CSRF_ENABLED', True)
            app.config['WTF_CSRF_ENABLED'] = False

            response = client.post(
                '/login',
                data={
                    'email': test_user['email'],
                    'password': test_user['password'],
                    'submit': 'Login'
                },
                follow_redirects=True
            )

            # Przywrócenie oryginalnych ustawień CSRF
            app.config['WTF_CSRF_ENABLED'] = original_csrf

            with client.session_transaction() as sess:
                if 'user_id' not in sess:
                    return "Session not set"

            if b"Login successful!" not in response.data:
                return "Login success message missing"

            return True

    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        if cursor:
            cursor.execute("DELETE FROM users WHERE email = %s", (test_user['email'],))
            mysql.connection.commit()
            cursor.close()

def test_reservation(test_data=None):
    try:
        # Domyślne dane testowe
        if test_data is None:
            test_data = {
                'game_id': 1,
                'reservation_date': datetime.now().date() + timedelta(days=1),
                'reservation_time': datetime.now().time(),
                'num_hours': 2,
                'num_people': 4
            }

        # Sprawdź datę
        if test_data['reservation_date'] < datetime.now().date():
            return "Cannot make reservation for past date"

        cursor = mysql.connection.cursor()

        # Utwórz rezerwację
        cursor.execute(
            """INSERT INTO reservations 
            (user_id, game_id, reservation_date, reservation_time, num_hours, num_people)
            VALUES (%s, %s, %s, %s, %s, %s)""",
            (1, test_data['game_id'], test_data['reservation_date'],
             test_data['reservation_time'], test_data['num_hours'], test_data['num_people'])
        )
        mysql.connection.commit()

        # Sprawdź istniejące rezerwacje
        cursor.execute(
            "SELECT * FROM reservations WHERE game_id = %s AND reservation_date = %s",
            (test_data['game_id'], test_data['reservation_date'])
        )
        reservations = cursor.fetchall()

        # Usuń testową rezerwację
        cursor.execute(
            "DELETE FROM reservations WHERE game_id = %s AND reservation_date = %s",
            (test_data['game_id'], test_data['reservation_date'])
        )
        mysql.connection.commit()
        cursor.close()

        return len(reservations) > 0

    except Exception as e:
        return f"Reservation error: {str(e)}"


def test_game_availability():
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM games WHERE availability = TRUE")  # Zmiana nazwy kolumny
        available_games = cursor.fetchall()
        cursor.close()
        return len(available_games) > 0
    except Exception as e:
        return f"Availability check error: {str(e)}"

def test_database_connection():
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT 1")  # Proste zapytanie testujące połączenie
        cursor.close()
        return True
    except Exception as e:
        return f"Database error: {str(e)}"

def test_registration():
    test_user = {
        'first_name': 'Test',
        'last_name': 'User',
        'email': 'test@example.com',
        'password': 'TestPassword123!'
    }

    try:
        cursor = mysql.connection.cursor()

        # Sprawdź, czy email istnieje
        cursor.execute("SELECT email FROM users WHERE email = %s", (test_user['email'],))
        if cursor.fetchone():
            return "Email already exists"

        # Hashuj hasło i dodaj użytkownika
        hashed_password = bcrypt.hashpw(test_user['password'].encode('utf-8'), bcrypt.gensalt())
        cursor.execute(
            "INSERT INTO users (first_name, last_name, email, password) VALUES (%s, %s, %s, %s)",
            (test_user['first_name'], test_user['last_name'], test_user['email'], hashed_password)
        )
        mysql.connection.commit()

        # Usuń użytkownika testowego
        cursor.execute("DELETE FROM users WHERE email = %s", (test_user['email'],))
        mysql.connection.commit()
        cursor.close()

        return True

    except Exception as e:
        return f"Registration error: {str(e)}"


# Dodaj nowe funkcje testowe
def test_invalid_registration():
    test_user = {
        'first_name': 'Test',
        'last_name': 'User',
        'email': 'test_invalid@example.com',
        'password': 'TestPassword123!'
    }

    cursor = None
    try:
        cursor = mysql.connection.cursor()
        hashed_password = bcrypt.hashpw(test_user['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute(
            "INSERT INTO users (first_name, last_name, email, password) VALUES (%s, %s, %s, %s)",
            (test_user['first_name'], test_user['last_name'], test_user['email'], hashed_password)
        )
        mysql.connection.commit()

        with app.test_client() as client:
            # Usunięto parsowanie CSRF
            response = client.post(
                '/register',
                data={
                    'first_name': 'Another',
                    'last_name': 'User',
                    'email': test_user['email'],
                    'password': 'DifferentPassword123!',
                    'submit': 'Register',
                },
                follow_redirects=True
            )

            if b'Email is already taken' not in response.data:
                return "Form validation failed to detect duplicate email"

        return True  # Zwracaj True zamiast "PASS"

    except Exception as e:
        return f"ERROR - {str(e)}"
    finally:
        if cursor:
            cursor.execute("DELETE FROM users WHERE email = %s", (test_user['email'],))
            mysql.connection.commit()
            cursor.close()


def test_past_reservation():
    try:
        test_data = {
            'game_id': 1,
            'reservation_date': datetime.now().date() - timedelta(days=1),
            'reservation_time': datetime.now().time(),
            'num_hours': 2,
            'num_people': 4
        }
        result = test_reservation(test_data)
        # Expecting an error message for past date
        return result == "Cannot make reservation for past date"
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        first_name = form.first_name.data
        last_name = form.last_name.data
        email = form.email.data
        password = form.password.data

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Store data into database with hashed password
        cursor = mysql.connection.cursor()
        cursor.execute(
            "INSERT INTO users (first_name, last_name, email, password) VALUES (%s, %s, %s, %s)",
            (first_name, last_name, email, hashed_password.decode('utf-8'))  # Store the hash as a string
        )
        mysql.connection.commit()
        cursor.close()

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT user_id FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            log_action(user[0], 'action', f"User registered with email {email}")

        return redirect(url_for('login'))

    return render_template('Register.html', form=form)

class RegisterForm(FlaskForm):
    first_name = StringField("First Name", validators=[
        DataRequired(message="First name is required"),
        Length(min=2, max=50, message="First name must be between 2 and 50 characters"),
        Regexp(r'^[A-Za-z]+$', message="First name must contain only letters")
    ])
    last_name = StringField("Last Name", validators=[
        DataRequired(message="Last name is required"),
        Length(min=2, max=50, message="Last name must be between 2 and 50 characters"),
        Regexp(r'^[A-Za-z]+$', message="Last name must contain only letters")
    ])
    email = StringField("Email", validators=[
        DataRequired(message="Email is required"),
        Email(message="Invalid email address format"),
        Length(max=100, message="Email cannot exceed 100 characters")
    ])
    password = PasswordField("Password", validators=[
        DataRequired(message="Password is required"),
        Length(min=5, message="Password must be at least 5 characters long"),
        Regexp(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
               message="Password must contain at least one letter, one number, and one special character")
    ])
    submit = SubmitField("Register")

    def validate_email(self, field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise ValidationError('Email is already taken')

def log_action(user_id, log_type, log_message):
    cursor = mysql.connection.cursor()
    cursor.execute("INSERT INTO logs (user_id, log_type, log_message) VALUES (%s, %s, %s)",
                   (user_id, log_type, log_message))
    mysql.connection.commit()
    cursor.close()


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[
        DataRequired(message="Email is required"),
        Email(message="Invalid email address format")
    ])
    password = PasswordField("Password", validators=[
        DataRequired(message="Password is required")
    ])
    submit = SubmitField("Login")


@app.route('/')
def index():
    if 'user_id' in session:
        user_id = session['user_id']

        # Pobranie informacji o zalogowanym użytkowniku
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users where user_id=%s", (user_id,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            # Przekazanie danych użytkownika do szablonu Index.html
            return render_template('Index.html', user=user)

    # Jeśli użytkownik nie jest zalogowany, wyświetl stronę główną bez danych użytkownika
    return render_template('Index.html', user=None)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        # Retrieve user from the database
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()

        # Validate the password using bcrypt
        if user and bcrypt.checkpw(password.encode('utf-8'), user[4].encode('utf-8')):  # Assuming `user[4]` is the password column
            session['user_id'] = user[0]
            flash("Login successful!")

            # Log the successful login action
            log_action(user[0], 'login', "Login successful")
            return redirect(url_for('index'))
        else:
            flash("Login failed. Please check your email and password")

            # Log the failed login attempt
            log_action(None, 'error', f"Failed login attempt for email {email}")
            return redirect(url_for('login'))

    return render_template('Login.html', form=form)


@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    session.pop('user_id', None)
    flash("You have been logged out successfully.")

    if user_id:
        # Logowanie akcji wylogowania
        log_action(user_id, 'action', "User logged out")

    return redirect(url_for('login'))

@app.route('/szablon')
def szablonik():
    return render_template('Szablon.html')

@app.route('/priceList')
def priceList():
    return render_template('PriceList.html')

@app.route('/reservation')
def reservation():
    if 'user_id' not in session:
        flash("You need to be logged in to view reservations.")
        return redirect(url_for('login'))

    user_id = session['user_id']

    cursor = mysql.connection.cursor()
    query = """
            SELECT reservation_id, game_name, reservation_date, reservation_time, num_people, num_hours, num_stations
            FROM user_reservations
            WHERE user_id = %s
        """
    cursor.execute(query, (user_id,))
    reservations = cursor.fetchall()
    cursor.close()

    if not reservations:
        flash("You have no reservations.")
        return render_template('Reservation.html', reservations=None)

    return render_template('Reservation.html', reservations=reservations)

@app.route('/contact')
def contact():
    return render_template('Contact.html')

@app.route('/billiard')
def billiard():
    return render_template('Billiard.html')

@app.route('/bowling')
def bowling():
    return render_template('Bowling.html')

@app.route('/dart')
def dart():
    return render_template('Dart.html')

@app.route('/shuffleboard')
def shuffleboard():
    return render_template('Shuffleboard.html')

@app.route('/check', methods=['POST'])
def check_availability():
    now = datetime.now()
    data = request.json
    data_rez = data['data']  # Reservation date (YYYY-MM-DD)
    godzina = data['godzina']  # Reservation time (HH:MM)
    liczba_osob = data['liczba_osob']  # Number of people
    czas_gry = data['czas_gry']  # Duration of play (in hours)

    try:
        reservation_date = datetime.strptime(data_rez, "%Y-%m-%d").date()
        reservation_time = datetime.strptime(godzina, "%H:%M").time()
        czas_gry = int(czas_gry)
        liczba_osob = int(liczba_osob)

        if 'user_id' not in session:
            return jsonify({"error": "You must be logged in to make a reservation."}), 401

        user_id = session['user_id']

        # Sprawdzenie, czy data i godzina rezerwacji jest w przyszłości
        reservation_datetime = datetime.combine(reservation_date, reservation_time)
        if reservation_datetime <= now:
            return jsonify({
                "error": "You cannot make a reservation for a past date or time."
            }), 400

        day_name = reservation_date.strftime("%A")
        if day_name not in HOURS:
            return jsonify({"error": "Invalid reservation date."}), 400

        open_time, close_time = HOURS[day_name]

        # Porównanie godzin i minut dla czasu rozpoczęcia
        if reservation_time.hour < open_time.hour or (
            reservation_time.hour == open_time.hour and reservation_time.minute < open_time.minute
        ):
            return jsonify({
                "error": f"The reservation time is before opening hours: {open_time.strftime('%H:%M')}."
            }), 400

        # Oblicz koniec rezerwacji
        reservation_end_time = (datetime.combine(reservation_date, reservation_time) +
                                 timedelta(hours=czas_gry)).time()

        # Porównanie godzin i minut dla czasu zakończenia
        if reservation_end_time.hour == 0 or (
            reservation_end_time.hour == close_time.hour and reservation_end_time.minute == 0
        ):
            return jsonify({
                "error": "The reservation exceeds the venue's opening hours."
            }), 400

        cursor = mysql.connection.cursor()
        query_reservations = """
            SELECT * FROM reservations
            WHERE reservation_date = %s
            AND ((reservation_time <= %s AND ADDTIME(reservation_time, SEC_TO_TIME(num_hours * 3600)) > %s)
                 OR (reservation_time < %s AND ADDTIME(reservation_time, SEC_TO_TIME(num_hours * 3600)) >= %s))
        """
        cursor.execute(query_reservations, (reservation_date, reservation_time, reservation_time,
                                            reservation_end_time, reservation_end_time))
        existing_reservations = cursor.fetchall()

        query_user_reservation = """
            SELECT * FROM reservations
            WHERE reservation_date = %s
            AND reservation_time = %s
            AND user_id = %s
        """
        cursor.execute(query_user_reservation, (reservation_date, reservation_time, user_id))
        user_reservation = cursor.fetchone()
        cursor.close()

        if user_reservation:
            return jsonify({
                "error": "You have already made a reservation for the selected date and time."
            }), 400

        if existing_reservations:
            return jsonify({"error": "There is already a reservation for the selected time."}), 400

        return jsonify({"message": "The time is available for reservation."}), 200

    except ValueError as e:
        return jsonify({"error": "Invalid input data format."}), 400

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/submit_reservation', methods=['POST'])
def submit_reservation():
    try:
        data_rez = request.form['data']
        godzina = request.form['godzina']
        czas_gry = int(request.form['czas-gry'].strip('h'))
        liczba_osob = int(request.form['ilosc-graczy'])
        ilosc_stanowisk = int(request.form['ilosc-stanowisk'])
        game_id = int(request.form['game_id'])

        if 'user_id' not in session:
            return jsonify({"error": "You must be logged in to make a reservation."}), 401

        user_id = session['user_id']

        reservation_date = datetime.strptime(data_rez, "%Y-%m-%d").date()
        reservation_time = datetime.strptime(godzina, "%H:%M").time()

        # Insert reservation into the database
        cursor = mysql.connection.cursor()
        insert_query = """
            INSERT INTO reservations (user_id, game_id, reservation_date, reservation_time, num_hours, num_people, num_stations)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (user_id, game_id, reservation_date, reservation_time, czas_gry, liczba_osob, ilosc_stanowisk))
        mysql.connection.commit()
        cursor.close()

        return jsonify({"message": "Reservation successfully submitted!"}), 200

    except ValueError as e:
        return jsonify({"error": "Invalid input data format."}), 400

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500



if __name__ == '__main__':
    app.run(debug=True, port=80)