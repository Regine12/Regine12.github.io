import os
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    jsonify,
    flash,
    redirect,
    url_for,
)
import sqlite3
import traceback
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from functools import wraps
from flask import redirect, url_for
import base64
import hashlib
import sqlite3

# Create the Flask app
app = Flask(__name__)
app.secret_key = "your-secret-key"  # Set a secret key for session management

# ________________ Database Setup and Authentication ______________________

# Database initialization

# Database configuration
DATABASE_PATH = "database.db"

# certificate authority (CA)
CA_CERTIFICATE_PATH = "ca_certificate.pem"
CA_PRIVATE_KEY_PATH = "ca_private_key.pem"
#
CERTIFICATE_PATH = "certificates"
# SSL context configuration
SSL_CONTEXT = ("server.crt", "server.key")


def init_database():
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS Persons (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                password TEXT NOT NULL,
                public_key TEXT NOT NULL,
                certificate TEXT NOT NULL
            );
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS Conversations (
                conversation_id INTEGER PRIMARY KEY,
                person1_id INTEGER,
                person2_id INTEGER,
                FOREIGN KEY (person1_id) REFERENCES Persons (id),
                FOREIGN KEY (person2_id) REFERENCES Persons (id)
            );
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS Messages (
                id INTEGER PRIMARY KEY,
                conversation_id INTEGER,
                sender_id INTEGER,
                receiver_id INTEGER,
                encrypted_message BLOB,
                signature BLOB,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (conversation_id) REFERENCES Conversations (conversation_id),
                FOREIGN KEY (sender_id) REFERENCES Persons (id),
                FOREIGN KEY (receiver_id) REFERENCES Persons (id)
            );
        """
        )

        conn.commit()


def create_database():
    print("Setting Up Database")
    if not os.path.exists(DATABASE_PATH):
        print("Creating Database")
        init_database()


# Call method to create the database on app startup
create_database()


# Helper function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def check_hashed_password(password, hashed_password):
    return hashed_password == hash_password(password)


def save_private_key_to_file(user_id, private_key_pem):
    user_certificate_dir = os.path.join(CERTIFICATE_PATH, str(user_id))
    os.makedirs(user_certificate_dir, exist_ok=True)

    with open(os.path.join(user_certificate_dir, "private_key.pem"), "wb") as f:
        f.write(private_key_pem)  # Write the private_key_pem directly as bytes


def get_private_key_from_file(user_id):
    user_certificate_dir = os.path.join(CERTIFICATE_PATH, str(user_id))
    private_key_path = os.path.join(user_certificate_dir, "private_key.pem")

    if not os.path.exists(private_key_path):
        return None

    with open(private_key_path, "rb") as f:
        return f.read()


def encrypt_message(public_key_pem, message):
    public_key = serialization.load_pem_public_key(
        public_key_pem, backend=default_backend()
    )
    encrypted_message = public_key.encrypt(
        message.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(encrypted_message).decode("utf-8")


def sign_message(private_key_pem, message):
    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None, backend=default_backend()
    )
    signature = private_key.sign(
        message.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(public_key_pem, message, signature):
    public_key = serialization.load_pem_public_key(
        public_key_pem, backend=default_backend()
    )
    try:
        signature = base64.b64decode(signature)
        public_key.verify(
            signature,
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def decrypt_message(private_key_pem, encrypted_message):
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem, password=None, backend=default_backend()
        )
        decoded_encrypted_message = base64.b64decode(encrypted_message)

        decrypted_message = private_key.decrypt(
            decoded_encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return decrypted_message.decode("utf-8")

    except ValueError as e:
        # Log the decryption failure
        traceback.print_exc()
        return "Decryption Failed: " + str(e)
    except Exception as e:
        # Log the decryption failure
        traceback.print_exc()
        return "Decryption Failed: " + str(e)


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_key_pem, public_key_pem


# Decorator function to require user login for specific routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            # If the 'user' key is not present in the session, the user is not logged in.
            # Redirect to the login page.
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


# Endpoints


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")

        # Check if the user already exists in the database
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM Persons WHERE email=?", (email,))
            existing_user = cursor.fetchone()

            if existing_user:
                flash("User already exists. Please log in.", "error")
                return redirect(url_for("login"))

            # Generate certificate pair for the user
            private_key_pem, public_key_pem = generate_key_pair()

            # Save the private key to file storage
            cursor.execute(
                """
                INSERT INTO Persons (name, email, password, public_key, certificate)
                VALUES (?, ?, ?, ?, ?)
                """,
                (name, email, hash_password(password), public_key_pem, "placeholder"),
            )

            user_id = cursor.lastrowid
            save_private_key_to_file(user_id, private_key_pem)

            conn.commit()

            flash("Account created successfully. Please log in.", "success")
            return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM Persons WHERE email=?", (email,))
            user = cursor.fetchone()

            if not user or not check_hashed_password(password, user[3]):
                flash("Invalid email or password.", "error")
                return redirect(url_for("login"))

            user_id, name, email, _, public_key_pem, _ = user
            private_key_pem = get_private_key_from_file(user_id)

            if not private_key_pem:
                flash("Error: Private key not found.", "error")
                return redirect(url_for("login"))

            # Store user information in the session
            session["user"] = {
                "id": user_id,
                "name": name,
                "email": email,
                "public_key": public_key_pem,
                "private_key": private_key_pem,
            }

            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))

    return render_template("login.html")


# ________________ Pages and Messaging ______________________


@app.route("/")
def landpage():
    return render_template("landpage.html")

def fetch_user_information(user_id):
    with sqlite3.connect("database.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name, email, password, public_key FROM Persons WHERE id = ?", (user_id,))
        user_information = cursor.fetchone()
    return user_information

@app.route("/credentials", methods=["GET"])
@login_required
def credentials():
    # Get the user name from the session
    user_name = session.get("user", {}).get("name")
    user_id = session.get("user", {}).get("id")

    # Fetch user credentials from the database
    user_information = fetch_user_information(user_id)

    # Extract the user information from the fetched data
    if user_information:
        user_email = user_information[1]
        user_password = user_information[2]
        user_public_key = user_information[3]
    else:
        # If user information is not found, you can handle this as needed
        user_email = None
        user_password = None
        user_public_key = None

    # Pass the user's name and other information to the template
    return render_template(
        "credentials.html",
        user_name=user_name,
        user_email=user_email,
        user_password=user_password,
        user_public_key=user_public_key,
    )


# Dashboard Page
@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    user = session.get("user")
    user_id = user.get("id")
    user_name = user.get("name")
    return render_template("dashboard.html", user_id=user_id, user_name=user_name)


@app.route("/test", methods=["GET"])
def test():
    # Generate a key pair
    private_key_pem, public_key_pem = generate_key_pair()

    # Define the original message
    message = "Hello World"

    print("Original Message:", message)

    # Sign the message with the private key
    signature = sign_message(private_key_pem, message)

    print("Signature:", signature)

    # Encrypt the message with the public key
    encrypted_message = encrypt_message(public_key_pem, message)

    print("Encrypted Message:", encrypted_message)

    # Decrypt the message with the private key
    decrypted_message = decrypt_message(private_key_pem, encrypted_message)

    print("Decrypted Message:", decrypted_message)

    # Verify the signature using the public key
    signature_verified = verify_signature(public_key_pem, decrypted_message, signature)

    print("Signature Verified:", signature_verified)

    # Check if the decrypted message matches the original message
    message_match = decrypted_message == message

    return jsonify(
        {
            "message": message,
            "encrypted_message": encrypted_message,
            "signature": signature,
            "decrypted_message": decrypted_message,
            "signature_verified": signature_verified,
            "message_match": message_match,
            "public_key": public_key_pem.decode("utf-8"),
            "private_key": private_key_pem.decode("utf-8"),
        }
    )


@app.route("/chat", methods=["GET"])
@login_required
def chat():
    user = session.get("user")
    user_name = user.get("name")

    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()

        # Fetch all users and their public keys (excluding the current user)
        cursor.execute(
            "SELECT id, name, public_key FROM Persons WHERE id != ?", (user["id"],)
        )
        users = cursor.fetchall()

    return render_template("chat.html", users=users, user_name=user_name)


def get_public_key_from_db(user_id):
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT public_key FROM Persons WHERE id=?", (user_id,))
        result = cursor.fetchone()
        if result:
            return result[0]
    return None


# Helper function to get or create a conversation between two users
def get_or_create_conversation(sender_id, receiver_id):
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()

        # Check if a conversation exists between the sender and receiver
        cursor.execute(
            "SELECT conversation_id FROM Conversations "
            "WHERE (person1_id = ? AND person2_id = ?) OR (person1_id = ? AND person2_id = ?)",
            (sender_id, receiver_id, receiver_id, sender_id),
        )
        result = cursor.fetchone()

        if result:
            conversation_id = result[0]
        else:
            # If no conversation exists, create a new one and get the conversation_id
            cursor.execute(
                "INSERT INTO Conversations (person1_id, person2_id) VALUES (?, ?)",
                (sender_id, receiver_id),
            )
            conversation_id = cursor.lastrowid

    return conversation_id


@app.route("/send-message", methods=["POST"])
def send_message():
    if request.method == "POST":
        # Get the receiver's name and message from the request
        data = request.get_json()
        receiver_name = data.get("receiver_name")
        message = data.get("message")

        user = session.get("user")
        sender_name = user.get("name")

        # Check if the sender ID is available in the session
        user_id = user.get("id")
        if user_id is None:
            return jsonify({"error": "Sender ID not found in the session."}), 500

        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()

            # Find the receiver's ID
            cursor.execute("SELECT id FROM Persons WHERE name=?", (receiver_name,))
            receiver = cursor.fetchone()

            if not receiver:
                return jsonify({"error": f"Receiver '{receiver_name}' not found."}), 404

            receiver_id = receiver[0]

            # Check if the receiver ID is available and not None
            if receiver_id is None:
                return jsonify({"error": "Receiver ID not found in the database."}), 500

            #
            conversation_id = get_or_create_conversation(
                sender_id=user_id, receiver_id=receiver_id
            )

            # Get the receiver's public key
            cursor.execute("SELECT public_key FROM Persons WHERE id=?", (receiver_id,))
            receiver_public_key_pem = cursor.fetchone()[0]

            # Encrypt the message with the receiver's public key
            encrypted_message = encrypt_message(receiver_public_key_pem, message)

            # Sign the message with the sender's private key
            sender_private_key_pem = user.get("private_key")
            signature = sign_message(sender_private_key_pem, encrypted_message)

            # Save the message in the database
            cursor.execute(
                """
                INSERT INTO Messages (conversation_id, sender_id, receiver_id, encrypted_message, signature)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    conversation_id,
                    user_id,
                    receiver_id,
                    encrypted_message,
                    signature,
                ),
            )

            conn.commit()

            return jsonify({"success": True}), 200


@app.route("/get-conversation/<receiver_name>", methods=["GET"])
@login_required
def get_conversation(receiver_name):
    user = session.get("user")
    user_id = user.get("id")
    user_private_key_pem = user.get("private_key")
    user_public_key_pem = user.get("public_key")

    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()

        # Find the receiver's ID
        cursor.execute("SELECT id FROM Persons WHERE name=?", (receiver_name,))
        receiver = cursor.fetchone()

        if not receiver:
            return jsonify({"error": f"Receiver '{receiver_name}' not found."}), 404

        receiver_id = receiver[0]

        conversation_id = get_or_create_conversation(user_id, receiver_id)

        if not conversation_id:
            return jsonify({"error": "Conversation not found."}), 404

        # Fetch conversation messages
        cursor.execute(
            """
            SELECT m.encrypted_message, m.sender_id, m.timestamp, m.signature
            FROM Messages m
            WHERE conversation_id = ?
            ORDER BY m.timestamp ASC
            """,
            (conversation_id,),
        )
        conversation = cursor.fetchall()

    conversation_messages = []

    for msg in conversation:
        encrypted_message = msg[0]
        sender_id = msg[1]
        signature = msg[3]

        # Determine if the message was sent by the user or the receiver
        is_user_message = sender_id == user_id

        if is_user_message:
            receiver_private_key_pem = get_private_key_from_file(receiver_id)
            if not receiver_private_key_pem:
                return (
                    jsonify({"error": "Private key not found for the receiver."}),
                    500,
                )
            # The message was sent by the user, so we decrypt it using the user's private key
            decrypted_message = decrypt_message(
                receiver_private_key_pem, encrypted_message
            )
        else:
            decrypted_message = decrypt_message(user_private_key_pem, encrypted_message)

        if decrypted_message.startswith("Decryption Failed"):
            # Message could not be decrypted, it may be corrupted or tampered
            continue

        signature_verified = bool(signature)

        conversation_messages.append(
            {
                "message": decrypted_message,
                "sender": user.get("name") if is_user_message else receiver_name,
                "time": msg[2],
                "signature": signature,
                "signature_verified": signature_verified,
            }
        )
    return jsonify({"conversation": conversation_messages})


@app.route("/settings", methods=["GET"])
def settings():
    # Get the user name from the session
    user_name = session.get("user", {}).get("name")

    # Add logic to fetch user settings or other related data if needed

    # Pass the user's name to the template
    return render_template("settings.html", user_name=user_name)


# Logout Endpoint
@app.route("/logout")
def logout():
    # Clear the user information from the session
    session.pop("user", None)
    return redirect("/")


if __name__ == "__main__":
    app.run(ssl_context=SSL_CONTEXT, use_reloader=True)
