from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import traceback # Import traceback

# --- Core App Imports ---
from auth import register_user, login_user, is_password_strong # is_password_strong needed for register
from database import get_db_connection
from crypto import get_master_key, get_phe_keys # For initialization only
import blockchain # Import blockchain for logging

# --- Blueprint Imports ---
from routes.admin.logs import admin_logs_bp
from routes.admin.user_management import admin_user_management_bp
from routes.admin.stats import admin_stats_bp
from routes.doctor import doctor_bp, render_doctor_dashboard
# --- Import the new doctor_stats blueprint ---
from routes.doctor_stats import doctor_stats_bp
# --- End Import ---
from routes.patient import patient_bp, render_patient_dashboard
from routes.pharmacist import pharmacist_bp, render_pharmacist_dashboard

app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- Initialize Crypto Keys ---
try:
    get_master_key()
    print("Master encryption key loaded/created successfully.")
    get_phe_keys() # Load/create PHE keys
    print("Homomorphic (PHE) keys loaded/created successfully.")
except Exception as e:
    print(f"CRITICAL ERROR during crypto initialization: {e}")

# --- Register Blueprints ---
app.register_blueprint(admin_logs_bp, url_prefix='/admin')
app.register_blueprint(admin_user_management_bp, url_prefix='/admin')
app.register_blueprint(admin_stats_bp, url_prefix='/admin')
app.register_blueprint(doctor_bp)
# --- Register the new doctor_stats blueprint ---
app.register_blueprint(doctor_stats_bp, url_prefix='/doctor') # Prefix with /doctor
# --- End Registration ---
app.register_blueprint(patient_bp)
app.register_blueprint(pharmacist_bp)

# --- Cache Control ---
@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

# --- Core Routes (Login, Logout, Register, Main Dashboard Router) ---

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        private_key_file = request.files.get('private_key_file') # Get the uploaded file

        private_key_pem_bytes = None
        if private_key_file and private_key_file.filename != '':
            try:
                private_key_pem_bytes = private_key_file.read()
                # Basic check if it looks like PEM - REMOVED length print
                if b'-----BEGIN RSA PRIVATE KEY-----' not in private_key_pem_bytes:
                     flash('Invalid private key file format (missing PEM header).', 'danger')
                     blockchain.log_action_to_blockchain(
                         user_id=None,
                         action='LOGIN_FAILURE',
                         details=f"Attempt for {username}. Reason: Invalid key format (no header)"
                     )
                     return render_template('login.html')
            except Exception as e:
                flash(f'Error reading private key file: {e}', 'danger')
                blockchain.log_action_to_blockchain(
                    user_id=None,
                    action='LOGIN_FAILURE',
                    details=f"Attempt for {username}. Reason: Error reading key file ({e})"
                )
                return render_template('login.html')
        elif not private_key_file or private_key_file.filename == '':
             # REMOVED print statement
             pass # Allow login_user to check if key is required

        # login_user now returns (user_data, error_message)
        # user_data will NOT contain the private key anymore
        user_data, error_message = login_user(username, password, private_key_pem_bytes)

        if user_data:
            session['user_id'] = user_data['user_id']
            session['username'] = user_data['username']
            session['role'] = user_data['role_name']
            session['attributes'] = user_data['attributes']
            # --- REMOVED private key storage in session ---
            # session['private_key_pem'] = user_data.get('private_key_pem') # Bytes
            session['public_key_pem'] = user_data.get('public_key_pem') # String

            flash('Logged in successfully!', 'success')
            blockchain.log_action_to_blockchain(
                user_id=user_data['user_id'],
                action='LOGIN_SUCCESS',
                details=f"User {username} logged in."
            )
            return redirect(url_for('dashboard'))
        else:
            flash(f'Login Failed: {error_message}', 'danger')
            blockchain.log_action_to_blockchain(
                user_id=None,
                action='LOGIN_FAILURE',
                details=f"Attempt for {username}. Reason: {error_message}"
            )
            return render_template('login.html')

    # For GET request
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles patient self-registration."""
    if request.method == 'POST':
        full_name = request.form['full_name']
        password = request.form['password'].strip()
        confirm_password = request.form['confirm_password'].strip()
        age_str = request.form.get('age')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')

        is_strong, error_msg = is_password_strong(password)
        if not is_strong:
            flash(error_msg, 'danger')
            return render_template('register.html')

        age = None
        if age_str and age_str.isdigit():
            age = int(age_str)
        elif age_str:
            flash("Invalid age provided.", "warning")
            return render_template('register.html')

        role_name = 'patient'
        profile_data = {}

        # Register user (gets private key back - DO NOT LOG IT HERE)
        user_id, new_username, private_key_pem = register_user(
            full_name, password, role_name, profile_data, age=age
        )

        if user_id and private_key_pem:
            # Temporarily store key in session ONLY for immediate download prompt
            # Use a more secure mechanism (like one-time token cache) in production
            flash(f'Registration successful! Your username is {new_username}. Please download your private key.', 'success')
            session['download_key_pem'] = private_key_pem.decode('utf-8')
            session['download_key_username'] = new_username
            # Redirect to download prompt page (using admin user management blueprint endpoint)
            # This endpoint needs to be accessible without admin login if used for self-registration
            # Or create a separate download prompt route outside admin blueprint
            return redirect(url_for('admin_user_management.prompt_download_key')) # Assuming this works for now
        else:
            flash('Registration failed. Username might be taken or invalid data.', 'danger')
            return render_template('register.html')

    # For GET request
    return render_template('register.html')


@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    username = session.get('username', 'Unknown')
    session.clear() # Clears everything, including temp download keys if any
    flash('You have been logged out.', 'info')
    if user_id:
        blockchain.log_action_to_blockchain(
            user_id=user_id,
            action='LOGOUT',
            details=f"User {username} logged out."
        )
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    """Acts as a router to the correct role-specific dashboard rendering function."""
    if 'user_id' not in session:
        flash('You must be logged in.', 'warning')
        return redirect(url_for('login'))

    role = session.get('role')
    view = request.args.get('view', 'tiles')

    try:
        if role == 'doctor':
            # doctor_bp's render_doctor_dashboard handles all its views including 'insights'
            return render_doctor_dashboard()
        elif role == 'pharmacist':
            return render_pharmacist_dashboard()
        elif role == 'admin':
            if view == 'logs':
                 role_filter = request.args.get('role_filter')
                 return redirect(url_for('admin_logs.view_logs', role_filter=role_filter))
            else: # Default is 'tiles'
                 return redirect(url_for('admin_logs.admin_dashboard_tiles'))
        elif role == 'patient':
            return render_patient_dashboard()
        else:
            flash(f'Unknown user role: {role}. Logging out.', 'danger')
            blockchain.log_action_to_blockchain(
                user_id=session.get('user_id'),
                action='ERROR',
                details=f"Unknown role '{role}' detected during dashboard access."
            )
            session.clear()
            return redirect(url_for('login'))
    except Exception as e:
        flash(f'Error loading dashboard: {e}', 'danger')
        print("--- ERROR RENDERING DASHBOARD ---")
        traceback.print_exc()
        print("--- SESSION DATA ---")
        print(session) # Okay to print session data here for debug, EXCLUDES private key now
        print("--------------------")
        blockchain.log_action_to_blockchain(
            user_id=session.get('user_id'),
            action='ERROR',
            details=f"Dashboard rendering failed for role '{role}': {e}"
        )
        return "An error occurred while loading your dashboard. Please contact support.", 500


if __name__ == '__main__':
    # Make sure threaded=False for SQLite if encountering issues, debug=True for development
    app.run(debug=True, threaded=False)
