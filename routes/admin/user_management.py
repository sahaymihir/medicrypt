from flask import (
    Blueprint, render_template, request, redirect, url_for, session, flash,
    send_file, after_this_request # Import send_file and after_this_request
)
import os # Import os for file deletion
import io # Import io for BytesIO
import traceback # Import traceback

# --- Project Imports ---
# Use absolute imports relative to the project root
from auth import register_user, is_password_strong
from database import get_db_connection
import blockchain # For logging actions

# Define the Blueprint for admin user management
admin_user_management_bp = Blueprint('admin_user_management', __name__,
                                     template_folder='../../templates') # Corrected path: Go up two levels for templates

# --- Routes ---

@admin_user_management_bp.route('/create_user_form')
def create_user_form():
    """Renders the form for creating a new user."""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))
    # Corrected template path reference
    return render_template('admin/admin_create_user_form.html')


@admin_user_management_bp.route('/create_user', methods=['POST'])
def admin_create_user():
    """Handles the creation of a new user by an admin."""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    # Basic form data
    full_name = request.form.get('full_name')
    role_name = request.form.get('role_name')
    password = request.form.get('password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()

    # Role-specific data
    profile_data = {}
    age = None
    # === ADDED: Get smoking status if role is patient ===
    smoking_status = 'unknown' # Default
    # === END ADDED ===

    if role_name == 'doctor':
        profile_data['department'] = request.form.get('department')
        profile_data['specialty'] = request.form.get('specialty')
        profile_data['hospital_id'] = request.form.get('hospital_id', 'KMC_Main') # Default if not provided
    elif role_name == 'patient':
        age_str = request.form.get('age')
        if age_str and age_str.isdigit():
            age = int(age_str)
        # === ADDED: Read smoking status from form ===
        smoking_status = request.form.get('smoking_status', 'unknown')
        # === END ADDED ===
    elif role_name == 'pharmacist':
        profile_data['pharmacy_name'] = request.form.get('pharmacy_name')
        profile_data['license_number'] = request.form.get('license_number')
    elif role_name == 'admin':
        profile_data['contact_email'] = request.form.get('contact_email')

    # --- Validation ---
    if not all([full_name, role_name, password, confirm_password]):
        flash('All fields except role-specific ones are required.', 'danger')
        # Corrected template path reference
        return render_template('admin/admin_create_user_form.html')

    if password != confirm_password:
        flash('Passwords do not match.', 'danger')
        # Corrected template path reference
        return render_template('admin/admin_create_user_form.html')

    is_strong, error_msg = is_password_strong(password)
    if not is_strong:
        flash(error_msg, 'danger')
        # Corrected template path reference
        return render_template('admin/admin_create_user_form.html')
    # --- End Validation ---

    # --- Register User ---
    try:
        # === UPDATED: Pass smoking_status to register_user ===
        user_id, new_username, private_key_pem = register_user(
            full_name, password, role_name, profile_data, age, smoking_status
        )
        # === END UPDATE ===

        if user_id and private_key_pem:
            flash(f'Successfully created {role_name} "{full_name}" with username "{new_username}".', 'success')
            blockchain.log_action_to_blockchain(
                user_id=session['user_id'], # Admin user ID
                action=blockchain.ACTION_ADMIN_CREATE_USER_SUCCESS,
                details=f"Admin created {role_name} {new_username}"
            )

            # Store key temporarily for download prompt
            session['download_key_pem'] = private_key_pem.decode('utf-8')
            session['download_key_username'] = new_username
            return redirect(url_for('admin_user_management.prompt_download_key'))

        else:
            # register_user should ideally return a reason, but provide a generic one if not
            flash('User creation failed. Username might be taken or invalid data provided.', 'danger')
            blockchain.log_action_to_blockchain(
                user_id=session['user_id'],
                action=blockchain.ACTION_ADMIN_CREATE_USER_FAILED,
                details=f"Admin failed to create {role_name} {full_name}. Reason: Registration function failed."
            )
            # Corrected template path reference
            return render_template('admin/admin_create_user_form.html')

    except Exception as e:
        flash(f"An unexpected error occurred: {e}", "danger")
        print("--- ERROR DURING ADMIN USER CREATION ---")
        traceback.print_exc()
        blockchain.log_action_to_blockchain(
            user_id=session['user_id'],
            action=blockchain.ACTION_ADMIN_CREATE_USER_FAILED,
            details=f"Admin failed to create {role_name} {full_name}. Reason: Exception - {e}"
        )
        # Corrected template path reference
        return render_template('admin/admin_create_user_form.html')


@admin_user_management_bp.route('/prompt_download_key')
def prompt_download_key():
    """Shows a page prompting the user to download their key."""
    if 'download_key_pem' not in session or 'download_key_username' not in session:
        flash('No key available for download or session expired.', 'warning')
        # Redirect based on role if needed, or just to admin dashboard/login
        if session.get('role') == 'admin':
            # Assuming admin_logs blueprint has the main admin dashboard tiles route
            return redirect(url_for('admin_logs.admin_dashboard_tiles'))
        else:
             return redirect(url_for('login')) # Non-admins go to login

    username = session['download_key_username']
    # Do NOT pass the key itself to the template
    # Corrected template path reference
    return render_template('admin/admin_download_key.html', username=username)


@admin_user_management_bp.route('/download_private_key')
def download_private_key():
    """Provides the generated private key as a file download."""
    if 'download_key_pem' not in session or 'download_key_username' not in session:
        flash('Key download session expired or invalid.', 'warning')
        if session.get('role') == 'admin':
            return redirect(url_for('admin_logs.admin_dashboard_tiles'))
        else:
             return redirect(url_for('login'))


    key_pem = session['download_key_pem']
    username = session['download_key_username']
    filename = f"{username.replace('@', '_at_').replace('.', '_dot_')}_private_key.pem"

    # Use BytesIO to send the string data as a file
    key_bytes = key_pem.encode('utf-8')
    buffer = io.BytesIO(key_bytes)
    buffer.seek(0)

    # Clear the key from session *after* setting up the response
    @after_this_request
    def clear_key(response):
        session.pop('download_key_pem', None)
        session.pop('download_key_username', None)
        session.modified = True # Ensure session changes are saved
        print("Cleared private key from session after download request.")
        return response

    return send_file(
        buffer,
        mimetype='application/x-pem-file',
        as_attachment=True,
        download_name=filename
    )


# --- Example: Add user listing later ---
# @admin_user_management_bp.route('/list_users')
# def list_users():
#     # ... fetch users from DB ...
#     return render_template('admin/admin_list_users.html', users=users) # Use admin/ subfolder

