from flask import Blueprint, render_template, request, redirect, url_for, session, flash
import traceback

# CORRECTED: Use absolute imports
from database import get_db_connection

# Define the Blueprint for logs specifically
# REMOVED template_folder argument
admin_logs_bp = Blueprint('admin_logs', __name__,
                          static_folder='../../static') # Keep static if needed

# --- Routes for Viewing Logs ---

@admin_logs_bp.route('/') # Route for the default admin view (tiles)
@admin_logs_bp.route('/dashboard') # Optional alias
def admin_dashboard_tiles():
    """Renders the main admin dashboard view (tiles)."""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    user_data = {
        'display_name': session.get('attributes', {}).get('full_name', session.get('username')),
        'username': session.get('username'),
        'role': session.get('role')
    }
    template_data = { 'user': user_data, 'view': 'tiles' }

    try:
        # Use path relative to main templates folder
        return render_template('admin/admin_dashboard.html', **template_data)
    except Exception as e:
        print(f"--- ERROR rendering admin/admin_dashboard.html (tiles): {e} ---")
        traceback.print_exc()
        flash("An error occurred while rendering the dashboard.", "danger")
        return redirect(url_for('logout'))

@admin_logs_bp.route('/logs') # Define the specific route for viewing logs
def view_logs():
    """Fetches and displays the audit logs, with filtering."""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    role_filter = request.args.get('role_filter', '')
    logs = []
    conn = get_db_connection()
    try:
        # Query logs, joining with users and roles to get role_name
        base_query = """
            SELECT b.*, r.role_name
            FROM blockchain_audit_log b
            LEFT JOIN users u ON b.user_id = u.user_id
            LEFT JOIN roles r ON u.role_id = r.role_id
        """
        params = []

        # --- Use subquery filtering logic ---
        if role_filter:
            base_query += """
                WHERE b.user_id IN (
                    SELECT u_filter.user_id
                    FROM users u_filter
                    JOIN roles r_filter ON u_filter.role_id = r_filter.role_id
                    WHERE r_filter.role_name = ?
                )
            """
            params.append(role_filter)
        # --- END FILTERING ---

        base_query += " ORDER BY b.log_id DESC LIMIT 100" # Fetch logs
        logs = conn.execute(base_query, params).fetchall()

    except Exception as e:
        flash(f"Error fetching logs: {e}", "danger")
        print(f"--- ERROR fetching logs: {e}")
        traceback.print_exc()
    finally:
        if conn: conn.close()

    user_data = {
        'display_name': session.get('attributes', {}).get('full_name', session.get('username')),
        'username': session.get('username'),
        'role': session.get('role')
    }
    template_data = {
        'user': user_data,
        'view': 'logs',
        'logs': logs,
        'role_filter': role_filter
    }

    try:
         # Use path relative to main templates folder
        return render_template('admin/admin_dashboard.html', **template_data)
    except Exception as e:
        print(f"--- ERROR rendering admin/admin_dashboard.html (logs): {e} ---")
        traceback.print_exc()
        flash("An error occurred while rendering the logs.", "danger")
        return redirect(url_for('admin_logs.admin_dashboard_tiles')) # Redirect back to tiles

