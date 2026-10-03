# OWASP A01:2021 - Broken Access Control
# Secure version

from flask import jsonify
from flask_login import login_required, current_user


@app.route('/account/<int:user_id>')
@login_required
def get_account(user_id):

    # Users may only access their own account
    # Administrators may access other accounts
    if current_user.id != user_id and not current_user.is_admin:
        return jsonify({
            "error": "Access denied"
        }), 403

    user = db.query(User).filter_by(id=user_id).first()

    if user is None:
        return jsonify({
            "error": "User not found"
        }), 404

    # Only return fields that are safe to expose
    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email
    })
