# OWASP A04:2021 - Insecure Design
# Secure password reset example

from datetime import datetime, timedelta
import secrets

from flask import request, jsonify
from werkzeug.security import generate_password_hash


def create_reset_token(user):
    """
    Creates a cryptographically secure,
    temporary password-reset token.
    """

    token = secrets.token_urlsafe(32)

    reset_request = PasswordResetToken(
        user_id=user.id,
        token=token,
        expires_at=datetime.utcnow()
        + timedelta(minutes=15),
        used=False
    )

    db.session.add(reset_request)
    db.session.commit()

    return token


@app.route(
    '/reset-password/<token>',
    methods=['POST']
)
def reset_password(token):

    reset_request = (
        PasswordResetToken.query
        .filter_by(
            token=token,
            used=False
        )
        .first()
    )

    # Token must exist
    if reset_request is None:
        return jsonify({
            "error": "Invalid reset request"
        }), 400

    # Token must not be expired
    if reset_request.expires_at < datetime.utcnow():
        return jsonify({
            "error": "Reset link has expired"
        }), 400

    new_password = request.form.get(
        'new_password',
        ''
    )

    # Example password policy
    if len(new_password) < 12:
        return jsonify({
            "error":
            "Password must contain at least 12 characters"
        }), 400

    user = User.query.get(
        reset_request.user_id
    )

    if user is None:
        return jsonify({
            "error": "Invalid reset request"
        }), 400

    # Securely hash the new password
    user.password_hash = (
        generate_password_hash(
            new_password,
            method="scrypt"
        )
    )

    # Make the reset token one-time use
    reset_request.used = True

    db.session.commit()

    return jsonify({
        "message":
        "Password reset successful"
    })