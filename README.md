# OWASP Top 10 Vulnerability Analysis

This project reviews ten vulnerable code samples based on the OWASP Top 10:2021. For each sample, I identify the security problem, explain the possible impact, provide a more secure implementation, and explain how the correction reduces the vulnerability.

---

# 1. Broken Access Control – JavaScript

## Vulnerable Code

```javascript
app.get('/profile/:userId', (req, res) => {
    User.findById(req.params.userId, (err, user) => {
        if (err) return res.status(500).send(err);
        res.json(user);
    });
});
```

## Security Flaw

The application accepts a `userId` directly from the URL and returns the corresponding user's profile without checking whether the person making the request has permission to access that account.

For example, an authenticated user might access:

```text
/profile/123
```

and then change the URL to:

```text
/profile/124
```

If account 124 belongs to another person, the application may expose that person's information.

This is commonly referred to as an Insecure Direct Object Reference, or IDOR, and is a form of broken access control.

## Secure Version

```javascript
app.get('/profile/:userId', requireAuth, async (req, res) => {
    try {
        const requestedUserId = req.params.userId;

        if (
            requestedUserId !== req.user.id.toString() &&
            req.user.role !== 'admin'
        ) {
            return res.status(403).json({
                error: 'Access denied'
            });
        }

        const user = await User.findById(requestedUserId)
            .select('-password -passwordHash');

        if (!user) {
            return res.status(404).json({
                error: 'User not found'
            });
        }

        res.json(user);
    } catch (error) {
        res.status(500).json({
            error: 'Internal server error'
        });
    }
});
```

## How the Fix Improves Security

The new code requires authentication and verifies that the requested profile belongs to the logged-in user. Administrators may also be allowed depending on the application's authorization policy.

The application therefore no longer trusts the `userId` in the URL by itself.

Sensitive password information is also excluded from the response.

## OWASP Reference

OWASP A01:2021 – Broken Access Control

---

# 2. Broken Access Control – Python

## Vulnerable Code

```python
@app.route('/account/<user_id>')
def get_account(user_id):
    user = db.query(User).filter_by(id=user_id).first()
    return jsonify(user.to_dict())
```

## Security Flaw

Like the previous example, this endpoint trusts the account ID supplied in the URL.

There is no authentication or authorization check to determine whether the logged-in user owns the requested account.

An attacker could change the `user_id` value and potentially retrieve another person's account information.

## Secure Version

```python
from flask import jsonify
from flask_login import login_required, current_user

@app.route('/account/<int:user_id>')
@login_required
def get_account(user_id):

    if current_user.id != user_id and not current_user.is_admin:
        return jsonify({"error": "Access denied"}), 403

    user = db.query(User).filter_by(id=user_id).first()

    if user is None:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email
    })
```

## How the Fix Improves Security

The `@login_required` decorator prevents anonymous access.

The application then verifies that the logged-in user's ID matches the requested account ID. An administrator can optionally be given additional permissions.

The response also explicitly selects fields instead of blindly returning every field from the database object.

## OWASP Reference

OWASP A01:2021 – Broken Access Control

---

# 3. Cryptographic Failures – Java

## Vulnerable Code

```java
public String hashPassword(String password)
        throws NoSuchAlgorithmException {

    MessageDigest md =
        MessageDigest.getInstance("MD5");

    md.update(password.getBytes());

    byte[] digest = md.digest();

    return DatatypeConverter.printHexBinary(digest);
}
```

## Security Flaw

This code uses MD5 to hash passwords.

MD5 is a fast and outdated hashing algorithm and is not appropriate for password storage. Because it is computationally inexpensive, attackers can attempt huge numbers of password guesses very quickly.

The code also does not use a unique random salt.

Two users with the same password would therefore receive the same MD5 hash.

## Secure Version

```java
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordHasher {

    public static String hashPassword(String password)
            throws Exception {

        SecureRandom random = new SecureRandom();

        byte[] salt = new byte[16];
        random.nextBytes(salt);

        KeySpec spec = new PBEKeySpec(
                password.toCharArray(),
                salt,
                210000,
                256
        );

        SecretKeyFactory factory =
                SecretKeyFactory.getInstance(
                        "PBKDF2WithHmacSHA256"
                );

        byte[] hash =
                factory.generateSecret(spec).getEncoded();

        return Base64.getEncoder().encodeToString(salt)
                + ":"
                + Base64.getEncoder().encodeToString(hash);
    }
}
```

## How the Fix Improves Security

The secure version uses PBKDF2 with HMAC-SHA256 instead of MD5.

PBKDF2 intentionally performs many iterations, making password guessing more expensive.

A cryptographically secure random salt is generated for every password. Because each user receives a different salt, two users using the same password will not normally have the same stored value.

In a production application, the iteration count should follow current security recommendations and application performance requirements.

## OWASP Reference

OWASP A02:2021 – Cryptographic Failures

---

# 4. Cryptographic Failures – Python

## Vulnerable Code

```python
import hashlib

def hash_password(password):
    return hashlib.sha1(
        password.encode()
    ).hexdigest()
```

## Security Flaw

SHA-1 is a general-purpose cryptographic hash rather than a password-hashing function.

It is far too fast for modern password storage and makes offline password guessing easier if the database is stolen.

The example also does not use a salt.

## Secure Version

```python
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

def hash_password(password):
    return generate_password_hash(
        password,
        method="scrypt"
    )


def verify_password(stored_hash, password):
    return check_password_hash(
        stored_hash,
        password
    )
```

## How the Fix Improves Security

Instead of directly applying SHA-1, this version uses a password-storage function provided by Werkzeug.

`scrypt` is designed to be significantly more expensive for attackers attempting large numbers of password guesses.

The password is also salted automatically.

The login system should verify a password using `check_password_hash()` instead of hashing the entered password and comparing strings manually.

## OWASP Reference

OWASP A02:2021 – Cryptographic Failures

---

# 5. Injection – Java SQL Injection

## Vulnerable Code

```java
String username =
    request.getParameter("username");

String query =
    "SELECT * FROM users WHERE username = '"
    + username + "'";

Statement stmt =
    connection.createStatement();

ResultSet rs =
    stmt.executeQuery(query);
```

## Security Flaw

User input is directly concatenated into the SQL query.

An attacker could enter SQL syntax instead of a normal username.

For example, malicious input could modify the intended structure of the SQL command and cause the database to return information that the user should not receive.

## Secure Version

```java
String username =
    request.getParameter("username");

String query =
    "SELECT id, username, email "
    + "FROM users WHERE username = ?";

PreparedStatement stmt =
    connection.prepareStatement(query);

stmt.setString(1, username);

ResultSet rs =
    stmt.executeQuery();
```

## How the Fix Improves Security

`PreparedStatement` separates SQL instructions from user-supplied data.

The database treats the username as a value instead of executable SQL syntax.

This prevents input from changing the structure of the SQL command.

Input validation should still be used for business rules, but parameterized queries are the primary defense against SQL injection.

## OWASP Reference

OWASP A03:2021 – Injection

---

# 6. Injection – JavaScript NoSQL Injection

## Vulnerable Code

```javascript
app.get('/user', (req, res) => {
    db.collection('users').findOne(
        { username: req.query.username },
        (err, user) => {
            if (err) throw err;
            res.json(user);
        }
    );
});
```

## Security Flaw

The program places a value supplied by the client directly into a MongoDB query.

Depending on the application's query-string parsing and database handling, an attacker may be able to provide an object or MongoDB operator instead of an ordinary username.

For example, malicious input could attempt to introduce operators such as `$ne`, `$gt`, or other query functionality.

This can alter the intended database query.

## Secure Version

```javascript
app.get('/user', async (req, res) => {
    try {
        const username = req.query.username;

        if (
            typeof username !== 'string' ||
            username.length < 1 ||
            username.length > 50
        ) {
            return res.status(400).json({
                error: 'Invalid username'
            });
        }

        const allowedUsername =
            /^[a-zA-Z0-9_.-]+$/;

        if (!allowedUsername.test(username)) {
            return res.status(400).json({
                error: 'Invalid username'
            });
        }

        const user =
            await db.collection('users').findOne(
                { username: username },
                {
                    projection: {
                        password: 0,
                        passwordHash: 0
                    }
                }
            );

        if (!user) {
            return res.status(404).json({
                error: 'User not found'
            });
        }

        res.json(user);

    } catch (error) {

        res.status(500).json({
            error: 'Internal server error'
        });
    }
});
```

## How the Fix Improves Security

The application first verifies that the username is a string rather than an object containing database operators.

It also applies an allowlist of acceptable characters and limits its length.

This prevents unexpected structures from being inserted into the MongoDB query.

Sensitive password information is excluded from the database response as an additional precaution.

## OWASP Reference

OWASP A03:2021 – Injection

---

# 7. Insecure Design – Password Reset

## Vulnerable Code

```python
@app.route('/reset-password', methods=['POST'])
def reset_password():
    email = request.form['email']
    new_password = request.form['new_password']

    user = User.query.filter_by(
        email=email
    ).first()

    user.password = new_password

    db.session.commit()

    return 'Password reset'
```

## Security Flaw

The password-reset process has a fundamental design problem.

Anyone who knows another person's email address could potentially send a request containing that email address and a new password.

The system does not require:

- proof that the person owns the email account
- an authenticated session
- a password-reset token
- an expiration time
- one-time use of the reset request

The password also appears to be stored directly instead of being securely hashed.

## Secure Version

A better design separates requesting a password reset from actually changing the password.

```python
from datetime import datetime
from flask import request, jsonify
from werkzeug.security import generate_password_hash

@app.route(
    '/reset-password/<token>',
    methods=['POST']
)
def reset_password(token):

    reset = PasswordResetToken.query.filter_by(
        token=token,
        used=False
    ).first()

    if reset is None:
        return jsonify({
            "error": "Invalid reset request"
        }), 400

    if reset.expires_at < datetime.utcnow():
        return jsonify({
            "error": "Reset link expired"
        }), 400

    new_password = request.form.get(
        'new_password', ''
    )

    if len(new_password) < 12:
        return jsonify({
            "error":
                "Password does not meet requirements"
        }), 400

    user = User.query.get(reset.user_id)

    if user is None:
        return jsonify({
            "error": "Invalid reset request"
        }), 400

    user.password_hash = (
        generate_password_hash(
            new_password,
            method="scrypt"
        )
    )

    reset.used = True

    db.session.commit()

    return jsonify({
        "message": "Password reset successful"
    })
```

The application should create the reset token using a cryptographically secure random generator, associate it with the user, give it a short expiration period, and email the reset link to the verified email address.

## How the Fix Improves Security

The new design requires possession of a valid one-time reset token.

The token expires and cannot be reused.

The password is also processed using a password-storage algorithm instead of being stored directly.

The design therefore verifies that a reset request was authorized before allowing an account credential to be changed.

## OWASP Reference

OWASP A04:2021 – Insecure Design

OWASP Forgot Password Cheat Sheet

---

# 8. Software and Data Integrity Failures

## Vulnerable Code

```html
<script
    src="https://cdn.example.com/lib.js">
</script>
```

## Security Flaw

The application loads JavaScript from an external CDN but does not verify the integrity of the downloaded file.

If the CDN, hosting account, DNS configuration, or dependency is compromised, modified JavaScript could be delivered to visitors.

Because JavaScript executes inside the application's page, malicious code could potentially steal information or modify application behavior.

## Secure Version

One option is to use a specifically versioned file and Subresource Integrity:

```html
<script
    src="https://cdn.example.com/lib-1.2.3.min.js"
    integrity="sha384-REAL_HASH_FROM_TRUSTED_RELEASE"
    crossorigin="anonymous">
</script>
```

The `REAL_HASH_FROM_TRUSTED_RELEASE` value must be replaced with the actual SHA-384 integrity value published or independently generated for that exact trusted library file.

Another approach is to host a reviewed and version-pinned copy locally:

```html
<script
    src="/static/vendor/lib-1.2.3.min.js">
</script>
```

## How the Fix Improves Security

Subresource Integrity, or SRI, allows the browser to calculate the downloaded file's hash and compare it with the expected value.

If the external file has been modified, the browser refuses to execute it.

Version pinning also reduces the possibility that an unexpected library update will automatically change the application's behavior.

Applications should additionally use trusted package repositories, dependency verification, Content Security Policy, and secure deployment pipelines.

## OWASP Reference

OWASP A08:2021 – Software and Data Integrity Failures

---

# 9. Server-Side Request Forgery

## Vulnerable Code

```python
url = input("Enter URL: ")

response = requests.get(url)

print(response.text)
```

## Security Flaw

The program allows a user to provide any URL and causes the server to request it.

If this functionality were exposed through a web application, an attacker could make the server attempt to access resources that the attacker cannot directly reach.

Possible targets could include:

```text
http://localhost/
```

private network services or cloud infrastructure metadata endpoints.

This is Server-Side Request Forgery, or SSRF.

## Secure Version

A strong solution is to allow requests only to explicitly approved destinations.

```python
import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = {
    "api.example.com",
    "images.example.com"
}

def fetch_url(url):

    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise ValueError(
            "Only HTTPS URLs are allowed"
        )

    hostname = parsed.hostname

    if hostname not in ALLOWED_HOSTS:
        raise ValueError(
            "Host is not allowed"
        )

    response = requests.get(
        url,
        timeout=5,
        allow_redirects=False
    )

    response.raise_for_status()

    return response.text


url = input("Enter URL: ")

try:
    print(fetch_url(url))
except Exception as error:
    print("Request rejected:", error)
```

## How the Fix Improves Security

Instead of trying to block every dangerous URL, the program uses an allowlist containing the specific external hosts the application is permitted to contact.

It also:

- allows only HTTPS
- blocks automatic redirects
- uses a timeout
- rejects unapproved hosts

Using a destination allowlist is much safer than accepting arbitrary Internet addresses.

Production systems should additionally consider DNS resolution attacks, private IP ranges, network-level egress controls, and redirect validation.

## OWASP Reference

OWASP A10:2021 – Server-Side Request Forgery

OWASP Server-Side Request Forgery Prevention Cheat Sheet

---

# 10. Identification and Authentication Failures

## Vulnerable Code

```java
if (inputPassword.equals(
        user.getPassword())) {

    // Login success
}
```

## Security Flaw

This code suggests that the password entered during login is being directly compared with the password stored on the user's account.

That would normally mean passwords are being stored in plaintext or in an equivalently insecure form.

If the database is compromised, attackers could immediately obtain user passwords.

Users frequently reuse passwords between services, so a breach could potentially affect other accounts as well.

## Secure Version

Using BCrypt:

```java
import org.mindrot.jbcrypt.BCrypt;

public boolean authenticate(
        String inputPassword,
        User user) {

    if (user == null ||
        user.getPasswordHash() == null) {

        return false;
    }

    return BCrypt.checkpw(
        inputPassword,
        user.getPasswordHash()
    );
}
```

When initially storing the password:

```java
String passwordHash =
    BCrypt.hashpw(
        password,
        BCrypt.gensalt(12)
    );

user.setPasswordHash(passwordHash);
```

## How the Fix Improves Security

The application no longer stores the original password.

Instead, it stores a password hash generated by BCrypt.

During authentication, BCrypt verifies the entered password against the stored hash.

BCrypt is deliberately computationally expensive, making large-scale password guessing more difficult than direct comparison or fast hashing algorithms.

A complete authentication system should also include protections such as:

- multi-factor authentication when appropriate
- login rate limiting
- protection against credential stuffing
- secure session management
- secure password-reset functionality
- prevention of common or compromised passwords

## OWASP Reference

OWASP A07:2021 – Identification and Authentication Failures

OWASP Password Storage Cheat Sheet

OWASP Authentication Cheat Sheet

---

# Conclusion

These examples demonstrate that application security requires more than simply checking user input. Secure applications must enforce authorization, properly protect passwords, separate user data from executable database commands, validate external resources, design secure account-recovery processes, and restrict server-side network requests.

The OWASP Top 10 provides guidance for identifying these common risks and designing applications with appropriate security controls.

---

# OWASP Top 10 Categories Represented in This Assignment

The provided ten samples represent the following OWASP Top 10:2021 categories:

1. A01 – Broken Access Control
2. A02 – Cryptographic Failures
3. A03 – Injection
4. A04 – Insecure Design
5. A07 – Identification and Authentication Failures
6. A08 – Software and Data Integrity Failures
7. A10 – Server-Side Request Forgery

The provided samples do not contain separate examples for:

- A05 – Security Misconfiguration
- A06 – Vulnerable and Outdated Components
- A09 – Security Logging and Monitoring Failures

Therefore, the ten code samples cover seven distinct OWASP Top 10 categories rather than all ten categories.

# Official References

OWASP Top 10:2021  
https://top10.owasp.org/2021/

OWASP A01:2021 – Broken Access Control  
https://top10.owasp.org/2021/A01_2021-Broken_Access_Control/

OWASP A02:2021 – Cryptographic Failures  
https://top10.owasp.org/2021/A02_2021-Cryptographic_Failures/

OWASP A03:2021 – Injection  
https://top10.owasp.org/2021/A03_2021-Injection/

OWASP A04:2021 – Insecure Design  
https://top10.owasp.org/2021/A04_2021-Insecure_Design/

OWASP A07:2021 – Identification and Authentication Failures  
https://top10.owasp.org/2021/A07_2021-Identification_and_Authentication_Failures/

OWASP A08:2021 – Software and Data Integrity Failures  
https://top10.owasp.org/2021/A08_2021-Software_and_Data_Integrity_Failures/

OWASP A10:2021 – Server-Side Request Forgery  
https://top10.owasp.org/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/