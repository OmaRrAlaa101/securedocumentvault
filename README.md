# Secure Authentication and Document Management System

This project is a secure web application built with Flask that provides robust authentication, user management, and secure document handling. It features multi-factor authentication (2FA), OAuth login (GitHub, Google), role-based access control, encrypted file uploads, digital signatures, and audit logging.

## Features

- **User Registration & Login**: Manual signup/login with strong password policy, plus OAuth via GitHub and Google.
- **Two-Factor Authentication (2FA)**: TOTP-based 2FA setup and enforcement for sensitive actions.
- **Role-Based Access Control**: Admin and user roles, with only one admin allowed at a time.
- **Profile Management**: Users can update their profile, including uploading a profile picture.
- **Password Management**: Password reset via email, change password, and strong password enforcement.
- **Document Upload & Download**:
  - Only allowed file types (txt, pdf, doc, docx)
  - Files are encrypted at rest
  - Integrity checks (SHA256, HMAC, CRC32)
  - Digital signatures (OpenSSL RSA)
  - Only owner or admin can access documents
- **Audit Logging**: All login attempts and actions are logged for auditing.
- **Admin Panel**: Manage users, edit roles, delete users, and view audit logs.
- **Security Best Practices**:
  - HTTPS enforcement in production
  - Secure session and cookie handling
  - CSRF protection (Flask-WTF recommended)
  - No sensitive data in client-side code

## Setup Instructions

### Prerequisites
- Python 3.8+
- pip

### Installation
1. Clone the repository or copy the project files.
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
3. Create a `.env` file in the project root with the following variables:
   ```env
   SECRET_KEY=your_secret_key
   GITHUB_CLIENT_ID=your_github_client_id
   GITHUB_CLIENT_SECRET=your_github_client_secret
   GOOGLE_CLIENT_ID=your_google_client_id
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   MAIL_SERVER=smtp.gmail.com
   MAIL_PORT=587
   MAIL_USERNAME=your_email@gmail.com
   MAIL_PASSWORD=your_email_password
   MAIL_DEFAULT_SENDER=your_email@gmail.com
   ```
4. Initialize the database:
   ```sh
   flask init-db
   ```
5. Run the application:
   ```sh
   python app.py
   ```
   The app will be available at https://127.0.0.1:5000

### Notes
- The first registered user is assigned the admin role. Only one admin is allowed.
- Uploaded documents are stored encrypted in the `secure_uploads/` directory.
- Profile pictures are stored in `static/profile_pics/`.
- For production, set `debug=False` and use a proper SSL certificate.

## File Structure
- `app.py` - Main Flask application
- `requirements.txt` - Python dependencies
- `templates/` - HTML templates
- `static/` - Static files (CSS, images)
- `secure_uploads/` - Encrypted uploaded documents
- `encryption.key` - Symmetric key for file encryption
- `private_key.pem`, `public_key.pem` - RSA keys for digital signatures

## License
This project is for educational purposes.

![login](https://github.com/user-attachments/assets/126fe215-2ca5-45c7-ac20-9b813af01621)


![2fa](https://github.com/user-attachments/assets/8ba9efd8-fdca-4055-8420-43bb0dd7f8a4)


![2fa auth](https://github.com/user-attachments/assets/909229c6-0ece-4780-bf64-9f0e4cfed125)


![admin dash](https://github.com/user-attachments/assets/25214a4c-d3b0-4fc4-8b33-b6c64506c76f)



![dashboard](https://github.com/user-attachments/assets/3097501e-1ae2-4085-85bf-827e87ecbbb5)

