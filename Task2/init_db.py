from app import app, db, Role, User, bcrypt
import os

def init_db():
    with app.app_context():
        # Create all tables
        db.create_all()
        print("Tables created (if not exist).")

        # Create roles if they don't exist
        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            admin_role = Role(name='admin')
            db.session.add(admin_role)
            print("Admin role created.")
        else:
            print("Admin role already exists.")

        user_role = Role.query.filter_by(name='user').first()
        if not user_role:
            user_role = Role(name='user')
            db.session.add(user_role)
            print("User role created.")
        else:
            print("User role already exists.")

        db.session.commit()  # Commit roles before assigning to users

        # Create admin user if it doesn't exist
        admin_user = User.query.filter_by(email='admin@example.com').first()
        if not admin_user:
            password = os.environ.get('ADMIN_PASSWORD', 'Admin@123')
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            admin_user = User(
                username='admin',
                email='admin@example.com',
                password_hash=hashed.decode('utf-8'),
                auth_method='manual',
                role=admin_role
            )
            db.session.add(admin_user)
            print("Admin user created.")
        else:
            print("Admin user already exists.")

        # Create 'user' user as admin if it doesn't exist
        user_admin = User.query.filter_by(username='user').first()
        if not user_admin:
            user_password = os.environ.get('USER_ADMIN_PASSWORD', 'User@123')
            user_hashed = bcrypt.hashpw(user_password.encode('utf-8'), bcrypt.gensalt())
            user_admin = User(
                username='user',
                email='user@example.com',
                password_hash=user_hashed.decode('utf-8'),
                auth_method='manual',
                role=admin_role
            )
            db.session.add(user_admin)
            print("'user' admin created.")
        else:
            print("'user' admin already exists.")

        # Ensure only 'admin' and 'user' are admins, others are regular users
        for u in User.query.all():
            if u.username not in ['admin', 'user']:
                if u.role != user_role:
                    u.role = user_role
                    print(f"User '{u.username}' set to user role.")
            else:
                if u.role != admin_role:
                    u.role = admin_role
                    print(f"User '{u.username}' set to admin role.")

        db.session.commit()
        print("Database initialized with roles and admin user.")

if __name__ == '__main__':
    try:
        init_db()
    except Exception as e:
        print("Error during database initialization:", e) 