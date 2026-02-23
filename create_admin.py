from app import create_app
from models import User, db
from werkzeug.security import generate_password_hash

def create_admin_user():
    app = create_app()
    with app.app_context():
        email = "adminvenu"
        password = "adminvenu321"
        
        # Check if user already exists
        user = User.query.filter_by(email=email).first()
        
        if user:
            print(f"User '{email}' already exists. Updating password and ensuring admin status...")
            user.password_hash = generate_password_hash(password)
            user.is_admin = True
            db.session.commit()
            print("Successfully updated user.")
        else:
            print(f"Creating new admin user: {email}...")
            new_user = User(
                email=email,
                password_hash=generate_password_hash(password),
                is_admin=True
            )
            db.session.add(new_user)
            db.session.commit()
            print("Successfully created admin user.")

if __name__ == "__main__":
    create_admin_user()
