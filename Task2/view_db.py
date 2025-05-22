from app import db, app, User, LoginLog
from datetime import datetime

def format_log_entry(log):
    return (
        f"Timestamp: {log.timestamp}\n"
        f"Method: {log.method}\n"
        f"IP Address: {log.ip_address}\n"
        f"Status: {'Success' if log.success else 'Failed'}\n"
        f"Details: {log.details if log.details else 'None'}\n"
        "----------------------------------------\n"
    )

def format_user_entry(user):
    return (
        f"\nUser ID: {user.id}\n"
        f"Username: {user.username}\n"
        f"Email: {user.email}\n"
        f"Auth Method: {user.auth_method}\n"
        f"Created At: {user.created_at}\n"
        "----------------------------------------\n"
    )

with app.app_context():
    # Get current timestamp for filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"database_export_{timestamp}.txt"
    
    with open(filename, 'w') as f:
        print("\n=== Users ===")
        f.write("=== Users ===\n\n")
        
        users = User.query.all()
        for user in users:
            # Print to terminal
            print(f"\nUser: {user.username} (ID: {user.id})")
            print(f"Email: {user.email}")
            print(f"Auth Method: {user.auth_method}")
            print(f"Created At: {user.created_at}")
            
            # Write to file
            f.write(format_user_entry(user))
            
            print("\nLogin Logs:")
            f.write("Login Logs:\n")
            
            logs = LoginLog.query.filter_by(user_id=user.id).order_by(LoginLog.timestamp.desc()).all()
            for log in logs:
                # Print to terminal
                print(f"- {log.timestamp}: {log.method} ({'Success' if log.success else 'Failed'})")
                print(f"  IP: {log.ip_address}")
                if log.details:
                    print(f"  Details: {log.details}")
                
                # Write to file
                f.write(format_log_entry(log))
            
            print("\n" + "="*50)
            f.write("\n" + "="*50 + "\n")
    
    print(f"\nData has been saved to {filename}") 