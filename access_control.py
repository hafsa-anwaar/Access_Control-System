import mysql.connector
import os  # it will get us to use environment variables where the values of our db and email values are stored for secure coding
import hashlib #it will help to generate and compare hash value sor our password
# getpass will help to take the input for password and will not display the password on the interface
from getpass import getpass
# smtplib will help to send emails
import smtplib
# random and string modules will help to generate a random OTP
import random
import string

# Connecting to the database
connection = mysql.connector.connect(
    host='localhost',
    user=os.environ.get('DB_USER'),  # Change 'username' to 'user'
    password=os.environ.get('DB_PASSWORD'),
    database='access_control'
)
cursor = connection.cursor()

# Create table for user credentials
def initialize_db():
    # Users Table: Stores user credentials and roles
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL
    )
    """)

    # Logs Table: Tracks accountability with user actions
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        action VARCHAR(255) NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Resources Table for privilege control: Simulates access to different resources
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS resources (
        id INT AUTO_INCREMENT PRIMARY KEY,
        resource_name VARCHAR(255) UNIQUE NOT NULL,
        restricted_role VARCHAR(255)
    )
    """)
     # Insert a default admin user if these values are not present otherwise ignore it
    cursor.execute("""
    INSERT IGNORE INTO users (username, password, email, role)
    VALUES ('admin', 'admin123', 'hafsaanwaar449@gmail.com', 'admin')
    """)

    # Inserting privilege controls to each resources/role and ignoring if the same resource name is already entered
    cursor.execute("""
    INSERT IGNORE INTO resources (resource_name, restricted_role)
    VALUES ('Confidential Report', 'admin'),
           ('User Settings', 'manager'),
           ('Public Dashboard', NULL)
    """)

    # Commit the changes
    connection.commit()

# now we are making an interface for our system
# the below function will keep track of the user action
def log_action(username, action):
    # notice that we have used %s in our sql query it is also parametrzied query for mysql server which will help to prevent the data of logs from being vulnerable to SQL injection
    cursor.execute("""
    INSERT INTO logs (username, action)
    VALUES (%s, %s)
    """, (username, action))
    connection.commit()

# Generate a random OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

# Send OTP to email
def send_otp(email, otp):
    sender = os.environ.get('OTP_EMAIL')  # these values are referencing to environment variable through os module where original values are stored
    sender_password = os.environ.get('OTP_PWD')
    message = f"Subject: Your OTP\n\nYour OTP is {otp}"

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(sender, sender_password)
        server.sendmail(sender, email, message)

def authenticate():
    print("\n--- User Login ---")
    username = input("Username: ")
    password = getpass("Password: ")
    # we have used parametrized query i.e "%s" to prevent sql injection
    cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, hashlib.md5(password.encode()).hexdigest()))
    # whatever row matches the result will be then saved to the user variable by retrieving the row through fetchone()
    user = cursor.fetchone()

    if user and hashlib.md5(password.encode()).hexdigest():
        # Generate and send OTP
        otp = generate_otp()
        send_otp(user[4], otp)  # Assuming user[4] is the email column
        print("OTP has been sent to your email.")
        # Verify OTP
        entered_otp = input("Enter the OTP: ")
        if entered_otp == otp:
            log_action(username, "Logged In")
            # user[index no] means that particular column of the record that is retrieved
            print(f"Welcome {username}! Role: {user[3]}")
            return {"username": user[1], "role": user[3]}
        else:
            print("Invalid OTP!")
            return None
    else:
        print("Invalid credentials!")
        return None

# AUTHORIZATION to give access to resources according to the restriced role fed in the databasen for a particular user using our system
def authorize(role, resource):
    # sql injection for securely process the query with the value of user's input by replacing input with %s in the query
    cursor.execute("SELECT restricted_role FROM resources WHERE resource_name = %s", (resource,))
    result = cursor.fetchone()
    if result:
        restricted_role = result[0]
        if restricted_role and role != restricted_role:
            print(f"Access Denied! Only '{restricted_role}' role can access this resource.")
            return False
        else:
            print(f"Access Granted to '{resource}'!")
            return True
    else:
        print("Resource not found.")
        return False

# function to add actions the user performed in the log table in database
def log_action(username, action):
    # SQL injection to hide the input of the actions of users from attackers
    cursor = connection.cursor()
    cursor.execute("INSERT INTO logs (username, action) VALUES (%s, %s)", (username, action))
    connection.commit()

def view_logs():
    print("\n--- System Logs ---")
    cursor.execute("SELECT * FROM logs")
    # resulting in all the records of log table
    logs = cursor.fetchall()
    # printing every log details in log table
    for log in logs:
        print(f"ID: {log[0]}, User: {log[1]}, Action: {log[2]}, Timestamp: {log[3]}")

# function to access the resources from the resource table according to user's choice and keeping track of user's action if the user is authorized
def access_resources(user):
    print("\n--- Access Resources ---")
    cursor.execute("SELECT resource_name FROM resources")
    resources = cursor.fetchall()
    # enumerate helps to keep track of index positions along with value
    # start=1 will change the starting index position value to 1
    for i, resource in enumerate(resources, start=1):
        print(f"{i}. {resource[0]}")
    choice = int(input("\nSelect a resource (number): ")) - 1
    if 0 <= choice < len(resources):
        # accessing the [0] column that is resource name and its value according to choice of user
        resource_name = resources[choice][0]
        # function calling
        if authorize(user['role'], resource_name):
            # function calling
            log_action(user['username'], f"Accessed resource '{resource_name}'")
    else:
        print("Invalid selection!")

# Admin menu to access the functions that we have created above (Admin will have all the access)
def admin_menu():
    print("\n--- Admin Menu ---")
    print("1. View Logs")
    print("2. Add User")
    print("3. Add Resource")
    choice = input("Choose an option: ")

    if choice == "1":
        view_logs()
    elif choice == "2":
        add_user()
    elif choice == "3":
        add_resource()
    else:
        print("Invalid option!")

# Manager access (A manager has less access than admin). manager can't add users and resources like admin
def manager_menu():
    print("\n--- Manager Menu ---")
    print("1. View Logs")
    print("2. Access Resources")
    choice = input("Choose an option: ")

    if choice == "1":
        view_logs()
    elif choice == "2":
        resource = input("Enter the resource name you want to access: ")
        if authorize("manager", resource):  # Assuming "manager" is the role
            log_action("manager", f"Accessed resource '{resource}'")
        else:
            print("Access Denied!")
    else:
        print("Invalid option!")

# USER MENU (Only giving access to limited options)
def user_menu(username):
    print("\n--- User Menu ---")
    print("1. Access Resources")
    choice = input("Choose an option: ")
    if choice == "1":
        access_resources({"username": username, "role": "user"})
    else:
        print("Invalid option!")

# function to add new users only accessible to admin
def add_user():
    print("\n--- Add User ---")
    username = input("New Username: ")
    password = getpass("New Password: ")
    email=input("New Email: ")
    role = input("Role (admin/manager/user): ")

    hashed_password = hashlib.md5(password.encode()).hexdigest()

    try:
        cursor.execute("INSERT INTO users (username, password, role,email) VALUES (%s, %s, %s,%s)", (username, hashed_password, role, email ))
        print(f"User '{username}' added successfully!")
    except mysql.connector.IntegrityError:
        print("Username already exists!")

# function that is only accessible for admin to add resources
def add_resource():
    print("\n--- Add Resource ---")
    resource_name = input("Resource Name: ")
    restricted_role = input("Restricted Role (leave blank for public): ")
    
    try:
        cursor.execute("INSERT INTO resources (resource_name, restricted_role) VALUES (%s, %s)", (resource_name, restricted_role))
        print(f"Resource '{resource_name}' added successfully!")
    except mysql.connector.IntegrityError:
        print("Resource already exists!")

# Main function to call our admin, manager and user's menu
def main():
    initialize_db()
    user = authenticate()
    if user:
        while True:
            print("\n--- Main Menu ---")
            print("1. Access Resources")
            if user['role'] == "admin":
                print("2. Admin Menu")
            elif user['role'] == "manager":
                print("2. Manager Menu")
            elif user['role'] == "user":
                print("2. User Menu")
            print("3. Logout")
            
            choice = input("Choose an option: ")
            if choice == "1":
                access_resources(user)
            elif choice == "2" and user['role'] == "admin":
                admin_menu()
            elif choice == "2" and user['role'] == "manager":
                manager_menu()
            elif choice == "2" and user['role'] == "user":
                user_menu(user['username'])
            elif choice == "3":
                log_action(user['username'], "Logged Out")
                print("Logged out. Goodbye!")
                break
            else:
                print("Invalid option!")

if __name__ == "__main__":
    main()
