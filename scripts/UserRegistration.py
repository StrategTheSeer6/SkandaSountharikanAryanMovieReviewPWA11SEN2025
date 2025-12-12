import sqlite3
import bcrypt
import datetime
import re
from better_profanity import profanity
profanity.load_censor_words()


def initialize_database():   #NEED TO IMMEDIATELY INITIALIZE DATABASE, IF NOT, IT WOULD CRASH. 
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS AccountsDetail (
        UserID INTEGER PRIMARY KEY AUTOINCREMENT,
        Username TEXT UNIQUE NOT NULL,
        UserPassword TEXT NOT NULL,
        UserEmail TEXT UNIQUE NOT NULL,
        UserPFP TEXT,
        UserJoinDate TEXT,
        UserReviewCount INTEGER DEFAULT 0,
        UserTitle TEXT,
        UserDescription TEXT,
        UserAuthorityLevel INTEGER DEFAULT 1
    )
    """)
    conn.commit()



conn = sqlite3.connect("PWAFramesDatabase.db")
cursor = conn.cursor()

initialize_database()

current_user = None
current_user_level = None


def is_username_valid(username):
    if len(username) > 16:
        print("Username must be 16 characters or less.")
        return False
    #CHANGE THIS PART TO THE BAD WORD API WHATEVER YOU FIND
    if profanity.contains_profanity(username):
        print("Username contains inappropriate language.")
        return False
    cursor.execute("SELECT COUNT(*) FROM AccountsDetail WHERE Username=?", (username,))
    if cursor.fetchone()[0] > 0:
        print("Username already exists. Choose a different one.")
        return False
    return True

def is_password_valid(password):
    if len(password) < 8:
        print("Password must be at least 8 characters.")
        return False
    return True

def is_email_valid(email):
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    if not re.match(pattern, email):
        print("Invalid email format.")
        return False
    cursor.execute("SELECT COUNT(*) FROM AccountsDetail WHERE UserEmail=?", (email,))
    if cursor.fetchone()[0] > 0:
        print("Email already registered. Use a different email.")
        return False
    return True


def registerUser():
    while True:
        email = input("Enter your email: ")
        if is_email_valid(email):
            break

    while True:
        username = input("Enter your username: ")
        if is_username_valid(username):
            break

    while True:
        password = input("Enter your password: ")
        if is_password_valid(password):
            password_again = input("Enter your password again: ")
            if password != password_again:
                print("Passwords do not match.")
            else:
                break

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    register_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    pfp_default = "default.png"
    review_count_default = 0
    title_default = "New User"
    bio_default = "This user doesn't have a bio yet."

    cursor.execute("""
        INSERT INTO AccountsDetail
        (Username, UserPassword, UserEmail, UserPFP, UserJoinDate, UserReviewCount, UserTitle, UserDescription)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (username, hashed_password.decode('utf-8'), email, pfp_default, register_date, review_count_default, title_default, bio_default))

    conn.commit()
    print("User registered successfully!")


def loginUser():
    global current_user, current_user_level

    username_or_email = input("Enter your username or email: ")
    password_entered = input("Enter your password: ")

    cursor.execute(
        "SELECT UserPassword, UserAuthorityLevel FROM AccountsDetail WHERE Username=? OR UserEmail=?",
        (username_or_email, username_or_email)
    )
    result = cursor.fetchone()

    if result is None:
        print("No such user found.")
        return False

    hashed_pw_db, auth_level = result
    hashed_pw_db = hashed_pw_db.encode('utf-8')

    if bcrypt.checkpw(password_entered.encode('utf-8'), hashed_pw_db):
        print("Login successful!")
        current_user = username_or_email
        current_user_level = auth_level
        return True
    else:
        print("Incorrect password.")
        return False


def deleteUser():
    username_or_email = input("Enter your username or email to delete: ")
    password = input("Enter your password: ")

    cursor.execute(
        "SELECT UserPassword FROM AccountsDetail WHERE Username=? OR UserEmail=?",
        (username_or_email, username_or_email)
    )
    result = cursor.fetchone()
    if not result:
        print("No such user.")
        return

    hashed_pw_db = result[0].encode('utf-8')
    if bcrypt.checkpw(password.encode('utf-8'), hashed_pw_db):
        cursor.execute(
            "DELETE FROM AccountsDetail WHERE Username=? OR UserEmail=?",
            (username_or_email, username_or_email)
        )
        conn.commit()
        print("Account deleted successfully.")
    else:
        print("Incorrect password.")

def dump_accounts():
    cursor.execute("SELECT * FROM AccountsDetail")
    rows = cursor.fetchall()
    for row in rows:
        print(row)


def logoutUser():
    global current_user, current_user_level
    current_user = None
    current_user_level = None
    print("Logged out successfully!")


def get_user_authority(username_or_email):
    cursor.execute(
        "SELECT UserAuthorityLevel FROM AccountsDetail WHERE Username=? OR UserEmail=?",
        (username_or_email, username_or_email)
    )
    result = cursor.fetchone()
    return result[0] if result else None


def promote_user():
    global current_user, current_user_level

    target = input("Enter the username/email of the user to promote: ")
    target_level = get_user_authority(target)
    if target_level is None:
        print("User not found.")
        return
    if target == current_user:
        print("You cannot promote yourself.")
        return

    if current_user_level == 2:
        if target_level >= 2:
            print("You cannot promote another moderator or admin.")
            return
        if target_level == 1:
            new_level = 2
        elif target_level == 0:
            new_level = 1
        else:
            print("Invalid promotion.")
            return
    elif current_user_level == 3:
        if target_level == 3:
            print("Admins cannot change another admin's level.")
            return
        new_level = target_level + 1
    else:
        print("You don't have permission to promote users.")
        return

    cursor.execute(
        "UPDATE AccountsDetail SET UserAuthorityLevel=? WHERE Username=? OR UserEmail=?",
        (new_level, target, target)
    )
    conn.commit()
    print(f"{target} has been promoted to level {new_level}! What a good boy.")


def demote_user():
    global current_user, current_user_level

    target = input("Enter the username/email of the user to demote: ")
    target_level = get_user_authority(target)
    if target_level is None:
        print("User not found.")
        return
    if target == current_user:
        print("You cannot demote yourself.")
        return

    if current_user_level == 2:
        if target_level >= 2:
            print("You cannot demote another moderator or admin.")
            return
        new_level = target_level - 1
        if new_level < 0:
            new_level = 0
    elif current_user_level == 3:
        if target_level == 3:
            print("Admins cannot demote other admins.")
            return
        new_level = target_level - 1
        if new_level < 0:
            new_level = 0
    else:
        print("You don't have permission to demote users.")
        return

    cursor.execute(
        "UPDATE AccountsDetail SET UserAuthorityLevel=? WHERE Username=? OR UserEmail=?",
        (new_level, target, target)
    )
    conn.commit()
    print(f"{target} has been demoted to level {new_level}. Such a bad boy.")


def menu_not_logged_in():
    print("\n MAIN MENU logged out")
    print("1. Register")
    print("2. Login")
    print("3. Exit")
    return input("Choose an option: ")

def menu_user():
    print("\n MAIN MENU logged in w 1")
    print("1. Log Out")
    print("2. Comment   (not implemented)")
    print("3. Review    (not implemented)")
    print("4. Delete account")
    print("5. Report user      (not implemented)")
    print("6. Report comment   (not implemented)")
    print("7. Exit")
    return input("Choose an option: ")

def menu_restricted():
    print("\n MAIN MENU logged in w 0")
    print("1. Log Out")
    print("2. Delete account")
    print("3. Exit")
    return input("Choose an option: ")

def menu_moderator():
    print("\n MAIN MENU logged in w 2")
    print("1. Log Out")
    print("2. Comment   (not implemented)")
    print("3. Review    (not implemented)")
    print("4. Delete account")
    print("5. Delete comment   (not implemented)")
    print("6. Demote account")
    print("7. Promote account")
    print("8. Exit")
    return input("Choose an option: ")

def menu_admin():
    print("\n MAIN MENU logged in w 3")
    print("1. Log Out")
    print("2. Delete comment   (not implemented)")
    print("3. Demote account")
    print("4. Promote account")
    print("5. Dump accounts")
    print("6. Exit")
    return input("Choose an option: ")



if __name__ == "__main__":
    while True:
        if current_user is None:
            choice = menu_not_logged_in()

            if choice == "1":
                registerUser()
            elif choice == "2":
                loginUser()
            elif choice == "3":
                break
            else:
                print("Invalid option.")

        else:
            if current_user_level == 0:
                choice = menu_restricted()

                if choice == "1":
                    logoutUser()
                elif choice == "2":
                    deleteUser() 
                elif choice == "3":
                    break
                else:
                    print("Invalid option.")

            elif current_user_level == 1:
                choice = menu_user()

                if choice == "1":
                    logoutUser()
                elif choice == "4":
                    deleteUser()
                elif choice == "7":
                    break
                else:
                    print("Not implemented yet or invalid option.")

            elif current_user_level == 2:
                choice = menu_moderator()

                if choice == "1":
                    logoutUser()
                elif choice == "4":
                    deleteUser()
                elif choice == "6":
                    demote_user()
                elif choice == "7":
                    promote_user()
                elif choice == "8":
                    break
                else:
                    print("Not implemented yet or invalid option.")

            elif current_user_level == 3:
                choice = menu_admin()

                if choice == "1":
                    logoutUser()
                elif choice == "3":
                    demote_user()
                elif choice == "4":
                    promote_user()
                elif choice == "5":
                    dump_accounts()
                elif choice == "6":
                    break
                else:
                    print("Not implemented yet or invalid option.")


conn.close()