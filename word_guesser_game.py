import bcrypt
import time
import sys
import random
import string
import pandas as pd
import re

DASH = "-" * 100
RED = "1;31"
GREEN = "1;32"
YELLOW = "1;33"
BLUE = "1;34"
MAGENTA = "1;35"

file_path_words = "/Users/anmolkumarsrivastava/PycharmProjects/pythonProject/words.txt"
file_path_users_data = "/Users/anmolkumarsrivastava/PycharmProjects/pythonProject/users_data.txt"
file_path_high_score = "/Users/anmolkumarsrivastava/PycharmProjects/pythonProject/high_scores.txt"
file_path_progress = "/Users/anmolkumarsrivastava/PycharmProjects/pythonProject/progress.txt"


def color_text(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"


def typing(message):
    for char in message:
        sys.stdout.write(char)
        time.sleep(0.1)
    print()


def valid_int(value):
    try:
        int(value)
        return True
    except ValueError:
        return False


def is_valid_password(password):
    pattern = (
        r'^(?=.*[a-z])'
        r'(?=.*[A-Z])'
        r'(?=.*\d)'
        r'(?=.*[@$!%*?&])'
        r'[A-Za-z\d@$!%*?&]{8,20}$'
    )
    return re.match(pattern, password)


def is_valid_letter(letter):
    pattern = r'^[a-zA-z]{1}$'
    return re.match(pattern, letter)


def is_valid_number(number):
    pattern = r'^[5-9]\d{9}$'
    return re.match(pattern, number)


def exit_code():
    message = "Exiting Game..."
    message = color_text(message, GREEN)
    typing(message)
    message = "Have a Good Day."
    print(color_text(message, GREEN))
    sys.exit(0)


def welcome():
    message = "Welcome to the Word Guesser Game..."
    message = color_text(message, GREEN)
    typing(message)
    print(color_text(DASH, GREEN))
    instructions = "This game challenges you to guess hidden words by suggesting letters within a \n" \
                   "limited number of attempts. You can sign up, log in, and track your progress and \n" \
                   "scores over time.\n" + DASH
    print(color_text(instructions, BLUE))


def print_rules():
    rules = "You will get 15 tries to guess the word correctly.\n" \
            "Each correct letter guess gives +10 points.\n" \
            "Each wasted try gives 0 points.\n" \
            "After 5th try, you can take hints by pressing '/h'\n" \
            "At max, 2 hints can be taken but not in same try.\n" \
            "Complete word guess gives:\n" \
            "\t0 hints = 150 points\n" \
            "\t1 hints = 140 points\n" \
            "\t2 hints = 130 points\n" \
            "Use '/e' to save progress and exit\n" + DASH
    print(color_text(rules, BLUE))


def otp_authenticator(otp, try_number):
    while try_number > 0:
        print("Tries left : ", try_number)
        user_input = input("Enter OTP : ")
        if user_input == otp:
            return True
        try_number -= 1
    return False


def generate_otp():
    sent_otp = ""
    for i in range(6):
        sent_otp += random.choice(string.digits)
    return sent_otp


def generate_password():
    passwords = ["", "", "", "", ""]
    list_characters = [string.digits, string.ascii_uppercase, string.ascii_lowercase, ["@", "$", "!", "%", "*", "?", "&"]]
    for i in range(5):
        password = []
        for j in range(4):
            character = random.choice(list_characters[j])
            password.append(character)
        for j in range(4):
            character = random.choice(string.digits + string.ascii_uppercase + string.ascii_lowercase + "@$!%*?&")
            password.append(character)
        for j in password:
            passwords[i] += j
    return passwords


def set_up_twilio():
    from twilio.rest import Client
    account_sid = '#SID'
    auth_token = '#KEY'
    client = Client(account_sid, auth_token)
    return client


def send_otp(number, otp, client):
    client.messages.create(
        body='Your One Time Password is : ' + otp,
        from_='#Number',
        to='+91' + number
    )


def import_data(file_path):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
    except FileNotFoundError:
        message = "Error loading the word file.\n" + DASH
        print(color_text(message, RED))
    except Exception as e:
        message = f"An Error Occurred : {e}\n" + DASH
        print(color_text(message, RED))
    users = []
    for i in lines:
        user = list(i.split(","))
        users.append(user)
    return users


def import_high_score():
    data = import_data(file_path_high_score)
    data_frame = pd.DataFrame(data, columns=["position", "username", "score"])
    data_frame['score'] = data_frame['score'].astype(str).str[:4]
    data_frame['score'] = pd.to_numeric(data_frame['score'], errors='coerce').astype('Int64')
    message = "High Scores Table:- \n" + DASH
    print(color_text(message, GREEN))
    print(color_text(data_frame[["position", "username", "score"]].to_string(index=False), BLUE))
    start()


def import_words_data(key):
    users = import_data(file_path_words)
    data_frame = pd.DataFrame(users, columns=["word", "hint1", "hint2"])
    if key == 0:
        return data_frame["word"]
    elif key == 1:
        return data_frame["hint1"]
    else:
        return data_frame["hint2"]


def import_users_data(key):
    users = import_data(file_path_users_data)
    data_frame = pd.DataFrame(users, columns=["username", "passwords", "security code", "number"])
    if key == 0:
        return data_frame["username"]
    elif key == 1:
        return data_frame["passwords"]
    elif key == 2:
        return data_frame["security code"]
    elif key == 3:
        return data_frame["number"]
    else:
        return data_frame


def word_picker():
    words_list = import_words_data(0)
    word = random.choice(list(words_list.values))
    index = 0
    for i in words_list.values:
        if i == word:
            break
        index += 1
    return word, index


def get_hint(index, key):
    data = import_words_data(key)
    hint = data.at[index]
    return hint


def get_username():
    usernames = import_users_data(0)
    while True:
        username = input("Enter username : ")
        if username not in usernames.values:
            return username
        else:
            message = "Username already exists.\nChoose another username.\n" + DASH
            print(color_text(message, RED))


def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')


def confirm_password(password):
    while True:
        confirm = input("Re-Enter your password ('/e' for new password) : ")
        if confirm == password:
            return True
        elif confirm == "/e":
            return False
        else:
            message = "Password Mismatch. Try again.\n" + DASH
            print(color_text(message, RED))


def get_password():
    while True:
        message = "Password Requirements : \n" \
                  "1- Minimum 8 characters.\n" \
                  "2- Upper and Lower case character.\n" \
                  "3- At least 1 Digit.\n" \
                  "4- Special Symbol [@, +, -, /, $]\n" + DASH
        print(color_text(message, BLUE))
        password = input("Set your password : ")
        if is_valid_password(password):
            if confirm_password(password):
                hashed_password = hash_password(password)
                return hashed_password
        else:
            message = "Invalid Password.Choose according to rules.\n" + DASH
            print(color_text(message, RED))


def set_security():
    security = ""
    for i in range(8):
        random_letter = random.choice(string.digits)
        security += random_letter
    message = "Your security code is : " + security + "\n" + DASH
    print(color_text(message, BLUE))
    return security


def get_number():
    while True:
        number = input("Enter your mobile number (only indian numbers): ")
        if is_valid_number(number):
            otp = generate_otp()
            client = set_up_twilio()
            send_otp(number, otp, client)
            if otp_authenticator(otp, 3):
                return number
        else:
            message = f"Enter a valid indian mobile number.\n{DASH}"
            print(color_text(message, RED))


def for_password():
    print("Press 1 to generate random password.")
    print("Press 2 to set manual password.")
    while True:
        message = "Enter your choice : "
        message = color_text(message, MAGENTA)
        choice = input(message)
        if valid_int(choice) and choice in ['1', '2']:
            choice = int(choice)
            if choice == 1:
                passwords = generate_password()
                for i in range(5):
                    print("Password ", i + 1, ": ", passwords[i])
                while True:
                    message = "Enter your choice : (1-5)"
                    message = color_text(message, MAGENTA)
                    choice = input(message)
                    if valid_int(choice) and choice in ['1', '2', '3', '4', '5']:
                        choice = int(choice)
                        hashed_password = hash_password(passwords[choice - 1])
                        return hashed_password
                    else:
                        print(color_text("Invalid Choice", RED))
            else:
                return get_password()
        else:
            print(color_text("Invalid Choice", RED))


def signup():
    message = "Welcome to new player registration...\n" + DASH
    print(color_text(message, GREEN))
    username = get_username()
    password = for_password()
    security = set_security()
    number = get_number()
    data_base_string = username + "," + password + "," + security + "," + number + "\n"
    while True:
        message = "Press 1 to create account.\n" \
                  "Press 2 to return to main menu.\n" + DASH
        print(color_text(message, GREEN))
        message = "Enter your choice : "
        message = color_text(message, MAGENTA)
        choice = input(message)
        if valid_int(choice) and int(choice) in [1, 2]:
            if int(choice) == 1:
                try:
                    with open(file_path_users_data, 'a') as file:
                        file.write(data_base_string)
                except FileNotFoundError:
                    message = "File not found. Please ensure the file exists.\n" + DASH
                    print(color_text(message, RED))
                except Exception as e:
                    message = "An error occurred: " + str(e) + "\n" + DASH
                    print(color_text(message, RED))
            else:
                message = "Sign-Up aborted, Returning to main menu.\n" + DASH
                print(color_text(message, RED))
                start()
            break
        else:
            message = "Enter a valid choice.\n" + DASH
            print(color_text(message, RED))


def get_username_login():
    stored_usernames = import_users_data(0)
    while True:
        username = input("Enter your username : ")
        if username in stored_usernames.values:
            index = 0
            for i in stored_usernames.values:
                if i == username:
                    break
                else:
                    index += 1
            return username, index
        elif username == "/e":
            message = "Returning back to main menu.\n" + DASH
            print(color_text(message, RED))
            start()
        else:
            message = "Invalid username.\n" \
                      "'/e' to return back\n" + DASH
            print(color_text(message, RED))


def verify_password(username_index):
    stored_passwords = import_users_data(1)
    stored_password = stored_passwords.at[username_index]
    tries = 3
    while tries > 0:
        password = input("Enter your password : ")
        if is_valid_password(password):
            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                return True
        tries -= 1
        message = "Wrong password!!!\nTries left : " + str(tries) + "\n" + DASH
        print(color_text(message, RED))
    message = "Maximum tries utilised, returning back... \n" + DASH
    print(color_text(message, RED))
    login()


def user_logged_in(username):
    message = "Press 1 for Single Player Mode.\n" \
              "Press 2 for Resume Saved Game.\n" \
              "Press 3 for High Score Table.\n" \
              "Press 4 to Log out.\n" + DASH
    print(color_text(message, GREEN))
    while True:
        message = color_text("Enter your choice: ", MAGENTA)
        choice = input(message)
        if valid_int(choice) and int(choice) in [1, 2, 3, 4]:
            if choice == "1":
                print_rules()
                single_player_mode(username)
            elif choice == "2":
                continue
            elif choice == "3":
                import_high_score()
                user_logged_in(username)
            else:
                message = "Logged Out!!!\nHave a great day...\n" + DASH
                print(color_text(message, YELLOW))
                start()
            break
        else:
            message = "Invalid entry."
            print(color_text(message, RED))


def login():
    message = "Welcome Back ...\nLet's log-in...\n"
    message = color_text(message, BLUE)
    typing(message)
    print(color_text(DASH, BLUE))
    username, username_index = get_username_login()
    verify_password(username_index)
    message = f"LOGIN SUCCESSFUL...\n{DASH}\nHello {username}...\n{DASH}"
    print(color_text(message, GREEN))
    user_logged_in(username)


def save_data(username, index, copy_word_list, used_words, used_letters, current_points, hint_used, tries_taken):
    try:
        with open(file_path_progress, "a") as file:
            file.write(username + "," + str(index) + "," + str(copy_word_list) +
                       "," + str(used_words) + "," + str(used_letters) + "," + str(current_points) + str(hint_used)
            + "," + str(tries_taken) + "," + "\n")
    except FileNotFoundError:
        message = "Error loading the word file.\n" + DASH
        print(color_text(message, RED))
    except Exception as e:
        message = f"An Error Occurred : {e}\n" + DASH
        print(color_text(message, RED))


def update_high_score(username, points, index):
    try:
        with open(file_path_high_score, "r") as file:
            lines = file.readlines()
    except FileNotFoundError:
        message = "Error loading the word file.\n" + DASH
        print(color_text(message, RED))
    except Exception as e:
        message = f"An Error Occurred : {e}\n" + DASH
        print(color_text(message, RED))
    points = str(points)
    while len(points) < 4:
        points = "0" + points
    data_base_string = str(index + 1) + "," + username + "," + points + "\n"
    if (index + 1) > len(lines):
        lines.append(data_base_string)
    else:
        lines[index] = data_base_string
    try:
        with open(file_path_high_score, "w") as file:
            file.writelines(lines)
    except FileNotFoundError:
        message = "Error loading the word file.\n" + DASH
        print(color_text(message, RED))
    except Exception as e:
        message = f"An Error Occurred : {e}\n" + DASH
        print(color_text(message, RED))
    return index + 1


def check_highscore(username, points):
    data = import_data(file_path_high_score)
    data_frame = pd.DataFrame(data, columns=["position", "username", "score"])
    scores = data_frame["score"].values
    index = 0
    for index in range(len(scores)):
        if int(scores[index]) < points:
            break
        index += 1
    key = update_high_score(username, points, index)
    return key


def winner_message(word, hint):
    points = 150 - (10 * hint)
    message = f"Word Guessed Successfully : {word}\nPoints {points}"
    print(color_text(message, GREEN))


def tries_finished(word):
    message = f"You have exhausted all your tries.\nBetter Luck next time.\nThe word was: {word}"
    print(color_text(message, RED))


def logic(letter, word_list, copy_word_list, points, tries):
    letter = letter.lower()
    if letter in word_list:
        for index, char in enumerate(word_list):
            if letter == char:
                copy_word_list[index] = char
                points += 10
    else:
        message = "Guess Wasted..."
        print(color_text(message, RED))
    tries -= 1
    return copy_word_list, points, tries


def start_game(username, used_words, total_points):
    while True:
        word, index = word_picker()
        if word not in used_words:
            used_words.append(word)
            break
    word_list = list(word)
    copy_word_list = ["-" for _ in range(len(word))]
    tries = 15
    points = 0
    hint = 0
    used_letters = []
    print(copy_word_list)
    while tries >= 0:
        if word_list == copy_word_list:
            winner_message(word, hint)
            return (150 - (10 * hint)), True
        if tries == 0:
            tries_finished(word)
            break
        if tries == 10:
            message = "Hints available now. ('/h')"
            print(color_text(message, BLUE))
        message = color_text("Enter your letter : ", MAGENTA)
        letter = input(message)
        if (is_valid_letter(letter) and letter not in used_letters) or (letter == "/h" and tries <= 10) or letter == "/e":
            if letter not in ["/e", "/h"]:
                used_letters.append(letter)
            if letter == "/h":
                if hint < 2:
                    hints = get_hint(index, hint + 1)
                    print(color_text(hints, BLUE))
                    hint += 1
                    while True:
                        letter = input(message)
                        if is_valid_letter(letter):
                            copy_word_list, points, tries = logic(letter, word_list, copy_word_list, points, tries)
                            break
                        elif letter == "/h":
                            message1 = "One hint per try."
                            print(color_text(message1, RED))
                        else:
                            message1 = "Invalid Input, Single alphabet allowed."
                            print(color_text(message1, RED))
                else:
                    message = "Maximum hints utilised."
                    print(color_text(message, RED))
            elif letter == "/e" and total_points > -1:
                message = "Saving progress...\n" \
                          "Returning back to main menu.\n" + DASH
                print(color_text(message, GREEN))
                save_data(username, index, copy_word_list, used_words, used_letters, total_points + points, hint, tries)
                start()
            elif letter == "/e" and total_points == -1:
                message = "Returning back to main menu.\n" + DASH
                print(color_text(message, GREEN))
                start()
            else:
                copy_word_list, points, tries = logic(letter, word_list, copy_word_list, points, tries)
            print(f"tries left : {tries}, word: {copy_word_list}")
        else:
            if letter in used_letters:
                message = "Invalid Input, Letter already guessed."
                print(color_text(message, RED))
            else:
                message = "Invalid Input, Single alphabet allowed."
                print(color_text(message, RED))
    else:
        tries_finished(word)
    return points, False


def single_player_mode(username):
    used_words = []
    if username == "9876543210-Guest-0123456789":
        print_rules()
        start_game(username, used_words, -1)
        start()
    else:
        total_points = 0
        next_round = True
        while next_round:
            this_round_points, next_round = start_game(username, used_words, total_points)
            total_points += this_round_points
        else:
            position = check_highscore(username, total_points)
            if position in [1, 2, 3, 4, 5]:
                message = f"{DASH}\nBeaten one of the high scores...\nLeaderboard position :- {position}\n{DASH}\n"
                print(color_text(message, BLUE))
            user_logged_in(username)


def validate_security_code(index):
    stored_security_codes = import_users_data(2)
    stored_security_code = stored_security_codes.at[index]
    tries = 3
    while tries > 0:
        message = "Enter your Security Code : "
        message = color_text(message, MAGENTA)
        security = input(message)
        if security == stored_security_code.strip():
            return True
        else:
            tries -= 1
            message = "Incorrect Security Code.Tries Left:- " + str(tries) + "\n" + DASH
            print(color_text(message, RED))
    return False


def update_password(index, hashed_password):
    try:
        with open(file_path_users_data, "r") as file:
            lines = file.readlines()
    except FileNotFoundError:
        message = "Error loading the word file.\n" + DASH
        print(color_text(message, RED))
    except Exception as e:
        message = f"An Error Occurred : {e}\n" + DASH
        print(color_text(message, RED))
    username, password, security, number = lines[index].split(",")
    data_base_string = username + "," + hashed_password + "," + security + "," + number + "\n"
    lines[index] = data_base_string
    try:
        with open(file_path_users_data, "w") as file:
            file.writelines(lines)
    except FileNotFoundError:
        message = "Error loading the word file.\n" + DASH
        print(color_text(message, RED))
    except Exception as e:
        message = f"An Error Occurred : {e}\n" + DASH
        print(color_text(message, RED))


def fetch_number(index):
    numbers = import_users_data(3)
    number = numbers.at[index]
    return number


def forgot_password():
    message = "Forgot Password? No Problem, we got u covered...\n" + DASH
    print(color_text(message, GREEN))
    username, index = get_username_login()
    if validate_security_code(index):
        message = "Security Code Matched.\nEnter OTP:"
        print(color_text(message, BLUE))
        number = fetch_number(index)
        otp = generate_otp()
        client = set_up_twilio()
        send_otp(number, otp, client)
        if otp_authenticator(otp, 3):
            hashed_password = for_password()
            update_password(index, hashed_password)
            message = "Password Updated.\n" + DASH
            print(color_text(message, GREEN))
    else:
        message = "Maximum Tries Reached.\nReturning back to main menu.\n" + DASH
        print(color_text(message, RED))
    start()


def start():
    message = "Press 1 to Sign up.\n" \
              "Press 2 to Log in.\n" \
              "Press 3 to play as Guest.\n" \
              "Press 4 to see HighScores.\n" \
              "Press 5 to change password\n" \
              "Press 6 to Exit\n"
    print(color_text(message, GREEN))
    while True:
        message = "Enter your choice : "
        message = color_text(message, MAGENTA)
        choice = input(message)
        if valid_int(choice) and choice in ['1', '2', '3', '4', '5', '6']:
            choice = int(choice)
            if choice == 1:
                signup()
                message = "Account created successfully.\n" + DASH
                message = color_text(message, GREEN)
                print(message)
                start()
            elif choice == 2:
                login()
            elif choice == 3:
                message = "Game starting in guest mode...\nNo progress will be recorded.\nBest of Luck.\n" + DASH
                print(color_text(message, GREEN))
                single_player_mode("9876543210-Guest-0123456789")
            elif choice == 4:
                import_high_score()
            elif choice == 5:
                forgot_password()
            else:
                exit_code()
            break
        else:
            message = "Enter a valid choice as per the instructions."
            print(color_text(message, RED))


start()
