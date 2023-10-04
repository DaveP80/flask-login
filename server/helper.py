import os
import re

regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')

def read_blocklist_file(app):
    # Define the path to the blocklist.txt file in the static folder
    static_folder = app.static_folder
    blocklist_file_path = os.path.join(static_folder, 'blocklist.txt')
    blocklist = []
    with open(blocklist_file_path, 'r') as file:
        for line in file:
            blocklist.append(line.strip())
    return blocklist

def isValid(email):
    if re.fullmatch(regex, email): return True
    else: return False