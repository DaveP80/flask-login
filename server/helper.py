import os
import re
from pathlib import Path

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

def clearDir(p):    
    for f in Path('./img').glob(p):
        try:
            f.unlink()
        except OSError as e:
            print('Error: %s : %s' % (f, e.strerror))

def validFile(arr, p):
    for c,d in enumerate(arr):
        if d['img_path'] == p:
            return False
    return True