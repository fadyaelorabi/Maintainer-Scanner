import json

def load_packages(path):

    with open(path,"r") as f:
        data = json.load(f)

    return data