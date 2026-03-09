from fastapi import FastAPI
from utils.json_loader import load_packages
from engine.batch_analyzer import analyze_from_file

app = FastAPI()


@app.get("/scan")

def scan():

    packages = load_packages("packages.json")

    results = analyze_from_file(packages)

    return results