import os
import requests
import urllib.parse
from flask import Flask, redirect, request, session, jsonify
from dotenv import load_dotenv
from time import sleep

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

CLIENT_ID = os.getenv("SPOTIFY_CLIENT_ID")
CLIENT_SECRET = os.getenv("SPOTIFY_CLIENT_SECRET")
REDIRECT_URI = os.getenv("SPOTIFY_REDIRECT_URI")
SCOPE = "user-read-private user-read-email"

SPOTIFY_AUTH_URL = "https://accounts.spotify.com/authorize"
SPOTIFY_TOKEN_URL = "https://accounts.spotify.com/api/token"
SPOTIFY_API_BASE_URL = "https://api.spotify.com/v1"


@app.route("/")
def index():
    return '<a href="/get_artist">artist</a> <a href="/get_playlist">playlist</a>'

def get_access_token():
    data = {
        "grant_type": "client_credentials"
    }
    auth = (CLIENT_ID, CLIENT_SECRET)

    response = requests.post(SPOTIFY_TOKEN_URL, data=data, auth=auth)
    response_data = response.json()

    return response_data.get("access_token")


@app.route("/get_artist")
def get_artist():
    artist = "4Z8W4fKeB5YxbusRsdQVPb"

    access_token = get_access_token()
    if not access_token:
        return jsonify({"error": "Could not get access token"}), 400


    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    url = SPOTIFY_API_BASE_URL + "/artists" + f"/{artist}"
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return jsonify({"error": "Failed to fetch artist", "status": response.status_code}), response.status_code

    return jsonify(response.json())

@app.route("/get_playlist")
def get_playlist():
    playlist = "1deWsaYD2MuFcgKdnXoeSC"

    access_token = get_access_token()
    if not access_token:
        return jsonify({"error": "Could not get access token"}), 400


    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    url = SPOTIFY_API_BASE_URL + "/playlists" + f"/{playlist}"
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return jsonify({"error": "Failed to fetch artist", "status": response.status_code}), response.status_code

    return jsonify(response.json())


if __name__ == "__main__":
    app.run(debug=True)
    # lsof -i :port
    # kill -9 number_of_task
    # to kill task which using this port
