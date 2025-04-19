import os
import requests
import urllib.parse
from flask import Flask, redirect, request, session, jsonify, render_template, url_for
from dotenv import load_dotenv
from time import sleep
import base64
import hashlib
import secrets

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


# TODO:

# get all user's profile data with pfp included
# use all given endpoints

# make homepage using Jinja (html)

# Make song player using all given endpoints

@app.route("/get_user_data")
def get_user_data():
    # user = "x3n5f0ve9qiyj306wtt1qw5oh"

    # collecting all user's info
    user_info = {}
    access_token = get_access_token()
    headers = {
        "Authorization": f"Authorization: {access_token}"
    }
    url = SPOTIFY_API_BASE_URL + "/me"
    response = requests.get(url, headers=headers)
    print(access_token)
    if response.status_code != 200:
        return jsonify({"error": "Failed to fetch user/me", "status": response.status_code, "message": response.reason}), response.status_code

    user_info["main"] = jsonify(response.json())
    # return user_info["main"]
    return render_template("user_info.html", main=user_info["main"])


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
        return jsonify({"error": "Failed to fetch playlist", "status": response.status_code}), response.status_code

    return jsonify(response.json())

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------

@app.route("/")
def index():
    try:
        # checking for token (function get_access_token() wont work because it will cause an endless loop)
        access_token = session["access_token"]
    except:
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier)

        session["code_verifier"] = code_verifier

        params = {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "scope": SCOPE,
            "redirect_uri": REDIRECT_URI,
            "code_challenge_method": "S256",
            "code_challenge": code_challenge,
        }

        url = f"{SPOTIFY_AUTH_URL}?{urllib.parse.urlencode(params)}"
        return redirect(url)

    return render_template('index.html', title='Player', message='Welcome to Flask with Jinja!', test='get user datas')

@app.route("/callback")
def callback():
    return_route = request.args.get("redirect_uri", "/")
    code = request.args.get("code")

    code_verifier = session.get("code_verifier")

    token_url = "https://accounts.spotify.com/api/token"
    payload = {
        "client_id": CLIENT_ID,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
    }

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    response = requests.post(token_url, data=payload, headers=headers)
    response_data = response.json()

    access_token = response_data.get("access_token")
    token_type = response_data.get("token_type")
    session["access_token"] = f"{token_type} {access_token}"

    return redirect(return_route)


# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------


def get_access_token():
    try:
        """ checking if there is a valid access_token (remake this part so it will check from the file filled with tokens)
            and if there is no valid access_token then we will authorize user"""
        access_token = session["access_token"]
    except:
        # refresh token if it expired
        return redirect("/")
    return access_token


def generate_code_verifier(length=64):
    if not (43 <= length <= 128):
        raise ValueError("Length must be between 43 and 128")
    allowed = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    return ''.join(secrets.choice(allowed) for _ in range(length))

def generate_code_challenge(code_verifier: str) -> str:
    sha256_hash = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    b64_encoded = base64.urlsafe_b64encode(sha256_hash).decode('utf-8')
    return b64_encoded.rstrip('=')



if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)

    # lsof -i :port
    # kill -9 number_of_task
    # to kill task which using this port
