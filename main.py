import os
import requests
import urllib.parse
from flask import Flask, redirect, request, session, jsonify, render_template, url_for
from dotenv import load_dotenv
# from time import sleep
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

# make some design for user_profile.html

# Make song player using all given endpoints

class UserController:
    main_route = "/me"


# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------


class PlayerController:
    main_route = "/player"
    get_devices = f"{main_route}/devices"
    currently_playing = f"{main_route}/currently-playing"

    # TODO:
    # routes for PUT requests

    recently_played = f"{main_route}/recently-played"
    queue = f"{main_route}/queue"

@app.route("/player")
def player():

    player_info = {}
    player_info["playback_state"] = get_playback_state()
    player_info["devices"] = get_available_devices()
    player_info["get_currently_playing_track"] = get_currently_playing_track()
    player_info["recently_played"] = get_recently_played()
    player_info["queue"] = get_player_queue()

    # TODO:
    # Do user's interaction using buttons
    # and write PUT-requests to this interaction
    #
    # Fix invalid token request???
    # idk how this works but okay

    return jsonify(player_info)
    # return render_template("player.html", **player_info)

def get_player_queue():
    access_token = get_access_token()

    headers = {
        "Authorization": access_token
    }

    url = f"{SPOTIFY_API_BASE_URL}{UserController.main_route}{PlayerController.queue}"
    response = requests.get(url, headers=headers)
    devices = response.json()

    return devices

def get_recently_played():
    access_token = get_access_token()

    headers = {
        "Authorization": access_token
    }

    url = f"{SPOTIFY_API_BASE_URL}{UserController.main_route}{PlayerController.recently_played}"
    response = requests.get(url, headers=headers)
    devices = response.json()

    return devices

def get_currently_playing_track():
    access_token = get_access_token()

    headers = {
        "Authorization": access_token
    }

    url = f"{SPOTIFY_API_BASE_URL}{UserController.main_route}{PlayerController.currently_playing}"
    response = requests.get(url, headers=headers)
    devices = response.json()

    return devices

def get_playback_state():
    access_token = get_access_token()

    headers = {
        "Authorization": access_token
    }

    url = f"{SPOTIFY_API_BASE_URL}{UserController.main_route}{PlayerController.main_route}"
    response = requests.get(url, headers=headers)
    devices = response.json()

    return devices

def get_available_devices():
    access_token = get_access_token()

    headers = {
        "Authorization": access_token
    }

    url = f"{SPOTIFY_API_BASE_URL}{UserController.main_route}{PlayerController.get_devices}"
    response = requests.get(url, headers=headers)
    devices = response.json()

    return devices


# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------


@app.route("/get_user_data")
def get_user_data():
    # user = "x3n5f0ve9qiyj306wtt1qw5oh"

    # collecting all user's info
    user_info = {}
    access_token = get_access_token()
    headers = {
        "Authorization": f"Authorization: {access_token}"
    }
    url = f"{SPOTIFY_API_BASE_URL}{UserController.main_route}"
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return jsonify({"error": f"Failed to fetch user{UserController.main_route}", "status": response.status_code, "message": response.reason}), response.status_code

    response_dict = response.json()

    # ["images"][0] -- is for image 300x300
    # ["images"][1] -- is for image 64x64
    user_info["height"] = response_dict["images"][0]["height"]
    user_info["user_pfp"] = response_dict["images"][0]["url"]
    user_info["width"] = response_dict["images"][0]["width"]

    user_info["display_name"] = response_dict["display_name"]
    user_info["country"] = response_dict["country"]
    user_info["email"] = response_dict["email"]
    user_info["ext_url"] = response_dict["external_urls"]["spotify"]
    user_info["followers"] = response_dict["followers"]["total"]
    user_info["subscription"] = response_dict["product"]

    return render_template("user_info.html", **user_info)


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

    # below we are getting access token
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
