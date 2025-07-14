from flask import Flask, redirect, session, request, render_template, url_for, jsonify
import hashlib
import os
import requests
from xml.etree import ElementTree
from werkzeug.utils import secure_filename

app = Flask(__name__)

# --- IMPORTANT: Get sensitive info from environment variables ---
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_super_secret_fallback_key_for_dev_only')
API_KEY = os.environ.get('LASTFM_API_KEY')
API_SECRET = os.environ.get('LASTFM_API_SECRET')
# The CALLBACK_URL will be your Render app's URL + /callback
# You MUST update this in your Last.fm API application settings after deploying to Render.
CALLBACK_URL = os.environ.get('LASTFM_CALLBACK_URL', 'http://localhost:5000/callback')
# --- End of environment variable setup ---

UPLOAD_FOLDER = 'uploads'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

ALLOWED_EXTENSIONS = {'log'}

def md5_hash(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def make_api_sig(params):
    # Ensure all parameter values are strings before concatenation for hashing
    sig_raw = ''.join([k + str(params[k]) for k in sorted(params)]) + API_SECRET
    return md5_hash(sig_raw)

def get_session_key(token):
    sig_raw = f"api_key{API_KEY}methodauth.getSessiontoken{token}{API_SECRET}"
    api_sig = md5_hash(sig_raw)
    params = {
        "method": "auth.getSession",
        "api_key": API_KEY,
        "token": token,
        "api_sig": api_sig,
        "format": "json"
    }
    r = requests.get("https://ws.audioscrobbler.com/2.0/", params=params)
    data = r.json()
    if 'session' in data:
        return data['session']['key'], data['session']['name'], None
    else:
        return None, None, data.get('message', 'Unknown error')

def get_user_info(username):
    """Fetches user information, including profile picture URL."""
    params = {
        "method": "user.getInfo",
        "user": username,
        "api_key": API_KEY,
        "format": "json"
    }
    try:
        r = requests.get("https://ws.audioscrobbler.com/2.0/", params=params)
        r.raise_for_status() # Raise an exception for HTTP errors
        data = r.json()
        if 'user' in data and 'image' in data['user']:
            # Prioritize 'large' image, then 'medium'
            for img in data['user']['image']:
                if img['size'] == 'large' and img['#text']:
                    return img['#text']
            for img in data['user']['image']:
                if img['size'] == 'medium' and img['#text']:
                    return img['#text']
    except requests.exceptions.RequestException as e:
        print(f"Error fetching user info for {username}: {e}")
    return None # Return None if no image found or error

def decode_line(line):
    try:
        return line.decode('utf-8')
    except UnicodeDecodeError:
        return line.decode('ISO-8859-1')

def submit_track(track, session_key, offset_seconds):
    # Track format: artist, album, title, tracknum, duration, L, timestamp
    # Changed condition: now allows 'L' or 'S' flags for scrobbling
    if len(track) < 7 or track[5] not in ['L', 'S']:
        return "Skipped (Flag not L or S)"
    params = {
        'method': 'track.scrobble',
        'artist[0]': track[0],
        'album[0]': track[1],
        'track[0]': track[2],
        'trackNumber[0]': track[3],
        'duration[0]': track[4],
        'timestamp[0]': str(int(track[6]) + offset_seconds),
        'sk': session_key,
        'api_key': API_KEY
    }
    api_sig = make_api_sig(params)
    params['api_sig'] = api_sig

    r = requests.post("https://ws.audioscrobbler.com/2.0/", data=params, headers={"Content-Type": "application/x-www-form-urlencoded"})
    if r.status_code != 200:
        # Attempt to parse XML for more specific error message even on HTTP error
        try:
            error_xml = ElementTree.fromstring(r.content)
            err_node = error_xml.find('error')
            if err_node is not None:
                return f"HTTP {r.status_code} - API Message: {err_node.text}"
        except ElementTree.ParseError:
            pass # Ignore XML parse error if content is not valid XML
        return f"HTTP {r.status_code}"
    
    data = ElementTree.fromstring(r.content)
    if data.attrib.get('status') != 'ok':
        err = data.find('error')
        return err.text if err is not None else "Unknown error"
    ignored = data.find(".//ignoredMessage")
    if ignored is not None and ignored.attrib.get('code') != '0':
        return ignored.text
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    return redirect(f"http://www.last.fm/api/auth/?api_key={API_KEY}&cb={CALLBACK_URL}")

@app.route('/callback')
def callback():
    token = request.args.get('token')
    if not token:
        return "missing token", 400
    session_key, username, error = get_session_key(token)
    if error:
        return f"authentication error: {error}", 400
    session['session_key'] = session_key
    session['username'] = username
    return redirect(url_for('scrobbler'))

@app.route('/scrobbler', methods=['GET', 'POST'])
def scrobbler():
    if 'session_key' not in session:
        return redirect(url_for('index'))

    username = session['username']
    pfp_url = get_user_info(username)

    if request.method == 'POST':
        file = request.files.get('file')
        if not file or not allowed_file(file.filename):
            return "invalid or missing file", 400

        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        with open(filepath, 'rb') as f:
            lines = [decode_line(line).strip() for line in f.readlines()]

        if not lines or lines[0] != "#AUDIOSCROBBLER/1.1":
            return "invalid scrobbler.log format", 400

        tz_line, client_line, *entries = lines
        parsed_tracks = []
        for e in entries:
            parts = e.split('\t')
            if len(parts) < 7:
                continue
            parsed_tracks.append({
                'artist': parts[0],
                'album': parts[1],
                'title': parts[2],
                'tracknum': parts[3],
                'duration': parts[4],
                'flag': parts[5],
                'timestamp': int(parts[6])
            })
        session['parsed_tracks'] = parsed_tracks
        return render_template('scrobbler.html', username=username, tracks=parsed_tracks, pfp_url=pfp_url)

    return render_template('scrobbler.html', username=username, tracks=None, pfp_url=pfp_url)

@app.route('/submit_scrobbles', methods=['POST'])
def submit_scrobbles():
    if 'session_key' not in session or 'parsed_tracks' not in session:
        return jsonify({"error": "unauthorized or no tracks loaded"}), 401 # Lowercase error message

    offset_hours = int(request.json.get('offset_hours', 0))
    offset_seconds = offset_hours * 3600
    session_key = session['session_key']
    tracks = session['parsed_tracks']

    results = []
    success = 0
    failure = 0
    for track in tracks:
        err = submit_track([
            track['artist'],
            track['album'],
            track['title'],
            track['tracknum'],
            track['duration'],
            track['flag'],
            str(track['timestamp'])
        ], session_key, offset_seconds)
        if err:
            failure += 1
            results.append({"track": f"{track['artist']} - {track['title']}", "status": "fail", "error": err})
        else:
            success += 1
            results.append({"track": f"{track['artist']} - {track['title']}", "status": "ok"})

    return jsonify({"success": success, "failure": failure, "results": results})

if __name__ == '__main__':
    app.run(debug=True)
