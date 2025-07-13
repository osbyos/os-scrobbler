from flask import Flask, redirect, session, request, render_template, url_for, jsonify
import hashlib
import os
import requests
from xml.etree import ElementTree
import time # Import the time module for delays
from werkzeug.utils import secure_filename # <--- ADDED THIS IMPORT

app = Flask(__name__)

# --- IMPORTANT: Get sensitive info from environment variables ---
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_super_secret_fallback_key_for_dev_only')
API_KEY = os.environ.get('LASTFM_API_KEY')
API_SECRET = os.environ.get('LASTFM_API_SECRET')
CALLBACK_URL = os.environ.get('LASTFM_CALLBACK_URL', 'http://localhost:5000/callback')
# --- End of environment variable setup ---

UPLOAD_FOLDER = 'uploads'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

ALLOWED_EXTENSIONS = {'log'}

def md5_hash(text):
    """Generates an MD5 hash for a given string."""
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def allowed_file(filename):
    """Checks if the uploaded file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def make_api_sig(params):
    """Generates a Last.fm API signature for authenticated calls."""
    # Sort parameters alphabetically by key, concatenate, and append API_SECRET
    sig_raw = ''.join([k + str(params[k]) for k in sorted(params)]) + API_SECRET # Ensure params[k] is string
    return md5_hash(sig_raw)

def get_session_key(token):
    """Exchanges a Last.fm request token for a session key."""
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
        return None, None, data.get('message', 'unknown error during session key retrieval')

def get_user_info(username):
    """Fetches user information from Last.fm, including profile picture URL."""
    params = {
        "method": "user.getInfo",
        "user": username,
        "api_key": API_KEY,
        "format": "json"
    }
    try:
        r = requests.get("https://ws.audioscrobbler.com/2.0/", params=params)
        r.raise_for_status()
        data = r.json()
        if 'user' in data and 'image' in data['user']:
            for img in data['user']['image']:
                if img['size'] == 'large' and img['#text']:
                    return img['#text']
            # Corrected: changed 'medium' to 'image' for consistency with Last.fm API response structure
            for img in data['user']['image']: 
                if img['size'] == 'medium' and img['#text']:
                    return img['#text']
    except requests.exceptions.RequestException as e:
        print(f"error fetching user info for {username}: {e}")
    return None

def decode_line(line):
    """Decodes a byte line from the log file, trying UTF-8 then ISO-8859-1."""
    try:
        return line.decode('utf-8')
    except UnicodeDecodeError:
        return line.decode('ISO-8859-1')

def submit_track_batch(tracks_batch, session_key, offset_seconds):
    """
    Submits a batch of tracks (up to 50) to Last.fm using the track.scrobble method.
    Returns a list of dictionaries with per-track results.
    """
    params = {
        'method': 'track.scrobble',
        'sk': session_key,
        'api_key': API_KEY
    }

    # Build indexed parameters for each track in the batch
    for i, track in enumerate(tracks_batch):
        # Track format: artist, album, title, tracknum, duration, L, timestamp
        if len(track) < 7 or track[5] != 'L':
            # This track will be marked as skipped in the results
            continue 
        
        params[f'artist[{i}]'] = track[0]
        params[f'album[{i}]'] = track[1]
        params[f'track[{i}]'] = track[2]
        params[f'trackNumber[{i}]'] = track[3]
        params[f'duration[{i}]'] = track[4]
        params[f'timestamp[{i}]'] = str(int(track[6]) + offset_seconds)

    api_sig = make_api_sig(params)
    params['api_sig'] = api_sig

    r = requests.post("https://ws.audioscrobbler.com/2.0/", data=params, headers={"Content-Type": "application/x-www-form-urlencoded"})
    
    batch_results = []
    if r.status_code != 200:
        # If the whole batch request fails, mark all tracks in batch as failed
        error_msg = f"http error for batch: {r.status_code}"
        for track in tracks_batch:
            batch_results.append({
                "track": f"{track[0]} - {track[2]}",
                "status": "fail",
                "error": error_msg
            })
        return batch_results

    try:
        data = ElementTree.fromstring(r.content)
        if data.attrib.get('status') != 'ok':
            err_node = data.find('error')
            error_msg = err_node.text if err_node is not None else "unknown api error for batch"
            for track in tracks_batch:
                batch_results.append({
                    "track": f"{track[0]} - {track[2]}",
                    "status": "fail",
                    "error": error_msg
                })
            return batch_results

        scrobbles_node = data.find('scrobbles')
        if scrobbles_node is None:
            # Handle unexpected response structure
            error_msg = "unexpected api response structure for scrobble batch"
            for track in tracks_batch:
                batch_results.append({
                    "track": f"{track[0]} - {track[2]}",
                    "status": "fail",
                    "error": error_msg
                })
            return batch_results

        # Parse individual scrobble results within the batch
        for i, scrobble_node in enumerate(scrobbles_node.findall('scrobble')):
            track_info = tracks_batch[i] # Get original track info for display
            artist = scrobble_node.find('artist').text if scrobble_node.find('artist') is not None else track_info[0]
            track_name = scrobble_node.find('track').text if scrobble_node.find('track') is not None else track_info[2]
            
            status = "ok" if scrobble_node.attrib.get('accepted') == '1' else "fail"
            error = None
            ignored_message_node = scrobble_node.find('ignoredMessage')
            if ignored_message_node is not None and ignored_message_node.attrib.get('code') != '0':
                error = ignored_message_node.text
                status = "fail" # Mark as fail if ignored

            batch_results.append({
                "track": f"{artist} - {track_name}",
                "status": status,
                "error": error
            })
    except ElementTree.ParseError as e:
        error_msg = f"xml parsing error: {e}"
        for track in tracks_batch:
            batch_results.append({
                "track": f"{track[0]} - {track[2]}",
                "status": "fail",
                "error": error_msg
            })
    except IndexError:
        # This can happen if Last.fm returns fewer scrobble results than tracks sent
        # Fallback to marking remaining tracks as failed
        error_msg = "mismatched scrobble results count from api"
        for i in range(len(batch_results), len(tracks_batch)):
            track = tracks_batch[i]
            batch_results.append({
                "track": f"{track[0]} - {track[2]}",
                "status": "fail",
                "error": error_msg
            })

    return batch_results


@app.route('/')
def index():
    """Renders the main landing page."""
    return render_template('index.html')

@app.route('/login')
def login():
    """Redirects to Last.fm for user authentication."""
    return redirect(f"http://www.last.fm/api/auth/?api_key={API_KEY}&cb={CALLBACK_URL}")

@app.route('/callback')
def callback():
    """Handles the callback from Last.fm after user authentication."""
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
    """Handles the scrobbler page, including file upload and track display."""
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
            parsed_tracks.append(parts) # Store as list of parts for submit_track_batch
        session['parsed_tracks'] = parsed_tracks
        return render_template('scrobbler.html', username=username, tracks=parsed_tracks, pfp_url=pfp_url)

    return render_template('scrobbler.html', username=username, tracks=None, pfp_url=pfp_url)

@app.route('/submit_scrobbles', methods=['POST'])
def submit_scrobbles():
    """Handles the submission of parsed tracks to Last.fm in batches."""
    if 'session_key' not in session or 'parsed_tracks' not in session:
        return jsonify({"error": "unauthorized or no tracks loaded"}), 401

    offset_hours = int(request.json.get('offset_hours', 0))
    offset_seconds = offset_hours * 3600
    session_key = session['session_key']
    tracks = session['parsed_tracks']

    all_results = []
    total_success = 0
    total_failure = 0
    
    # Chunk tracks into batches of 50
    BATCH_SIZE = 50
    for i in range(0, len(tracks), BATCH_SIZE):
        batch = tracks[i:i + BATCH_SIZE]
        
        # Submit the batch
        batch_results = submit_track_batch(batch, session_key, offset_seconds)
        
        # Aggregate results from the batch
        for result in batch_results:
            all_results.append(result)
            if result['status'] == 'ok':
                total_success += 1
            else:
                total_failure += 1
        
        # Add a delay between batches to respect Last.fm's rate limits
        if i + BATCH_SIZE < len(tracks): # Don't sleep after the last batch
            time.sleep(1) # Wait for 1 second between batches

    return jsonify({"success": total_success, "failure": total_failure, "results": all_results})

if __name__ == '__main__':
    app.run(debug=True)
