from flask import Flask, redirect, session, request, render_template, url_for, jsonify
import hashlib
import os
import requests
from xml.etree import ElementTree
import time # Import the time module for delays
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
    """Generates an MD5 hash for a given string."""
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def allowed_file(filename):
    """Checks if the uploaded file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def make_api_sig(params):
    """
    Generates a Last.fm API signature for authenticated calls.
    Handles numerical sorting for array notation parameters as per Last.fm docs
    (e.g., artist[10] comes before artist[1]).
    """
    def custom_sort_key(item_key):
        # This function extracts the base name and numerical index for sorting
        if '[' in item_key and ']' in item_key:
            parts = item_key.split('[')
            base_name = parts[0] # e.g., 'artist'
            index_str = parts[1][:-1] # e.g., '0', '10' (remove ']')
            try:
                # Return tuple for sorting: (base_name, numerical_index)
                # This ensures 'artist[1]' comes before 'artist[10]' numerically
                # but 'artist' parameters are grouped together, then 'album', etc.
                return (base_name, int(index_str))
            except ValueError:
                # Fallback for non-integer indices or malformed keys
                # This ensures these sort consistently, typically at the end of their base_name group
                return (item_key, -1)
        # For non-indexed parameters (e.g., 'method', 'api_key', 'sk')
        return (item_key, -1) # These will be sorted alphabetically by item_key, then by -1

    # Sort parameters using the custom key applied to the parameter name (k)
    sorted_items = sorted(params.items(), key=lambda item: custom_sort_key(item[0]))
    
    # Concatenate sorted keys and string-converted values, then append API_SECRET
    sig_raw = ''.join([k + str(v) for k, v in sorted_items]) + API_SECRET
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
            for img in data['user']['image']: 
                if img['size'] == 'medium' and img['#text']:
                    return img['#text']
    except requests.exceptions.RequestException as e:
        print(f"Error fetching user info for {username}: {e}")
    return None

def decode_line(line):
    """Decodes a byte line from the log file, trying UTF-8 then ISO-8859-1."""
    try:
        return line.decode('utf-8')
    except UnicodeDecodeError:
        return line.decode('ISO-8859-1')

def submit_track_batch(tracks_batch_dicts, session_key, offset_seconds):
    """
    Submits a batch of tracks (up to 50) to Last.fm using the track.scrobble method.
    `tracks_batch_dicts` is a list of dictionaries, where each dictionary represents a track.
    Returns a list of dictionaries with per-track results.
    """
    params = {
        'method': 'track.scrobble',
        'sk': session_key,
        'api_key': API_KEY
    }

    # This list will hold only the tracks that are actually sent to Last.fm API
    # This ensures their indices are consecutive (0, 1, 2...) for the API call.
    tracks_to_scrobble_api = []
    
    # This list accumulates results for all original tracks in the batch,
    # including those skipped locally.
    detailed_batch_results = [] 

    # First pass: Filter tracks and prepare for API call, and pre-populate skipped results
    for track_dict in tracks_batch_dicts:
        # Basic validation for essential keys
        if not all(k in track_dict for k in ['artist', 'album', 'title', 'tracknum', 'duration', 'flag', 'timestamp']):
            detailed_batch_results.append({
                "track": f"{track_dict.get('artist', 'Unknown')} - {track_dict.get('title', 'Unknown')}",
                "status": "fail",
                "error": "invalid track data format (missing keys)"
            })
            continue 
        
        # Only scrobble tracks with 'L' or 'S' flag
        if track_dict['flag'] not in ['L', 'S']:
            detailed_batch_results.append({
                "track": f"{track_dict['artist']} - {track_dict['title']}",
                "status": "skipped", 
                "error": "track not marked for scrobble ('L' or 'S' flag missing)"
            })
            continue

        tracks_to_scrobble_api.append(track_dict) # Add to the list that will be sent to API

    if not tracks_to_scrobble_api:
        # If no tracks are valid for scrobbling in this batch, return immediately
        return detailed_batch_results 

    # Second pass: Build indexed parameters for the tracks that *will* be scrobbled
    for i, track_dict in enumerate(tracks_to_scrobble_api):
        params[f'artist[{i}]'] = track_dict['artist']
        params[f'album[{i}]'] = track_dict['album']
        params[f'track[{i}]'] = track_dict['title']
        params[f'trackNumber[{i}]'] = track_dict['tracknum']
        params[f'duration[{i}]'] = track_dict['duration']
        params[f'timestamp[{i}]'] = str(int(track_dict['timestamp']) + offset_seconds)

    api_sig = make_api_sig(params) # Use the updated make_api_sig
    params['api_sig'] = api_sig

    r = requests.post("https://ws.audioscrobbler.com/2.0/", data=params, headers={"Content-Type": "application/x-www-form-urlencoded"})
    
    api_response_results = [] # Results specifically from the API response
    
    if r.status_code != 200:
        error_msg = f"HTTP error for batch: {r.status_code}"
        try:
            error_xml = ElementTree.fromstring(r.content)
            err_node = error_xml.find('error')
            if err_node is not None:
                error_msg += f" - API Message: {err_node.text}"
        except ElementTree.ParseError:
            pass 
        
        for track_dict in tracks_to_scrobble_api:
            api_response_results.append({
                "track": f"{track_dict['artist']} - {track_dict['title']}",
                "status": "fail",
                "error": error_msg
            })
        # Merge api_response_results back into detailed_batch_results based on original order
        # This ensures "skipped" tracks are preserved and API results are added for scrobbled tracks.
        final_batch_results = []
        api_result_idx = 0
        for original_track_dict in tracks_batch_dicts:
            if original_track_dict['flag'] not in ['L', 'S']:
                # This track was skipped locally, find its pre-generated result
                for res in detailed_batch_results:
                    if res['status'] == 'skipped' and res['track'] == f"{original_track_dict['artist']} - {original_track_dict['title']}":
                        final_batch_results.append(res)
                        break
            else:
                # This track was intended for API, get its result from api_response_results
                if api_result_idx < len(api_response_results):
                    final_batch_results.append(api_response_results[api_result_idx])
                    api_result_idx += 1
                else:
                    final_batch_results.append({
                        "track": f"{original_track_dict['artist']} - {original_track_dict['title']}",
                        "status": "fail",
                        "error": "internal logic error (API result missing for scrobbled track)"
                    })
        return final_batch_results

    try:
        data = ElementTree.fromstring(r.content)
        if data.attrib.get('status') != 'ok':
            err_node = data.find('error')
            error_msg = err_node.text if err_node is not None else "unknown API error for batch"
            for track_dict in tracks_to_scrobble_api:
                api_response_results.append({
                    "track": f"{track_dict['artist']} - {track_dict['title']}",
                    "status": "fail",
                    "error": error_msg
                })
            # Extend detailed_batch_results with API errors for sent tracks
            final_batch_results = []
            api_result_idx = 0
            for original_track_dict in tracks_batch_dicts:
                if original_track_dict['flag'] not in ['L', 'S']:
                    for res in detailed_batch_results:
                        if res['status'] == 'skipped' and res['track'] == f"{original_track_dict['artist']} - {original_track_dict['title']}":
                            final_batch_results.append(res)
                            break
                else:
                    if api_result_idx < len(api_response_results):
                        final_batch_results.append(api_response_results[api_result_idx])
                        api_result_idx += 1
                    else:
                        final_batch_results.append({
                            "track": f"{original_track_dict['artist']} - {original_track_dict['title']}",
                            "status": "fail",
                            "error": "internal logic error (API result missing for scrobbled track)"
                        })
            return final_batch_results

        scrobbles_node = data.find('scrobbles')
        if scrobbles_node is None:
            error_msg = "unexpected API response structure for scrobble batch"
            for track_dict in tracks_to_scrobble_api:
                api_response_results.append({
                    "track": f"{track_dict['artist']} - {track_dict['title']}",
                    "status": "fail",
                    "error": error_msg
                })
            final_batch_results = []
            api_result_idx = 0
            for original_track_dict in tracks_batch_dicts:
                if original_track_dict['flag'] not in ['L', 'S']:
                    for res in detailed_batch_results:
                        if res['status'] == 'skipped' and res['track'] == f"{original_track_dict['artist']} - {original_track_dict['title']}":
                            final_batch_results.append(res)
                            break
                else:
                    if api_result_idx < len(api_response_results):
                        final_batch_results.append(api_response_results[api_result_idx])
                        api_result_idx += 1
                    else:
                        final_batch_results.append({
                            "track": f"{original_track_dict['artist']} - {original_track_dict['title']}",
                            "status": "fail",
                            "error": "internal logic error (API result missing for scrobbled track)"
                        })
            return final_batch_results

        # Parse individual scrobble results within the batch
        # The API returns scrobbles in the order they were sent
        for i, scrobble_node in enumerate(scrobbles_node.findall('scrobble')):
            track_info_from_sent_list = tracks_to_scrobble_api[i] 
            
            artist = scrobble_node.find('artist').text if scrobble_node.find('artist') is not None else track_info_from_sent_list['artist']
            track_name = scrobble_node.find('track').text if scrobble_node.find('track') is not None else track_info_from_sent_list['title']
            
            status = "ok" if scrobble_node.attrib.get('accepted') == '1' else "fail"
            error = None
            ignored_message_node = scrobble_node.find('ignoredMessage')
            if ignored_message_node is not None and ignored_message_node.attrib.get('code') != '0':
                error = ignored_message_node.text
                status = "fail" # Mark as fail if ignored

            api_response_results.append({
                "track": f"{artist} - {track_name}",
                "status": status,
                "error": error
            })
    except ElementTree.ParseError as e:
        error_msg = f"XML parsing error: {e}"
        for track_dict in tracks_to_scrobble_api:
            api_response_results.append({
                "track": f"{track_dict['artist']} - {track_dict['title']}",
                "status": "fail",
                "error": error_msg
            })
    except IndexError:
        error_msg = "mismatched scrobble results count from API (some tracks might be missing results)"
        for i in range(len(api_response_results), len(tracks_to_scrobble_api)):
            track_dict = tracks_to_scrobble_api[i]
            api_response_results.append({
                "track": f"{track_dict['artist']} - {track_dict['title']}",
                "status": "fail",
                "error": error_msg
            })

    # Merge api_response_results back into detailed_batch_results based on original order
    # This ensures "skipped" tracks are preserved and API results are added for scrobbled tracks.
    final_batch_results = []
    api_result_idx = 0
    for original_track_dict in tracks_batch_dicts:
        if original_track_dict['flag'] not in ['L', 'S']:
            # This track was skipped locally, find its pre-generated result
            found_skipped = False
            for res in detailed_batch_results:
                if res['status'] == 'skipped' and res['track'] == f"{original_track_dict['artist']} - {original_track_dict['title']}":
                    final_batch_results.append(res)
                    found_skipped = True
                    break
            if not found_skipped: # Fallback if not found (shouldn't happen with correct logic)
                 final_batch_results.append({
                    "track": f"{original_track_dict['artist']} - {original_track_dict['title']}",
                    "status": "fail",
                    "error": "internal logic error (skipped track result not found)"
                })
        else:
            # This track was sent to the API, get its result from api_response_results
            if api_result_idx < len(api_response_results):
                final_batch_results.append(api_response_results[api_result_idx])
                api_result_idx += 1
            else:
                final_batch_results.append({
                    "track": f"{original_track_dict['artist']} - {original_track_dict['title']}",
                    "status": "fail",
                    "error": "internal logic error (API result missing for scrobbled track)"
                })

    return final_batch_results


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
    """Handles the submission of parsed tracks to Last.fm in batches."""
    if 'session_key' not in session or 'parsed_tracks' not in session:
        return jsonify({"error": "unauthorized or no tracks loaded"}), 401

    offset_hours = int(request.json.get('offset_hours', 0))
    offset_seconds = offset_hours * 3600
    session_key = session['session_key']
    tracks = session['parsed_tracks'] # This is now a list of dictionaries

    all_results = []
    total_success = 0
    total_failure = 0
    total_skipped = 0 # Track skipped count
    
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
            elif result['status'] == 'skipped':
                total_skipped += 1
            else: # status == 'fail'
                total_failure += 1
        
        # Removed: time.sleep(1) # No delay between batches

    return jsonify({"success": total_success, "failure": total_failure, "skipped": total_skipped, "results": all_results})

if __name__ == '__main__':
    app.run(debug=True)
