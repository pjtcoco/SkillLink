# import gevent
# from gevent import monkey
# monkey.patch_all()
from urllib import response
import firebase_admin, json,re, random, logging, google, requests, bcrypt, time, pytz, base64, dropbox, uuid
from google.cloud import firestore
from flask_session import Session
from flask_socketio import SocketIO, emit, join_room, leave_room
from geopy.geocoders import Nominatim
import firebase_admin.db
from flask_cors import CORS
from urllib3.exceptions import ReadTimeoutError
from config import Config
from firebase_admin import credentials, db, exceptions, auth, firestore
from datetime import timezone, timedelta, datetime
from dateutil.tz import tzutc
from geopy.distance import geodesic
from flask import Flask, session,  request, jsonify, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
CORS(app)
app.config.from_object(Config)
app.config['SECRET_KEY'] = '34'
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

GOOGLE_MAPS_API_KEY = 'GOOLE_API_KEY'
socketio = SocketIO(app, cors_allowed_origins='*')

# Provide the path to the service account key file
service_account_key = "C:/Users/LENOVO/Desktop/SkillLink/backend/skilllink.json"

# Initialize the Firebase Admin SDK
cred = credentials.Certificate(service_account_key)
firebase_admin.initialize_app(cred, {
    'databaseURL': ''
    
})
firebase_config = {
  "apiKey": "",
  "authDomain": "",
  "databaseURL": "",
  "projectId": "",
  "storageBucket": "",
  "messagingSenderId": "",
  "appId": "",
  "measurementId": ""
}

# Get a reference to the Realtime Database
rtdb = firebase_admin.db
rtdb_ref = rtdb.reference('/')


# Get a reference to Firestore
firestore_db = firebase_admin.firestore.client()
class BytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode('utf-8')
        return json.JSONEncoder.default(self, obj)
    
def get_current_user_id():
    try:
        user = auth.get_auth().current_user
        return user.uid
    except Exception as e:
        print(f"Error getting current user ID: {e}")
        return None
@app.errorhandler(400)
def handle_400_error(error):
    return jsonify({"error": str(error)}), 400

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({'error': 'Method Not Allowed'}), 405


# def send_sms(phone_number, message):
#     account_sid = ''
#     auth_token = ''
#     twilio_sms_url = f''
#     payload = {
#         'To': phone_number,
#         'Body': message,
#         'From': '',
#     }
#     response = requests.post(twilio_sms_url, data=payload, auth=(account_sid, auth_token))
#     return response

def validate_data(data):
    required_fields = ['address', 'fullName', 'email', 'phoneNumber', 'password']
    if any(field not in data for field in required_fields):
        return False, 'Missing required fields'

    # Get location coordinates
    location_url = f'https://maps.googleapis.com/maps/api/geocode/json?address={data["address"]}&key={GOOGLE_MAPS_API_KEY}'
    location_response = requests.get(location_url)
    location_data = location_response.json()
    if location_data['status'] != 'OK':
        return False, 'Error getting user location'

    return True, location_data

# Email validation regex
EMAIL_REGEX = r'^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$'


@app.route('/api/signup/technician', methods=['POST'])
def signup():
    data = request.get_json()

    is_valid, location_data = validate_data(data)
    if not is_valid:
        missing_fields = [field for field in ['address', 'fullName', 'email', 'phoneNumber', 'password'] if field not in data]
        return jsonify({'message': f'Missing required fields: {", ".join(missing_fields)}'}), 400

    is_valid, location_data = validate_data(data)
    if not is_valid:
        return jsonify({'message': location_data}), 400

    # Check if the phone number is valid (starts with '+237')
    phone_number = data['phoneNumber']
    if not phone_number.startswith('+237'):
        return jsonify({'message': 'Invalid phone number. Please enter a Cameroonian phone number.'}), 400

    # Check if the email or phone number already exists
    ref = rtdb.reference('Technicians')
    technicians = ref.order_by_child('email').equal_to(data['email']).get()
    if technicians:
        return jsonify({'message': 'User with this email already exists'}), 400

    technicians = ref.order_by_child('phoneNumber').equal_to(phone_number).get()
    if technicians:
        return jsonify({'message': 'User with this phone number already exists'}), 400

    # Hash the password using bcrypt
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), salt)

    # Save the hashed password to the database
    ref = rtdb.reference('Technicians')
    last_online = datetime.now(timezone.utc)
    technician_ref = ref.push()
    technician_id = technician_ref.key
    technician_ref.set({
        'fullName': data['fullName'],
        'email': data['email'],
        'age': data['age'],
        'gender': data['gender'],
        'specialization': data['specialization'],
        'workExperience': data['workExperience'],
        'phoneNumber': data['phoneNumber'],
        'password': hashed_password.decode('utf-8'),  # Save the hashed password as a string
        'otp': ''.join(random.choices('0123456789', k=6)),
        'otp_expiration': int(time.time() * 1000) + 300000,  # OTP expires in 5 minutes
        'last_online': json.dumps(last_online, default=str),  # Save the last_online field as a datetime object
        'location': {
            'latitude': location_data['results'][0]['geometry']['location']['lat'],
            'longitude': location_data['results'][0]['geometry']['location']['lng']
        }
    })
    # Store multiple attributes in the session
    session['phone_number'] = phone_number
    session['technician_id'] = technician_id
    

    # Check password complexity requirements
    if len(data['password']) < 8:
        return jsonify({'message': 'Password must be at least 8 characters long.'}), 400
    if not any(char.isupper() for char in data['password']):
        return jsonify({'message': 'Password must contain at least one uppercase letter.'}), 400
    if not any(char.isdigit() for char in data['password']):
        return jsonify({'message': 'Password must contain at least one digit.'}), 400

    # Get the technician's location using the Google Maps API
    location_url = f'https://maps.googleapis.com/maps/api/geocode/json?address={data["address"]}&key=GOOLE_API_KEY'
    location_response = requests.get(location_url)
    location_data = location_response.json()
    if location_data['status'] != 'OK':
        return jsonify({'message': 'Error getting user location'}), 400
    latitude = location_data['results'][0]['geometry']['location']['lat']
    longitude = location_data['results'][0]['geometry']['location']['lng']

    # Send OTP to technician's phone number
    otp = ''.join(random.choices('0123456789', k=6))
    # message = f'Your OTP is {otp}'
    # response = send_sms(phone_number, message)  # Call the send_sms function
    # if response.status_code != 200:
    #     return jsonify({'message': 'Failed to send OTP'}), 400

    return jsonify({'message': 'technician created successfully', 'technician_id': technician_id}), 201
    # Verify the OTP
@app.route('/api/verify/technician', methods=['POST'])
def verify_technician():
    data = request.get_json()
    if not data or 'otp' not in data:
        return jsonify({'message': 'Verification code is required'}), 400

    verification_code = data['otp']

    # Get the phone number from the session
    phone_number = session.get('phone_number')
    if phone_number is None:
        return jsonify({'message': 'Invalid request'}), 400

    # Ignore the phone number sent in the request body
    # del data['phoneNumber']  # uncomment this line if you want to remove the phone number from the request body

    # Verify the OTP
    technicians_ref = db.reference('Technicians')
    technicians_snapshots = technicians_ref.get()

    if technicians_snapshots is None:
        print("Technicians node not found in the database")
        return jsonify({'message': 'Technicians node not found'}), 404

    for technicians_id, technician_data in technicians_snapshots.items():
        if 'phoneNumber' in technician_data:
            db_phone_number = technician_data['phoneNumber']  
            if db_phone_number == phone_number:
                if 'otp' in technician_data and technician_data['otp'] == verification_code and 'otp_expiration' in technician_data and technician_data['otp_expiration'] / 1000 > time.time():
                    # OTP is valid, update the Technician data
                    technicians_ref.child(technicians_id).update({'verified': True, 'otp': None, 'otp_expiration': None})
                    return jsonify({'message': 'Technician verified successfully'}), 200
                else:
                    return jsonify({'message': 'Invalid OTP'}), 400

    print("Technician not found in the database")
    return jsonify({'message': 'Technician not found'}), 404

@app.route('/api/database/technician', methods=['GET'])
def database():
    return jsonify(db.reference().get())

@app.route('/api/resend', methods=['POST'])
def resend_code():
    data = request.get_json()
    phone_number = data['phoneNumber']

    # Get the Technician's reference
    technicians_ref = db.reference('Technicians')

    # Find the Technician's node
    technicians_snapshots = technicians_ref.get()
    for technician_id, technician_data in technicians_snapshots.items():
        if 'phoneNumber' in technician_data and technician_data['phoneNumber'] == phone_number:
            # Delete the old OTP
            technicians_ref.child(technician_id).child('otp').set('')

            # Set the verify state to false
            technicians_ref.child(technician_id).child('verified').set(False)

            # Generate a new verification code and save it to the database
            verification_code = ''.join(random.choices('0123456789', k=6))
            technicians_ref.child(technician_id).child('otp').set(verification_code)
            technicians_ref.child(technician_id).child('otp_expiration').set(int(time.time() * 1000) + 300000)

            # Send the new OTP to the Technician's phone number
        message = f'Your new OTP is {verification_code}'
        if response.status_code != 200:
                return jsonify({'message': 'Failed to send OTP'}), 400

        return jsonify({'success': True})

    # Return an error message if the technician is not found
    return jsonify({'message': 'Technician not found'}), 404

    
@app.route('/api/login/technician', methods=['POST'])
def technician_login():
    data = request.get_json()

    # Check if the email and password are correct
    ref = db.reference('Technicians')
    technician = ref.order_by_child('email').equal_to(data['email']).get()
    if not technician:
        return jsonify({'message': 'Technician with this email does not exist'}), 400

    technician_id = list(technician.keys())[0]
    technician_data = technician[technician_id]
    if not bcrypt.checkpw(data['password'].encode('utf-8'), technician_data['password'].encode('utf-8')):
        return jsonify({'message': 'Password is incorrect'}), 400

    # Store the technician_id and fullName in the session
    session['technician_id'] = technician_id
   

    # Return a success response with a redirect to the profile page
    return jsonify({'message': 'Login successful', 'edirect': '/api/profile/technician'}), 200



@app.route('/api/logout', methods=['POST'])
def technician_logout():
    # Invalidate the technician's session
    session.clear()

    # Redirect the technician to the login page
    return redirect(url_for('login'))

@app.route('/api/delete_technician_account/<string:technician_id>', methods=['DELETE', 'POST'])
def technician_delete_account(technician_id):
     # Check if the technician exists in the database
    ref = db.reference('Technicians')
    technician = ref.child(technician_id).get()
    if not technician:
        return jsonify({'message': 'Technician not found'}), 404

    # Delete the technician from the database
    ref.child(technician_id).delete()

    return jsonify({'message': 'Technician account deleted successfully'}), 200

@app.route('/api/forgot_password', methods=['POST'])
def technician_forgot_password():
    # Get the technician's email from the request data
    email = request.json['email']

    # Check if the email exists in the Firebase realtime database
    ref = db.reference('users')
    user = ref.order_by_child('email').equal_to(email).get()
    if not user:
        return jsonify({'message': 'User with this email does not exist'}), 400

    # Send a password reset email to the user's email address
    try:
        auth.send_password_reset_email(email)
        return jsonify({'message': 'Password reset email sent'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500


@app.route('/api/technicians/search', methods=['GET'])
def search_technicians():
    # Get the search query from the request parameters
    query = request.args.get('q')

    # Get the user's current location using the ipapi.co API
    response = requests.get('https://ipapi.co/json/')
    if response.status_code != 200:
            logging.error(f"IPAPI.co API error: {response.text}")
            return jsonify([]), 500
    data = response.json()
    if 'latitude' not in data or 'longitude' not in data:
        return jsonify([]), 500

    user_lat, user_long = data['latitude'], data['longitude']

    # Fetch all technicians from the database
    technicians = rtdb_ref.child('Technicians').get()

    # If no technicians were found, return an empty list
    if not technicians:
        return jsonify([])

    # Convert the Firebase data to a list of dictionaries
    technician_list = []
    for technician_id, technician_data in technicians.items():
        technician_data['id'] = technician_id
        technician_list.append(technician_data)

    # Filter the technicians by search query
    results = []
    for technician in technician_list:
        for key, value in technician.items():
            if query.lower() in str(key).lower() or query.lower() in str(value).lower():
                # Calculate the distance between the technician and the user
                technician_lat, technician_long = technician['location']['latitude'], technician['location']['longitude']
                distance = geodesic((user_lat, user_long), (technician_lat, technician_long)).miles
                technician['distance'] = distance
                results.append(technician)
                break

    # Sort the results by distance
    results.sort(key=lambda x: x['distance'])

    # Return the search results as JSON
    return jsonify(results)


@app.route('/api/signup/user', methods=['POST'])
def user_signup():
    data = request.get_json()

    is_valid, location_data = validate_data(data)
    if not is_valid:
        missing_fields = [field for field in ['address', 'fullName', 'email', 'phoneNumber', 'password'] if field not in data]
        return jsonify({'message': f'Missing required fields: {", ".join(missing_fields)}'}), 400

    is_valid, location_data = validate_data(data)
    if not is_valid:
        return jsonify({'message': location_data}), 400

    # Check if the phone number is valid (starts with '+237')
    phone_number = data['phoneNumber']
    if not phone_number.startswith('+237'):
        return jsonify({'message': 'Invalid phone number. Please enter a Cameroonian phone number.'}), 400

    # Check if the email or phone number already exists
    ref = db.reference('Users')
    users = ref.order_by_child('email').equal_to(data['email']).get()
    if users:
        return jsonify({'message': 'User with this email already exists'}), 400

    users = ref.order_by_child('phoneNumber').equal_to(phone_number).get()
    if users:
        return jsonify({'message': 'User with this phone number already exists'}), 400

    # Hash the password using bcrypt
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), salt)

    # Save the hashed password to the database
    ref = db.reference('Users')
    user_ref = ref.push()
    user_id = user_ref.key
    user_ref.set({
        'fullName': data['fullName'],
        'email': data['email'],
        'age': data['age'],
        'gender': data['gender'],
        'phoneNumber': data['phoneNumber'],
        'password': hashed_password.decode('utf-8'),  # Save the hashed password as a string
        'otp': ''.join(random.choices('0123456789', k=6)),
        'otp_expiration': int(time.time() * 1000) + 3000000,  # OTP expires in 5 minutes
        'location': {
            'latitude': location_data['results'][0]['geometry']['location']['lat'],
            'longitude': location_data['results'][0]['geometry']['location']['lng']
        }
    })

    # Check password complexity requirements
    if len(data['password']) < 8:
        return jsonify({'message': 'Password must be at least 8 characters long.'}), 400
    if not any(char.isupper() for char in data['password']):
        return jsonify({'message': 'Password must contain at least one uppercase letter.'}), 400
    if not any(char.isdigit() for char in data['password']):
        return jsonify({'message': 'Password must contain at least one digit.'}), 400

    # Get the user's location using the Google Maps API
    location_url = f'https://maps.googleapis.com/maps/api/geocode/json?address={data["address"]}&key=GOOLE_API_KEY'
    location_response = requests.get(location_url)
    location_data = location_response.json()
    if location_data['status'] != 'OK':
        return jsonify({'message': 'Error getting user location'}), 400
    latitude = location_data['results'][0]['geometry']['location']['lat']
    longitude = location_data['results'][0]['geometry']['location']['lng']

    # Send OTP to user's phone number
    otp = ''.join(random.choices('0123456789', k=6))
    # message = f'Your OTP is {otp}'
    # response = send_sms(phone_number, message)  # Call the send_sms function
    # if response.status_code != 200:
    #     return jsonify({'message': 'Failed to send OTP'}), 400

    return jsonify({'message': 'User created successfully', 'user_id': user_id}), 201

@app.route('/api/verify/user', methods=['POST'])
def verify_user():
    data = request.get_json()
    if not data or 'otp' not in data:
        return jsonify({'message': 'Verification code is required'}), 400

    verification_code = data['otp']

    # Get the phone number from the session
    phone_number = session.get('phone_number')
    if phone_number is None:
        return jsonify({'message': 'Invalid request'}), 400

    # Ignore the phone number sent in the request body
    # del data['phoneNumber']  # uncomment this line if you want to remove the phone number from the request body

    # Verify the OTP
    users_ref = db.reference('Users')
    users_snapshots = users_ref.get()

    if users_snapshots is None:
        print("Users node not found in the database")
        return jsonify({'message': 'Users node not found'}), 404

    for users_id, user_data in users_snapshots.items():
        if 'phoneNumber' in user_data:
            db_phone_number = user_data['phoneNumber']  
            if db_phone_number == phone_number:
                if 'otp' in user_data and user_data['otp'] == verification_code and 'otp_expiration' in user_data and user_data['otp_expiration'] / 1000 > time.time():
                    # OTP is valid, update the Technician data
                    users_ref.child(users_id).update({'verified': True, 'otp': None, 'otp_expiration': None})
                    return jsonify({'message': 'User verified successfully'}), 200
                else:
                    return jsonify({'message': 'Invalid OTP'}), 400

    print("User not found in the database")
    return jsonify({'message': 'User not found'}), 404

@app.route('/api/login/user', methods=['POST'])
def user_login():
    data = request.get_json()
    print(f"Login request received with email: {data['email']}")

    # Check if the email or phone number exists
    ref = db.reference('Users')
    user = ref.order_by_child('email').equal_to(data['email']).get()
    if not user:
        print(f"User with email {data['email']} not found")
        return jsonify({'message': 'User with this email or phone number does not exist'}), 400

    user_id = list(user.keys())[0]
    user_data = user[user_id]
    if not bcrypt.checkpw(data['password'].encode('utf-8'), user_data['password'].encode('utf-8')):
        print(f"Password for user {user_id} is incorrect")
        return jsonify({'message': 'Password is incorrect'}), 400

    # Store the user_id and fullName in the session
    session['user_id'] = user_id
    

    # Return a success response with a redirect to the profile page
    print(f"User {user_id} logged in successfully")
    return jsonify({'message': 'Login successful'}), 200

@app.route('/api/logout', methods=['POST'])
def user_logout():
    # Invalidate the user's session
    session.clear()

    # Redirect the user to the login page
    return redirect(url_for('login'))

@app.route('/api/delete_user_account/<string:user_id>', methods=['DELETE', 'POST'])
def user_delete_account(user_id):
     # Check if the user exists in the database
    ref = db.reference('Users')
    user = ref.child(user_id).get()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Delete the user from the database
    ref.child(user_id).delete()

    return jsonify({'message': 'User account deleted successfully'}), 200
@app.route('/api/forgot_password', methods=['POST'])
def user_forgot_password():
    # Get the user's email from the request data
    email = request.json['email']

    # Check if the email exists in the Firebase realtime database
    ref = db.reference('users')
    user = ref.order_by_child('email').equal_to(email).get()
    if not user:
        return jsonify({'message': 'User with this email does not exist'}), 400

    # Send a password reset email to the user's email address
    try:
        auth.send_password_reset_email(email)
        return jsonify({'message': 'Password reset email sent'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    

@app.route('/api/technicians/nearby/', methods=['GET'])
def get_nearby_technicians():
    try:
        lat = request.args.get('lat')
        lng = request.args.get('lng')

        if not lat or not lng:
            return jsonify({'message': 'lat and lng are required'}), 400

        lat = float(lat)
        lng = float(lng)

        ref = db.reference('Technicians')
        technicians = ref.order_by_child('location/latitude').start_at(lat - 0.1).end_at(lat + 0.1).get()

        nearby_technicians = []
        technician_ids = []
        for technician_id, technician_data in technicians.items():
            last_online = technician_data.get('last_online')
            if last_online is not None:
                last_online = format_last_online(last_online)
            else:
                last_online = 'Never online'

            location = technician_data['location']
            distance = geodesic((lat, lng), (location['latitude'], location['longitude'])).km

            # Make a request to the Google Maps API with a timeout
            google_maps_api_key = 'GOOLE_API_KEY'
            url = f"https://maps.googleapis.com/maps/api/geocode/json?latlng={location['latitude']},{location['longitude']}&key={google_maps_api_key}"
            response = requests.get(url, timeout=5)

            # Parse the response as JSON
            result = response.json()

            # Extract the address from the response
            address = None
            if result['status'] == 'OK' and len(result['results']) > 0:
                address = result['results'][0]['formatted_address']

            # Get the profile picture URL
            profile_picture_url = technician_data.get('profilePicture')

            nearby_technicians.append({
                'technician_id': technician_id,
                'fullName': technician_data['fullName'],
                'email': technician_data['email'],
                'age': technician_data['age'],
                'gender': technician_data['gender'],
                'specialization': technician_data['specialization'],
                'workExperience': technician_data['workExperience'],
                'phoneNumber': technician_data['phoneNumber'],
                'last_online': last_online,
                'location': {
                    'latitude': location['latitude'],
                    'longitude': location['longitude'],
                    'address': address
                },
                'distance': round(distance, 2),
                'profilePicture': profile_picture_url  # Add the profile picture URL
            })

            technician_ids.append(technician_id)

        session['technician_ids'] = technician_ids

        return jsonify(nearby_technicians), 200
    except requests.exceptions.Timeout:
        print("Timeout error")
        return jsonify({'message': 'Internal Server Error'}), 500


def format_last_online(last_online_timestamp):
    if last_online_timestamp is None:
        return "Never online"

    try:
        # Parse the timestamp in the format of YYYY-MM-DDTHH:MM:SS.ssssss+HH:MM
        last_online_date = datetime.strptime(last_online_timestamp, '%Y-%m-%dT%H:%M:%S.%f%z')
    except ValueError:
        try:
            # Parse the timestamp in the format of YYYY-MM-DD HH:MM:SS
            last_online_date = datetime.strptime(last_online_timestamp, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return "Invalid last online timestamp"

    # Remove the timezone from the last_online_date variable
    if last_online_date.tzinfo is not None:
        last_online_date = last_online_date.replace(tzinfo=None)

    # Make sure that last_online_date is an aware datetime object
    tz = pytz.timezone('Africa/Douala')
    last_online_date = tz.localize(last_online_date)

    # Get the current time as an aware datetime object
    now = datetime.now(tz)

    # Calculate the time since the last_online timestamp
    time_since_last_online = now - last_online_date

    # Format the last_online timestamp as a string
    last_online_string = last_online_date.strftime('%Y-%m-%d %H:%M:%S')

    # Format the time since the last_online timestamp as a string
    time_since_string = ''
    days = time_since_last_online.days
    hours, remainder = divmod(time_since_last_online.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if days > 0:
        time_since_string += f'{days} day{"s" if days > 1 else ""} '
    if hours > 0:
        time_since_string += f'{hours} hour{"s" if hours > 1 else ""} '
    if minutes > 0:
        time_since_string += f'{minutes} minute{"s" if minutes > 1 else ""} '
    if seconds > 0:
        time_since_string += f'{seconds} second{"s" if seconds > 1 else ""} ago'

    return f' {last_online_string} ({time_since_string})'


@app.route('/api/profile/technician', methods=['GET', 'POST'])
def technician_profile():
    tz = pytz.timezone('Africa/Douala')
    now = datetime.now(tz)
    # Check if the technician is logged in
    technician_id = session.get('technician_id')
    if not technician_id:
        return jsonify({'message': 'Please log in to view your profile'}), 401

    # Update the last_online attribute
    last_online = now.isoformat()
    technician_ref = rtdb_ref.child('Technicians').child(technician_id)
    technician_ref.update({'last_online': last_online})

    if request.method == 'GET':
        # Fetch the technician data from the Realtime Database
        technician_ref = rtdb_ref.child('Technicians').child(technician_id)
        technician_data = technician_ref.get()

        if technician_data is None:
            return jsonify({'error': 'Technician not found'}), 404

        # Process the technician data
        technician = {}

        if 'profilePicture' in technician_data:
            profile_picture_url = technician_data['profilePicture']
            response = requests.get(profile_picture_url)
            profile_picture_content = response.content
            technician['profilePictureContent'] = base64.b64encode(profile_picture_content).decode('utf-8')

        if 'cv' in technician_data:
            cv_url = technician_data['cv']
            response = requests.get(cv_url)
            cv_content = response.content
            technician['cvContent'] = base64.b64encode(cv_content).decode('utf-8')

        technician['age'] = technician_data['age']
        technician['email'] = technician_data['email']
        technician['fullName'] = technician_data['fullName']
        technician['gender'] = technician_data['gender']
        technician['phoneNumber'] = technician_data['phoneNumber']
        technician['specialization'] = technician_data['specialization']
        technician['verified'] = technician_data['verified']
        technician['workExperience'] = technician_data['workExperience']

        # Handle location field
        if isinstance(technician_data['location'], dict):
            lat = technician_data['location']['latitude']
            lng = technician_data['location']['longitude']
        else:
            lat = None
            lng = None

        # Convert the latitude and longitude values to an address using Google Maps API
        google_maps_api_key = 'GOOLE_API_KEY'
        if lat and lng:
            url = f"https://maps.googleapis.com/maps/api/geocode/json?latlng={lat},{lng}&key={google_maps_api_key}"
            try:
                response = requests.get(url)
                response.raise_for_status()
                
                # Parse the response as JSON
                result = response.json()
                # Extract the address from the response
                if result['status'] == 'OK' and len(result['results']) > 0:
                    address = result['results'][0]['formatted_address']
                   
                    technician['location'] = address
                else:
                    technician['location'] = 'Unknown location'
            except requests.exceptions.RequestException as e:
                technician['location'] = f'Error: {e}'
            except KeyError as e:
                technician['location'] = f'Error: {e}'
        else:
            technician['location'] = technician_data['location']

        return jsonify(technician), 200
    

@app.route('/api/profile/technician/edit', methods=['POST'])
def edit_technician_profile():
    technician_id = session.get('technician_id')
    if not technician_id:
        return jsonify({'message': 'Please log in to edit your profile'}), 401

    # Get the updated profile data from the request
    data = request.form


    # Check if files are being sent
    if 'profilePicture' in request.files:
        profile_picture = request.files['profilePicture']
        print("Profile picture file received")
    else:
        print("No profile picture file received")

    if 'cv' in request.files:
        cv = request.files['cv']
        print("CV file received")
    else:
        print("No CV file received")

    technician_ref = rtdb_ref.child('Technicians').child(technician_id)

    # Update the technician's details only if the field is present and has a value
    updates = {}
    for field in ['fullName', 'age', 'email', 'gender', 'phoneNumber', 'specialization', 'workExperience']:
        if field in data and data[field]:
            updates[field] = data[field]

    # Handle location update
    if 'location_latitude' in data and 'location_longitude' in data:
        location_data = {
            'latitude': data['location_latitude'],
            'longitude': data['location_longitude']
        }
        updates['location'] = location_data

    # Handle profile picture upload to Dropbox
    if 'profilePicture' in request.files:
        profile_picture = request.files['profilePicture']
        dbx = dropbox.Dropbox('')
        file_path = '/profile_pictures/' + technician_id + '_' + uuid.uuid4().hex + '.jpg'
        dbx.files_upload(profile_picture.read(), file_path)
        try:
            profile_picture_url = dbx.files_get_temporary_link(file_path).link
        except dropbox.exceptions.ApiError as e:
            print(f"Error getting temporary link: {e}")
        updates['profilePicture'] = profile_picture_url

    # Handle CV upload to Dropbox
    if 'cv' in request.files:
        cv = request.files['cv']
        dbx = dropbox.Dropbox('')
        file_path = '/cvs/' + technician_id + '_' + uuid.uuid4().hex + '.pdf'
        dbx.files_upload(cv.read(), file_path)
        cv_url = dbx.files_get_temporary_link(file_path).link
        updates['cv'] = cv_url

    

    if updates:
        technician_ref.update(updates)
    else:
        return jsonify({'message': 'No updates provided'}), 400

    return jsonify({'message': 'Profile updated successfully'}), 200


@app.route('/api/technician/details/<string:technician_id>', methods=['GET'])
def get_technician_details(technician_id):
    session['technician_id'] = technician_id  # Store technician ID in session
    ref = rtdb.reference('Technicians')
    technician_data = ref.child(technician_id).get()
    session['technician_full_name'] = technician_data['fullName']  # Store technician full name in session
    user_id = session.get('user_id')
    if user_id is None:
        return jsonify({'message': 'User ID not found in session'}), 404
    if technician_data:
        # Convert the latitude and longitude values to an address using Google Maps API
        lat = technician_data['location']['latitude']
        lng = technician_data['location']['longitude']
        
        
        # Use Google Maps Geocoding API to convert coordinates to address
        api_key = 'GOOLE_API_KEY'
        url = f'https://maps.googleapis.com/maps/api/geocode/json?latlng={lat},{lng}&key={api_key}'
        response = requests.get(url)
        data = response.json()
        address = data['results'][0]['formatted_address']
        
        # Query Firestore for reviews
        reviews_ref = firestore_db.collection('reviews')
        reviews_query = reviews_ref.where('technician_id', '==', technician_id)
        reviews = reviews_query.stream()
        
        reviews_data = []
        for review in reviews:
            review_data = review.to_dict()
            user_id = review_data.get('written_by')
            if user_id is None:
                written_by = "Unknown"
            elif user_id == session.get('user_id'):  
                written_by = 'You'
            else:
                sender_ref = rtdb.reference('Users/' + user_id)
                sender_data = sender_ref.get()
                if sender_data is not None:
                    written_by = sender_data.get('fullName')
                else:
                    written_by = "Unknown"
            print(session['user_id'])
            
            reviews_data.append({
                'rating': review_data['rating'],
                'review': review_data['review'],
                'created_at': review_data['created_at'].strftime('%Y-%m-%d %H:%M:%S'),
                'written_by': written_by
            })
        
        return jsonify({
            'fullName': technician_data['fullName'],
            'email': technician_data['email'],
            'specialization': technician_data['specialization'],
            'workExperience': technician_data['workExperience'],
            'phoneNumber': technician_data['phoneNumber'],
            'location': address,
            'last_online': format_last_online(technician_data.get('last_online')),
            'reviews': reviews_data
            # 'profilePicture': technician_data['profilePicture'],
            # Add any other details you want to display
        }), 200
        
    else:
        return jsonify({'message': 'Technician not found'}), 404


@app.route('/api/review/submit', methods=['POST'])
def submit_review():
    technician_id = session.get('technician_id')
    user_id = session.get('user_id')
    if technician_id and user_id:
        review_data = request.get_json()
        rating = review_data.get('rating')
        review_text = review_data.get('review')
        
        # Validate the review data
        if rating and review_text:
            # Create a new review document in Firestore
            review_ref = firestore_db.collection('reviews').document()
            review_ref.set({
                'technician_id': technician_id,
                'written_by': user_id,  # Store the user_id in the review document
                'rating': rating,
                'review': review_text,
                'created_at': datetime.now()
            })
            return jsonify({'message': 'Review submitted successfully'}), 201
        else:
            return jsonify({'message': 'Invalid review data'}), 400
    else:
        return jsonify({'message': 'Technician ID or User ID not found in session'}), 404
    
@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('message')
def handle_message(message):
    print('Received message:', message)
    conversation_id = message['conversation_id']
    sender_id = message['sender_id']
    recipient_id = message['recipient_id']

    # Broadcast the message to the sender and the recipient
    emit('message', message, room=sender_id)
    emit('message', message, room=recipient_id)
    
@app.route('/')
def socket_io(path):
    return socketio.handle_request(request, {
        'path': f'/socket.io/{path}',
        'server': '172.20.10.2:5000'
    })
    
@app.route('/api/users/conversations', methods=['GET'])
def get_user_conversations():
    user_id = session.get('user_id')
    if user_id is None:
        return jsonify({'error': 'User ID not found in session'}), 401

    conversations_ref = firestore_db.collection('conversations')
    conversations = conversations_ref.stream()

    conversation_list = []
    for conversation in conversations:
        conversation_dict = conversation.to_dict()
        print("Conversation data:", conversation_dict)
        if user_id in conversation_dict.get('users', {}):
            print("User is part of this conversation")
            user_keys = list(conversation_dict['users'].keys())
            technician_id = [key for key in user_keys if key!= user_id][0]
            technician_full_name = conversation_dict['users'][technician_id]['fullName']

            # Get the messages for this conversation
            messages_ref = conversation.reference.collection('messages')
            messages = messages_ref.stream()
            message_list = []
            if messages:  # Check if there are any messages
                for message in messages:
                    message_data = message.to_dict()
                    if 'sender_id' in message_data:
                        message_list.append({
                            'text': message_data.get('text', ''),
                            'sender_id': message_data.get('sender_id', ''),
                            'timestamp': message_data.get('timestamp', '')
                        })
                    else:
                        # Handle the case where 'sender_id' does not exist
                        print("Warning: 'sender_id' does not exist in message data")

            conversation_dict['technician_full_name'] = technician_full_name
            conversation_dict['messages'] = message_list
            conversation_list.append(conversation_dict)

    print("Conversation list:", conversation_list)
    return jsonify(conversation_list)


def get_technician_full_name(technician_id):
    technician_ref = rtdb_ref.child('Technicians').child(technician_id)
    technician_data = technician_ref.get()
    if technician_data is not None:
        return technician_data.get('fullName', "")
    else:
        return ""  # or some other default value
    
@app.route('/api/create/user/conversations', methods=['POST'])
def create_conversation():
    print("create_conversation function called")
    user_id = session.get('user_id')
    technician_id = session.get('technician_id')
    

    print("Retrieved user_id:", user_id)
    print("Retrieved technician_id:", technician_id)
    

    if not user_id or not technician_id:
        return jsonify({'error': 'Missing user_id or technician_id'}), 400

    # Retrieve all conversations
    conversations_ref = firestore_db.collection('conversations')
    all_conversations = conversations_ref.stream()

    # Filter conversations to find one with both user_id and technician_id
    for conversation in all_conversations:
        users = conversation.to_dict().get('users', {})
        if user_id in users and technician_id in users:
            # If a conversation with this technician and user exists, return the conversation ID
            print("Existing conversation found:", conversation.id)
            return jsonify({'conversation_id': conversation.id}), 200

    # If no conversation with this technician and user exists, create a new one
    conversation_ref = firestore_db.collection('conversations').document()
    conversation_ref.set({
        'users': {
            user_id: {'id': user_id},
            technician_id: {'fullName': get_technician_full_name(technician_id), 'technician_id': technician_id}
        }
    })

    # Return the conversation ID
    return jsonify({'conversation_id': conversation_ref.id}), 201


@app.route('/api/messages', methods=['POST'])
def create_message():
    data = request.get_json()
    print("Received data:", data)
    if 'conversation_id' not in data:
        return jsonify({'error': 'conversation_id is required'}), 400
    conversation_id = data['conversation_id']

    if 'message_text' not in data:
        return jsonify({'error': 'message_text is required'}), 400

    message_text = data['message_text']

    # Get the user_id from the session
    user_id = session.get('user_id')

    if not user_id:
        return jsonify({'error': 'User is not logged in'}), 400

    # Use the user_id as the sender_id
    sender_id = user_id

    # Create a new message document in Firestore
    messages_ref = firestore_db.collection('conversations').document(conversation_id).collection('messages').document()
    messages_ref.set({
        'sender_id': request.json['sender_id'],
        'recipient_id': request.json['recipient_id'],
        'conversation_id': request.json['conversation_id'],
        'message': request.json['message'],
        'created_at': datetime.now()
    })
    
    message_data = {
    'message_id': messages_ref.id,
    'sender_id': request.json['sender_id'],
    'recipient_id': request.json['recipient_id'],
    'conversation_id': request.json['conversation_id'],
    'message': request.json['message'],
    'created_at': datetime.now()
}
    
    # Send the message to the recipient using Socket.IO
    emit('new_message', message_data, to=request.json['recipient_id'])


    return jsonify({'message_id': messages_ref.id}), 201


@app.route('/api/fetch/messages/<string:conversation_id>', methods=['GET'])
def get_messages(conversation_id):
    # Get the user_id from the session
    user_id = session.get('user_id')

    if not user_id:
        return jsonify({'error': 'User is not logged in'}), 400

    # Check if the conversation ID exists in Firestore
    conversation_ref = firestore_db.collection('conversations').document(conversation_id)
    if not conversation_ref.exists:
        return jsonify({'error': 'Conversation not found'}), 404

    # Get all the messages in the conversation
    messages_ref = conversation_ref.collection('messages')
    messages = messages_ref.order_by('timestamp').stream()

    # Create a list to store the retrieved messages
    retrieved_messages = []

    # Iterate over the messages and add them to the list
    for message in messages:
        retrieved_messages.append({
            'id': message.id,
            'text': message.get('text'),
            'senderId': message.get('sender_id'),
            'timestamp': message.get('timestamp')
        })

    # Return the list of retrieved messages
    return jsonify(retrieved_messages)

@app.route('/api/technician/conversations', methods=['GET'])
def get_technician_conversations():
    try:
        technician_id = session.get('technician_id')
        if technician_id is None:
            print("Error: Technician ID not found in session")
            return {'error': 'Technician ID not found in session'}, 401

        print(f'Technician ID: {technician_id}')

        conversations_ref = firestore_db.collection('conversations')
        print('Querying Firestore for conversations...')
        conversations = conversations_ref.stream()

        conversation_list = []
        conversation_ids = {}  # Store conversation IDs in a dictionary
        for conversation in conversations:
            conversation_dict = conversation.to_dict()
            users = conversation_dict.get('users')
            if users:
                for user_id, user_data in users.items():
                    if 'technician_id' in user_data and user_data.get('technician_id') == technician_id:
                        conversation_id = conversation.id  # Get the conversation ID

                        # Retrieve the sender's full name from the Realtime Database
                        for user_id, user_data in users.items():
                            if 'id' in user_data:
                                sender_id = user_data.get('id')  # Retrieve the sender's ID
                                break
                        else:
                            sender_id = None

                        if sender_id is None:
                            print("Error: sender_id is None")
                        else:
                            print(f"Querying Realtime Database for sender ID: {sender_id}")
                            sender_ref = rtdb.reference('Users/' + sender_id)
                            sender_data = sender_ref.get()
                            if sender_data is not None:  # Check if sender_data is not None
                                conversation_name = sender_data.get('fullName')
                            else:
                                conversation_name = "Unknown"  # Set default full name if sender_data is None

                            print(f"Found conversation ID: {conversation_id} for conversation {conversation_name}")

                            # Store the conversation ID in the dictionary
                            conversation_ids[conversation_name] = conversation_id

                            conversation_dict['conversation_id'] = conversation_id
                            conversation_dict['conversation_name'] = conversation_name
                            conversation_list.append(conversation_dict)
                            

                            break
            else:
                print(f"Error: 'users' field not found in conversation {conversation.id}")

        # Store conversation IDs in the session
        session['conversation_ids'] = conversation_ids
        session.modified = True  # Mark the session as modified
        
        

        if not conversation_list:
            print("Error: No conversations found")
            return {'error': 'No conversations found'}, 404

        return jsonify(conversation_list)
    
    

    except Exception as e:
        print(f"Error: {str(e)}")
        print(conversation_list)  # Log the conversation_list before sending it to the frontend

        return {'error': 'Internal Server Error'}, 500



@app.route('/api/technician/conversations/<string:conversation_id>/messages', methods=['GET'])
def get_conversation_messages(conversation_id):
    # Retrieve the conversation IDs from the session
    conversation_ids = session.get('conversation_ids')
    print("Conversation IDs in session:", conversation_ids)
    
    # Check if conversation IDs are not found in the session
    if conversation_ids is None:
        print("Error: Conversation IDs not found in session")
        return {'error': 'Conversation IDs not found in session'}, 401

    # Retrieve the conversation name from the conversation IDs dictionary using the conversation ID
    conversation_name = next((name for name, cid in conversation_ids.items() if cid == conversation_id), None)
    
    # Check if conversation name is not found for the conversation ID
    if conversation_name is None:
        print(f"Error: Conversation name not found for conversation ID {conversation_id}")
        return {'error': 'Conversation name not found'}, 404

    try:
        # Print the conversation ID for which messages are being retrieved
        print(f"Retrieving messages for conversation ID: {conversation_id}")

        # Retrieve the messages from Firestore
        messages_ref = firestore_db.collection('conversations').document(conversation_id).collection('messages')
        messages = messages_ref.stream()

        # Initialize an empty list to store the messages
        message_list = []
        
        # Iterate over the messages and create a dictionary for each message
        for message in messages:
            message_dict = {
                'text': message.to_dict().get('text'),
                'timestamp': int(message.to_dict().get('timestamp').timestamp() * 1000)  # Convert to milliseconds
            }
            message_list.append(message_dict)

        # Check if no messages are found for the conversation
        if not message_list:
            print(f"Error: No messages found for conversation ID {conversation_id}")
            return {'error': 'No messages found'}, 404

        # Return the list of messages
        return jsonify(message_list)

    except Exception as e:
        # Print any error that occurs
        print(f"Error: {str(e)}")
        return {'error': 'Internal Server Error'}, 500
    
@app.route('/api/technician/conversations/send/<string:conversation_id>/messages', methods=['POST'])
def send_message(conversation_id):
    try:
        # Retrieve the conversation IDs from the session
        conversation_ids = session.get('conversation_ids')
        print("Conversation IDs in session:", conversation_ids)
        
        # Check if conversation IDs are not found in the session
        if conversation_ids is None:
            print("Error: Conversation IDs not found in session")
            return {'error': 'Conversation IDs not found in session'}, 401

        # Retrieve the conversation name from the conversation IDs dictionary using the conversation ID
        conversation_name = next((name for name, cid in conversation_ids.items() if cid == conversation_id), None)
        
        # Check if conversation name is not found for the conversation ID
        if conversation_name is None:
            print(f"Error: Conversation name not found for conversation ID {conversation_id}")
            return {'error': 'Conversation name not found'}, 404

        # Get the message text from the request body
        message_text = request.json.get('message_text')
        if not message_text:
            print("Error: Message text is required")
            return {'error': 'Message text is required'}, 400

        # Create a new message document in Firestore
        messages_ref = firestore_db.collection('conversations').document(conversation_id).collection('messages')
        message_ref = messages_ref.document()
        message_ref.set({
            'text': message_text,
            'timestamp': datetime.now(),
            'sender_id': session.get('technician_id')
        })

        print(f"Message sent successfully to conversation ID {conversation_id}")
        return {'message': 'Message sent successfully'}, 201

    except Exception as e:
        print(f"Error: {str(e)}")
        
        # Broadcast the message to all connected clients in the same conversation
        socketio.emit('message', {'text': message_text, 'conversation_id': conversation_id}, room=conversation_id)

        
        return {'error': 'Internal Server Error'}, 500
    
    
@app.route('/api/technician/conversations/<string:conversation_id>/messages/<string:message_id>/reply', methods=['POST'])
def reply_to_message(conversation_id, message_id):
    try:
        # Retrieve the conversation IDs from the session
        conversation_ids = session.get('conversation_ids')
        print("Conversation IDs in session:", conversation_ids)
        
        # Check if conversation IDs are not found in the session
        if conversation_ids is None:
            print("Error: Conversation IDs not found in session")
            return {'error': 'Conversation IDs not found in session'}, 401

        # Retrieve the conversation name from the conversation IDs dictionary using the conversation ID
        conversation_name = next((name for name, cid in conversation_ids.items() if cid == conversation_id), None)
        
        # Check if conversation name is not found for the conversation ID
        if conversation_name is None:
            print(f"Error: Conversation name not found for conversation ID {conversation_id}")
            return {'error': 'Conversation name not found'}, 404

        # Get the reply message text from the request body
        reply_message_text = request.json.get('reply_message_text')
        if not reply_message_text:
            print("Error: Reply message text is required")
            return {'error': 'Reply message text is required'}, 400

        # Create a new reply message document in Firestore
        messages_ref = firestore_db.collection('conversations').document(conversation_id).collection('messages')
        reply_message_ref = messages_ref.document()
        reply_message_ref.set({
        'sender_id': request.json['sender_id'],
        'recipient_id': request.json['recipient_id'],
        'conversation_id': conversation_id,
        'message': request.json['message'],
        'created_at': datetime.now()
        })

        reply_message_data = {
                'message_id': reply_message_ref.id,
                'sender_id': request.json['sender_id'],
                'recipient_id': request.json['recipient_id'],
                'conversation_id': conversation_id,
                'message': request.json['message'],
                'created_at': datetime.now()
            }

        # Send the reply to the recipient using Socket.IO
        emit('new_message', reply_message_data, to=request.json['recipient_id'])

        print(f"Reply sent successfully to message ID {message_id} in conversation ID {conversation_id}")
        return {'message': 'Reply sent successfully'}, 201

    except Exception as e:
        print(f"Error: {str(e)}")
        
        # Broadcast the message to all connected clients in the same conversation
        socketio.emit('message', {'text': reply_message_text, 'conversation_id': conversation_id}, room=conversation_id)
        return {'error': 'Internal Server Error'}, 500
if __name__ == '__main__':
        socketio.run(app, debug=True, host='192.168.1.67', port=5000, use_reloader=False)

    #    app.run(debug=True, host='172.20.10.2', port=5000)
    #    socketio.serve_forever()