from flask import Flask, render_template, request, flash, url_for, session,jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import base64
from gridfs import GridFS
from authlib.integrations.flask_client import OAuth
from authlib.common.security import generate_token
from bson import ObjectId  # Import ObjectId from pymongo
#SMTP Part
import smtplib
import threading
from datetime import timedelta
# Gmail SMTP settings
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "adityadhanwai8@gmail.com"
SMTP_PASSWORD = "SMTP Password"
# Email account credentials
email_address = "adityadhanwai8@gmail.com"
password = "SMTP Password"
app = Flask(__name__)
app.secret_key = 'asdfghjk123'
oauth = OAuth(app)
import pyttsx3

# MongoDB Configuration
client = MongoClient('mongodb://localhost:27017/')
db = client['college_reviews']
collection = db['reviews']
users_collection = db['users']
fs = GridFS(db)

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=50)


# Define a decorator function to check authentication
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You must be logged in to access this page.', 'error')
            # Use a JavaScript alert and then redirect
            return f'''
            <script>
                alert('Login is required !!');
                window.location.href = '/';
            </script>
            '''
        return f(*args, **kwargs)
    return decorated_function

def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_username' not in session:
            flash('You must be logged in to access this page.', 'error')
            # Use a JavaScript alert and then redirect
            return f'''
            <script>
                alert('Admin Login is required !!');
                window.location.href = '/';
            </script>
            '''
        return f(*args, **kwargs)
    return decorated_function

def login_or_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in session or 'admin_username' in session:
            return f(*args, **kwargs)
        else:
            flash('Login is required to access this page.', 'error')
            return '''
                <script>
                    alert('Login is required!!');
                    window.location.href = '/';
                </script>
                '''
    return decorated_function

@app.route('/login', methods=['GET'])
def login():
    return render_template('newlogin.html')

@app.route('/chat', methods=['GET'])
# decorator
@login_required
def Chat():
    return render_template('GPT.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email=request.form['email']
        if users_collection.find_one({'username': username}):
            flash('Username already exists. Choose another.', 'error')
            return '''
                <script>
                    alert('Username Already exits!!');
                    window.location.href = '/register'; // Redirect to the admin dashboard or any other admin page
                </script>
                '''
        else:
            subject="Welcome Mail"
            message="Thank You "+username+" for registering with us "
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            users_collection.insert_one({'username': username, 'password': hashed_password,'is_admin':False})
            flash('Registration successful. You can now log in.', 'success')
            send_email(email,subject,message)
            return '''
                <script>
                    alert('Registration successful. You can now log in.');
                    window.location.href = '/login'; // Redirect to the admin dashboard or any other admin page
                </script>
                '''
    return render_template('newsignup.html')

@app.route('/login', methods=['GET', 'POST'])
def login_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        #Query to find 
        user = users_collection.find_one({'username': username})

        if user and check_password_hash(user['password'], password):
            # Set session to be permanent
            session.permanent = True
            # Successful login
            if user.get('is_admin', True):
                session['admin_username'] = username
                response ="Logged in successfully, welcome Admin!"
                threading.Thread(target=speak, args=(response,)).start()
                return '''
                <script>
                    alert('Admin login successful');
                    window.location.href = '/admin'; // Redirect to the admin dashboard or any other admin page
                </script>
                '''
            else:
                session['username'] = username
                response ="Logged in successfully, welcome user!"
                threading.Thread(target=speak, args=(response,)).start()
                return '''
                <script>
                    alert('User login successful');
                    window.location.href = '/user'; // Redirect to the user dashboard or any other user page
                </script>
                '''
        else:
            response ="Invalid username or password.Please,try again!"
            threading.Thread(target=speak, args=(response,)).start()
            return '''
            <script>
                alert('Invalid username or password');
                window.location.href = '/login';
            </script>
            '''

    return render_template('login.html')


@app.route('/', methods=['GET'])
def homepage():
    # Create a list of dictionaries with college name and summary where 'approved' is true
    reviews = list(collection.find({'approved': True}, {'_id': 0,'video_data':0}))

    return render_template('index.html', colleges=reviews)

@app.route('/about', methods=['GET'])
def AboutUS():
    response ="College Insider is developed by Aditya,Shruti,Rohit and Siddhesh inview of helping the students to know about the hidden facts of colleges."
    threading.Thread(target=speak, args=(response,)).start()
    return render_template('about.html')

@app.route('/user', methods=['GET'])
@login_required
def get_colleges():
    # Create a list of dictionaries with college name and summary
    reviews = list(collection.find({'approved': True}, {'_id': 0}))
    return render_template('newhome.html', colleges=reviews)

@app.route('/share', methods=['GET'])
@login_required
def add_review_page():
    return render_template('add_reviews.html')

@app.route('/manage', methods=['GET'])
@admin_login_required
def Mange_Review_Page():
    reviews = list(collection.find({'approved':True}))
    if not reviews:
        # If no reviews were found, return a message
        return f'''
        <script>
            alert('Reviews not found');
            window.location.href = '/admin';
        </script>
        '''
    return render_template('managereviews.html',reviews=reviews)

@app.route('/analysis', methods=['GET'])
@login_required
def Colleges_Comparison():
    return render_template('analysis.html')
# @app.route('/get_colleges', methods=['GET'])
# def get_colleges():
#     reviews = list(collection.find({}, {'_id': 0}))
#     return render_template('index.html', colleges=reviews)
@app.route('/admin_search_colleges', methods=['POST'])
@admin_login_required
def Admin_search_colleges():
    search_query = request.form.get('search_query')
    print("Reached searched")
    print(search_query)
    # Perform a search in database using the "college" field to find colleges
    reviews = list(collection.find({'college': {'$regex': search_query, '$options': 'i'}}))
    if not reviews:
        # If no reviews were found, return a message that reviews not found
        return f'''
    <script>
        alert('Reviews not found');
        window.location.href = '/user';
    </script>
    '''
    response ="These are the reviews for "+search_query
    threading.Thread(target=speak, args=(response,)).start()
    # Process the search results and render them in a template
    return render_template('managereviews.html', reviews=reviews)

@app.route('/search_colleges', methods=['POST'])
@login_or_admin_required
def search_colleges():
    search_query = request.form.get('search_query')
    print("Reached searched")
    print(search_query)
    # Perform a search in your database using the "college" field to find colleges
    # You need to replace this with your actual database query
    reviews = list(collection.find({'college': {'$regex': search_query, '$options': 'i'}}))
    if not reviews:
        # If no reviews were found, return a message
        return f'''
    <script>
        alert('Reviews not found');
        window.location.href = '/user';
    </script>
    '''
    response ="These are the reviews for "+search_query
    threading.Thread(target=speak, args=(response,)).start()
    # Process the search results and render them in a template
    return render_template('reviews.html', reviews=reviews)


@app.route('/get_reviews', methods=['GET'])
@login_required
def get_reviews():
    # Define a query filter to fetch only approved reviews
    query_filter = {'approved': True}

    reviews = list(collection.find(query_filter, {'_id': 0}))
    if not reviews:
        # If no reviews were found, return a message
        return f'''
            <script>
                alert('Reviews not found');
                window.location.href = '/user';
            </script>
            '''
    for review in reviews:
        if 'image_id' in review:
            image_data = fs.get(review['image_id']).read()
            review['image_data'] = base64.b64encode(image_data).decode('utf-8')

    return render_template('reviews.html', reviews=reviews)

@app.route('/report', methods=['GET'])
@login_required
def Comparisons():
    # Define a query filter to fetch only approved reviews
    query_filter = {'approved': True}

    # Exclude the 'video_data' field from the projection
    projection = {'_id': 0, 'video_data': 0}

    reviews = list(collection.find(query_filter, projection))
    return jsonify(reviews)

@app.route('/add_review', methods=['POST'])
@login_required
def add_review():
    college = request.form.get('college')
    reviewer_name = request.form.get('reviewer_name')
    prn = request.form.get('PRN')
    email = request.form.get('email')
    image = request.files['image']
    academics = request.form.get('academics')
    placements = request.form.get('placements')
    campus_life = request.form.get('campus_life')
    infrastructure = request.form.get('infrastructure')
    summary = request.form.get("detailreview")
    facilities = request.form.getlist('facilities[]')
    overall_rating = int(request.form.get('overall_rating'))

    if image:
        image_data = base64.b64encode(image.read()).decode('utf-8')
    # Handle college images
    college_images = []
    captions = []

    for i in range(1, 4):
        image_key = f'image{i}'
        caption_key = f'caption{i}'

        college_image = request.files.get(image_key)
        caption = request.form.get(caption_key)

        if college_image:
            college_image_data = base64.b64encode(college_image.read()).decode('utf-8')
            college_images.append(college_image_data)
            captions.append(caption)
        else:
            college_images.append(None)
            captions.append(None)
    video = request.files.get('video')

    if video:
        # Read the video file and encode it as Base64
        video_data = base64.b64encode(video.read()).decode('utf-8')
    new_review = {
        'college': college,
        'reviewer_name': reviewer_name,
        'prn': prn,
        'email': email,
        'image_data': image_data if image else None,
        'video_data':video_data if video else None,
        'college_images': college_images,
        'captions': captions,
        'academics': academics,
        'placements': placements,
        'campus_life': campus_life,
        'infrastructure': infrastructure,
        'facilities': facilities,
        'overall_rating': overall_rating,
        'summary': summary,
        'approved': False  # Set the "approved" field to False by default
    }

    collection.insert_one(new_review)
    response ="Review added successfully"
    threading.Thread(target=speak, args=(response,)).start()    
    # Use a JavaScript alert and then redirect
    return f'''
    <script>
        alert('Review added successfully and awaiting approval');
        window.location.href = '/user';
    </script>
    '''


def speak(audio):
    # Initialize the text-to-speech engine
    engine = pyttsx3.init()

    # Speak the logout message
    engine.say(audio)
    engine.runAndWait()

    # Stop and close the engine
    engine.stop()

@app.route('/logout', methods=['GET'])
def logout():
    session.pop('username', None)
    flash('Logged out', 'success')
    response ="Logged out successfully"
    threading.Thread(target=speak, args=(response,)).start()
    # Use a JavaScript alert and then redirect
    return f'''
    <script>
        alert('Logged out successfully');
        window.location.href = '/';
    </script>
    '''
@app.route('/adminlogout', methods=['GET'])
def Adminlogout():
    session.pop('admin_username', None)
    flash('Logged out', 'success')
    response ="Logged out successfully"
    threading.Thread(target=speak, args=(response,)).start()
    # Use a JavaScript alert and then redirect
    return f'''
    <script>
        alert('Logged out successfully');
        window.location.href = '/';
    </script>
    '''

@app.route('/google/')
def google():

    GOOGLE_CLIENT_ID = '202782780730-au1pe7280jn50nbhpsg0lmedlmk9djpu.apps.googleusercontent.com'
    GOOGLE_CLIENT_SECRET = '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'

    CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url=CONF_URL,
        client_kwargs={
            'scope': 'openid email profile'
        }
    )

     # Redirect to google_auth function
    redirect_uri = url_for('google_auth', _external=True)
    print(redirect_uri)
    session['nonce'] = generate_token()
    return oauth.google.authorize_redirect(redirect_uri, nonce=session['nonce'])

@app.route('/google/auth/')
def google_auth():
    token = oauth.google.authorize_access_token()
    user = oauth.google.parse_id_token(token, nonce=session['nonce'])
    session['user'] = user
    session['username'] = user
    print(" Google User ", user)
    return f'''
    <script>
        alert('Sign in Successfull from Google!!');
        window.location.href = '/user';
    </script>
    '''


#Admin part begins
@app.route('/admin', methods=['GET'])
@admin_login_required
def admin_reviews():
    return render_template('adminhome.html')

@app.route('/approve', methods=['GET'])
@admin_login_required
def approve_reviews():
    # Retrieve all reviews, including those pending approval
    reviews = list(collection.find({'approved': False}))
    if not reviews:
        # If no reviews were found, return a message
        return f'''
        <script>
            alert('No pending Reviews to approve !');
            window.location.href = '/admin';
        </script>
        '''
    return render_template('admin_reviews.html', reviews=reviews)

@app.route('/declined', methods=['GET'])
@admin_login_required
def Declined_reviews():
    # Retrieve all reviews, including those pending approval
    reviews = list(collection.find({'declined': True}))
    if not reviews:
        # If no reviews were found, return a message
        return f'''
        <script>
            alert('No reviews are declined');
            window.location.href = '/admin';
        </script>
        '''
    return render_template('newdeclined.html', reviews=reviews)
@app.route('/handle_review', methods=['POST'])
@admin_login_required
def handle_review():
    review_id = request.form.get('review_id')
    recipient_email = request.form.get('recipient_email')
    action = request.form.get('action')

    # Check if review_id is a valid ObjectId
    try:
        review_id = ObjectId(review_id)
    except Exception as e:
        return jsonify(error="Invalid review_id"), 400

    if action == 'approve':
        # Update the review in the database to mark it as approved
        collection.update_one({'_id': review_id}, {'$set': {'approved': True,'declined': False}})

        # Compose a default subject and message
        subject = "Review Approved"
        message = "Your review has been approved. Thank you for your contribution."
    elif action == 'decline':
        # Update the review in the database to mark it as declined
        collection.update_one({'_id': review_id}, {'$set': {'declined': True}})

        # Compose a default subject and message
        subject = "Review Declined"
        message = "Your review has been declined. Sorry for the result, but we encourage you to write again."
    else:
        return jsonify(error="Invalid action"), 400

    # Send an email notification to the recipient
    result = send_email(recipient_email, subject, message)

    if "successfully" in result:
        return f'''
            <script>
                alert('Review {action.capitalize()} successfully');
                window.location.href = '/admin';
            </script>
        '''
    else:
        return f'''
            <script>
                alert('Review {action.capitalize()} successfully but failed to send email notification');
                window.location.href = '/admin';
            </script>
        '''

def send_email(recipient, subject, message):
    try:
        print(recipient)
        # Connect to the SMTP server
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)

        # Compose the email
        email_message = f"Subject: {subject}\n\n{message}"
        server.sendmail(SMTP_USERNAME, recipient, email_message)

        server.quit()

        # Return a success message when the email is successfully sent
        return "Email sent successfully."
    except smtplib.SMTPException as e:
        error_message = f'Email could not be sent. SMTP Error: {str(e)}'
        print(error_message)
        return error_message
    except Exception as e:
        error_message = f'Email could not be sent. Error: {str(e)}'
        print(error_message)
        return error_message
# from web import text
# global message
# message=text
import openai,time,re
# from openai import error


def chat_with_chatgpt(message, model_name='text-davinci-003'):
    # Set up OpenAI API credentials
    openai.api_key = 'YourAPIKEY'

    # Define the parameters for the GPT-3 API call
    params = {
        'model': model_name,  # Replace with the name of the latest model
        'prompt': message,
        'max_tokens': 200,
        'temperature': 0.4
    }

    # Make the API call
    response = openai.Completion.create(**params)

    # Extract the generated reply from the API response
    reply = response.choices[0].text.strip()

    return reply



@app.route('/chatgpt', methods=['POST'])
def chatgpt():
    try:
        # Get the user's message from the request
        user_message = request.json.get('message', '')
        print(user_message)
        # Your existing logic for processing the message and getting a response
        response = chat_with_chatgpt(user_message)
        print("The response is: "+response)
        # Respond with the ChatGPT response
        return jsonify({'response': response})
    except Exception as e:
        # Handle exceptions, log errors, and return an error response
        print(f"Error in /chatgpt endpoint: {str(e)}")
        return jsonify({'response': 'Error processing the request'}), 500

@app.route('/colleges', methods=['GET'])
@login_required
def get_colleges_gallery():
    # Retrieve unique college names from the database where 'approved' is true
    unique_colleges = collection.distinct('college', {'approved': True})

    return render_template('colleges.html', colleges=unique_colleges)


@app.route('/virtual_tour', methods=['GET'])
@login_required
def get_colleges_video_gallery():
    # Retrieve unique college names from the database where 'approved' is true
    unique_colleges = collection.distinct('college', {'approved': True})

    return render_template('clgvideogallery.html', colleges=unique_colleges)
# Add a new route for the gallery page

@app.route('/gallery/<college>', methods=['GET'])
@login_required
def show_gallery(college):
    # Retrieve reviews for the selected college from the database
    college_reviews = collection.find({'college': college, 'approved': True}, {'_id': 0})

    # Pass the reviews data to the frontend
    return render_template('gallery.html', college=college, reviews=college_reviews)

@app.route('/videos/<college>', methods=['GET'])
@login_required
def show_videos(college):
    # Retrieve reviews for the selected college from the database
    college_reviews = collection.find({'college': college, 'approved': True}, {'_id': 0})

    # Pass the reviews data to the frontend
    return render_template('videos.html', college=college, reviews=college_reviews)
@app.route('/college_images', methods=['GET'])
def show_college_images():
    # Get the 'id' parameter from the request URL
    review_id = request.args.get('id')
    print(review_id)
    # Retrieve the review from the database based on the provided ID
    review = collection.find_one({'_id': ObjectId(review_id)})

    if review:
        # Pass the review data to the frontend
        return render_template('admingallery.html', review=review)
    else:
        # Handle the case where the review with the specified ID is not found
        return f'''
            <script>
                alert('Not found');
                window.location.href = '/approve';
            </script>
        '''

@app.route('/video_approve', methods=['GET'])
def Video_Approval():
    # Get the 'id' parameter from the request URL
    review_id = request.args.get('id')
    print(review_id)
    # Retrieve the review from the database based on the provided ID
    review = collection.find_one({'_id': ObjectId(review_id)})

    if review:
        # Pass the review data to the frontend
        return render_template('videoapprove.html', review=review)
    else:
        # Handle the case where the review with the specified ID is not found
        return f'''
            <script>
                alert('Not found');
                window.location.href = '/approve';
            </script>
        '''
@app.route('/delete_review', methods=['POST'])
def delete_review():
    review_id = request.form.get('review_id')
    print("Reiew ID:"+review_id)
    try:
        print(review_id)
        result =collection.delete_one({'_id': ObjectId(review_id)})
        if result.deleted_count == 1:
            return f'''
            <script>
                alert('Review Deleted Successfully!');
                window.location.href = '/admin';
            </script>
        '''
        else:
            return f'''
            <script>
                alert('Review Not found');
                window.location.href = '/manage';
            </script>
        '''
    except Exception as e:
        print(str(e))
        return ('Internal Server Error', 500)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
