from flask import Blueprint, render_template, request, redirect, url_for, session

# Create a blueprint for the routes
routes = Blueprint('routes', __name__)

@routes.route('/')
def index():
    return render_template('index.html')

@routes.route('/signup', methods=['GET', 'POST'])
def signup():
    # if request.method == 'POST':
    #     # Process signup form data
    #     return redirect(url_for('routes.dashboard'))
    return render_template('signup.html')

@routes.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@routes.route('/chat')
def chat():
    return render_template('chat.html')

@routes.route('/credentials')
def credentials():
    return render_template('credentials.html')

@routes.route('/notifications')
def notifications():
    return render_template('notifications.html')

@routes.route('/calender')
def calender():
    return render_template('calender.html')

@routes.route('/settings')
def settings():
    return render_template('settings.html')

@routes.route('/logout')
def logout():
    # Clear the user information from the session
    session.pop('user', None)
    return redirect('/')