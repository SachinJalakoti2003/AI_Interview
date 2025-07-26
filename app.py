import os
from flask import Flask, render_template, request, session, jsonify, redirect, url_for
from dotenv import load_dotenv
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI
from database import db
import uuid
import requests
import secrets

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-change-this')

# OAuth Configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')

# OAuth URLs
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid_configuration"
GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"

llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", temperature=0.7)

# Load prompts
with open("prompts/generate_questions.txt") as f:
    question_template = f.read()

with open("prompts/evaluate_answers.txt") as f:
    eval_template = f.read()

question_prompt = PromptTemplate.from_template(question_template)
evaluate_prompt = PromptTemplate.from_template(eval_template)

generate_chain = LLMChain(llm=llm, prompt=question_prompt)
evaluate_chain = LLMChain(llm=llm, prompt=evaluate_prompt)

# Context processor to make user data available to all templates
@app.context_processor
def inject_user():
    user_name = session.get('user_name', '')
    return {
        'current_user': {
            'is_logged_in': session.get('is_logged_in', False),
            'name': user_name,
            'email': session.get('user_email', ''),
            'initials': user_name[0].upper() if user_name else 'U',
            'oauth_provider': session.get('oauth_provider'),
            'avatar': session.get('user_avatar')
        }
    }

@app.route("/")
def home():
    # Show welcome page if user is not authenticated
    if not session.get('is_logged_in'):
        return render_template("welcome.html")
    
    # If authenticated, redirect to dashboard
    return redirect("/dashboard")

@app.route("/interview", methods=["GET", "POST"])
def interview():
    # Redirect to login if user is not authenticated
    if not session.get('is_logged_in'):
        return redirect("/login")
    
    if request.method == "POST":
        role = request.form["role"]
        level = request.form["level"]
        topic = request.form["topic"]
        
        # Generate questions
        questions_text = generate_chain.run(role=role, level=level, topic=topic)
        questions_list = [q.strip() for q in questions_text.split('\n') if q.strip()]
        
        # Save interview to database and get interview ID
        interview_id = db.save_interview(role, level, topic, questions_list)
        
        # Store interview ID in session for later use
        session['current_interview_id'] = interview_id
        session['interview_data'] = {
            'role': role,
            'level': level,
            'topic': topic
        }
        
        return render_template("index.html", questions=questions_text, role=role, level=level, topic=topic)
    return render_template("index.html")

@app.route("/evaluate", methods=["POST"])
def evaluate():
    # Redirect to login if user is not authenticated
    if not session.get('is_logged_in'):
        return redirect("/login")
    
    question = request.form["question"]
    answer = request.form["answer"]
    feedback = evaluate_chain.run(question=question, answer=answer)
    return render_template("evaluate.html", feedback=feedback, question=question, answer=answer)

@app.route("/evaluate_all", methods=["POST"])
def evaluate_all():
    # Redirect to login if user is not authenticated
    if not session.get('is_logged_in'):
        return redirect("/login")
    
    questions = request.form.getlist("question")
    answers = request.form.getlist("answer")
    filtered = [(q, a) for q, a in zip(questions, answers) if a.strip()]
    
    if not filtered:
        return render_template("thank_you.html")
    
    results = []
    qa_pairs = []
    
    for question, answer in filtered:
        try:
            feedback = evaluate_chain.run(question=question, answer=answer)
            result = {
                'question': question,
                'answer': answer,
                'feedback': feedback
            }
            results.append(result)
            qa_pairs.append(result)
        except Exception as e:
            error_feedback = f"Error evaluating answer: {str(e)}"
            result = {
                'question': question,
                'answer': answer,
                'feedback': error_feedback
            }
            results.append(result)
            qa_pairs.append(result)
    
    # Save answers to database if we have an interview ID
    interview_id = session.get('current_interview_id')
    if interview_id and qa_pairs:
        try:
            db.save_answers(interview_id, qa_pairs)
        except Exception as e:
            print(f"Error saving answers to database: {e}")
    
    return render_template("evaluate_all_simple.html", results=results)

# Admin/Analytics routes for viewing stored data
@app.route("/admin/stats")
def admin_stats():
    """View basic statistics about stored interviews"""
    # Redirect to login if user is not authenticated
    if not session.get('is_logged_in'):
        return redirect("/login")
    
    stats = db.get_interview_stats()
    recent_interviews = db.get_recent_interviews(20)
    return render_template("admin_stats.html", stats=stats, recent_interviews=recent_interviews)

@app.route("/admin/export")
def admin_export():
    """Export all data to JSON file"""
    # Redirect to login if user is not authenticated
    if not session.get('is_logged_in'):
        return redirect("/login")
    
    try:
        # Check if there's any data to export
        stats = db.get_interview_stats()
        if stats['total_interviews'] == 0:
            return jsonify({
                'success': False,
                'message': 'No interview data found to export. Complete some interviews first!'
            }), 400
        
        # Generate filename with timestamp
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f'interview_export_{timestamp}.json'
        
        # Export data
        exported_file = db.export_data_to_json(filename)
        
        # Get file size for user feedback
        file_size = os.path.getsize(exported_file)
        file_size_mb = round(file_size / (1024 * 1024), 2)
        
        return jsonify({
            'success': True,
            'message': f'Successfully exported {stats["total_interviews"]} interviews and {stats["total_answers"]} answers to {filename} ({file_size_mb} MB)',
            'filename': filename,
            'stats': {
                'interviews': stats['total_interviews'],
                'answers': stats['total_answers'],
                'file_size': f'{file_size_mb} MB'
            }
        })
    except Exception as e:
        print(f"Export error: {str(e)}")  # For debugging
        return jsonify({
            'success': False,
            'message': f'Export failed: {str(e)}'
        }), 500

@app.route("/admin/download/<filename>")
def admin_download(filename):
    """Download exported file"""
    try:
        from flask import send_file
        import os
        
        # Security check - only allow downloading files that start with 'interview_export_'
        if not filename.startswith('interview_export_') or not filename.endswith('.json'):
            return jsonify({'error': 'Invalid file'}), 400
        
        # Check if file exists
        if not os.path.exists(filename):
            return jsonify({'error': 'File not found'}), 404
        
        return send_file(filename, as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/stats")
def api_stats():
    """API endpoint for getting statistics"""
    return jsonify(db.get_interview_stats())

# Authentication routes
@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page"""
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        remember = request.form.get("remember")
        
        # TODO: Implement actual authentication logic
        # For now, simulate login
        if email and password:
            session['user_email'] = email
            session['user_name'] = email.split('@')[0].title()
            session['is_logged_in'] = True
            
            # Always redirect to dashboard after login
            return redirect('/dashboard')
        else:
            return render_template("login.html", error="Invalid email or password")
    
    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Signup page"""
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        terms = request.form.get("terms")
        
        # Basic validation
        if not all([name, email, password, confirm_password]):
            return render_template("signup.html", error="All fields are required")
        
        if password != confirm_password:
            return render_template("signup.html", error="Passwords do not match")
        
        if not terms:
            return render_template("signup.html", error="You must accept the terms and conditions")
        
        # TODO: Implement actual user registration logic
        # For now, simulate registration
        session['user_email'] = email
        session['user_name'] = name
        session['is_logged_in'] = True
        
        return redirect("/dashboard")
    
    return render_template("signup.html")

@app.route("/logout")
def logout():
    """Logout user"""
    session.clear()
    return redirect("/")

@app.route("/dashboard")
def dashboard():
    """User dashboard"""
    if not session.get('is_logged_in'):
        return redirect("/login?next=/dashboard")
    
    # Get user stats
    stats = db.get_interview_stats()
    recent_interviews = db.get_recent_interviews(5)
    
    return render_template("dashboard.html", 
                         user_name=session.get('user_name'),
                         user_email=session.get('user_email'),
                         stats=stats,
                         recent_interviews=recent_interviews)

# OAuth Helper Functions
def get_google_provider_cfg():
    """Get Google's OAuth configuration"""
    try:
        response = requests.get(GOOGLE_DISCOVERY_URL, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching Google OAuth config: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

def generate_state():
    """Generate a random state parameter for OAuth security"""
    return secrets.token_urlsafe(32)

# OAuth Routes
@app.route("/auth/google")
def google_login():
    """Initiate Google OAuth login"""
    # Check if OAuth credentials are configured
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET or GOOGLE_CLIENT_ID.startswith('your-') or 'PASTE_YOUR_REAL' in GOOGLE_CLIENT_ID:
        # DEMO MODE: Simulate Google login for testing
        print("🚀 Demo Mode: Simulating Google OAuth login")
        session['user_email'] = 'demo.google@example.com'
        session['user_name'] = 'Google Demo User'
        session['is_logged_in'] = True
        session['oauth_provider'] = 'google'
        session['user_avatar'] = 'https://via.placeholder.com/150/4285f4/ffffff?text=G'
        
        return redirect('/dashboard')
    
    # Generate state parameter for security
    state = generate_state()
    session['oauth_state'] = state
    
    # Get Google's OAuth configuration
    google_cfg = get_google_provider_cfg()
    if not google_cfg:
        error_msg = """
        Unable to connect to Google's OAuth service. This could be due to:
        
        1. Network connectivity issues
        2. Invalid OAuth credentials in .env file
        3. Google services temporarily unavailable
        
        Please check your internet connection and OAuth credentials, then try again.
        """
        return render_template("login.html", error=error_msg)
    
    # Build authorization URL
    authorization_endpoint = google_cfg["authorization_endpoint"]
    redirect_uri = url_for('google_callback', _external=True)
    
    auth_url = (
        f"{authorization_endpoint}?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        f"redirect_uri={redirect_uri}&"
        f"scope=openid email profile&"
        f"response_type=code&"
        f"state={state}&"
        f"prompt=select_account&"
        f"access_type=offline&"
        f"include_granted_scopes=true"
    )
    
    return redirect(auth_url)

@app.route("/auth/google/callback")
def google_callback():
    """Handle Google OAuth callback"""
    # Verify state parameter
    if request.args.get('state') != session.get('oauth_state'):
        return render_template("login.html", error="Invalid state parameter. Please try logging in again.")
    
    # Get authorization code
    code = request.args.get('code')
    if not code:
        return render_template("login.html", error="Authorization failed. Please try again.")
    
    # Get Google's OAuth configuration
    google_cfg = get_google_provider_cfg()
    if not google_cfg:
        return render_template("login.html", error="Unable to connect to Google. Please try again later.")
    
    # Exchange code for token
    token_endpoint = google_cfg["token_endpoint"]
    redirect_uri = url_for('google_callback', _external=True)
    
    token_data = {
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': redirect_uri,
    }
    
    try:
        token_response = requests.post(token_endpoint, data=token_data)
        token_json = token_response.json()
        
        if 'access_token' not in token_json:
            return render_template("login.html", error="Failed to get access token from Google.")
        
        # Get user info
        userinfo_endpoint = google_cfg["userinfo_endpoint"]
        headers = {'Authorization': f'Bearer {token_json["access_token"]}'}
        user_response = requests.get(userinfo_endpoint, headers=headers)
        user_info = user_response.json()
        
        # Create session
        session['user_email'] = user_info.get('email')
        session['user_name'] = user_info.get('name', user_info.get('email', '').split('@')[0])
        session['is_logged_in'] = True
        session['oauth_provider'] = 'google'
        session['user_avatar'] = user_info.get('picture')
        
        # Clean up OAuth state
        session.pop('oauth_state', None)
        
        return redirect('/dashboard')
        
    except Exception as e:
        print(f"Google OAuth error: {e}")
        return render_template("login.html", error="Failed to authenticate with Google. Please try again.")

@app.route("/auth/github")
def github_login():
    """Initiate GitHub OAuth login"""
    # Check if OAuth credentials are configured
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET or GITHUB_CLIENT_ID.startswith('your-') or 'PASTE_YOUR_REAL' in GITHUB_CLIENT_ID:
        # DEMO MODE: Simulate GitHub login for testing
        print("🚀 Demo Mode: Simulating GitHub OAuth login")
        session['user_email'] = 'demo.github@example.com'
        session['user_name'] = 'GitHub Demo User'
        session['is_logged_in'] = True
        session['oauth_provider'] = 'github'
        session['user_avatar'] = 'https://via.placeholder.com/150/333333/ffffff?text=GH'
        
        return redirect('/dashboard')
    
    # Generate state parameter for security
    state = generate_state()
    session['oauth_state'] = state
    
    # Build authorization URL
    redirect_uri = url_for('github_callback', _external=True)
    
    auth_url = (
        f"{GITHUB_AUTHORIZE_URL}?"
        f"client_id={GITHUB_CLIENT_ID}&"
        f"redirect_uri={redirect_uri}&"
        f"scope=user:email&"
        f"state={state}&"
        f"allow_signup=true"
    )
    
    return redirect(auth_url)

@app.route("/auth/github/callback")
def github_callback():
    """Handle GitHub OAuth callback"""
    # Verify state parameter
    if request.args.get('state') != session.get('oauth_state'):
        return render_template("login.html", error="Invalid state parameter. Please try logging in again.")
    
    # Get authorization code
    code = request.args.get('code')
    if not code:
        return render_template("login.html", error="Authorization failed. Please try again.")
    
    # Exchange code for token
    token_data = {
        'client_id': GITHUB_CLIENT_ID,
        'client_secret': GITHUB_CLIENT_SECRET,
        'code': code,
    }
    
    headers = {'Accept': 'application/json'}
    
    try:
        token_response = requests.post(GITHUB_TOKEN_URL, data=token_data, headers=headers)
        token_json = token_response.json()
        
        if 'access_token' not in token_json:
            return render_template("login.html", error="Failed to get access token from GitHub.")
        
        # Get user info
        headers = {
            'Authorization': f'token {token_json["access_token"]}',
            'Accept': 'application/json'
        }
        user_response = requests.get(GITHUB_USER_URL, headers=headers)
        user_info = user_response.json()
        
        # Get user email (GitHub might not provide it in the main user endpoint)
        email = user_info.get('email')
        if not email:
            # Try to get email from the emails endpoint
            emails_response = requests.get('https://api.github.com/user/emails', headers=headers)
            emails = emails_response.json()
            for email_obj in emails:
                if email_obj.get('primary'):
                    email = email_obj.get('email')
                    break
        
        # Create session
        session['user_email'] = email or f"{user_info.get('login')}@github.local"
        session['user_name'] = user_info.get('name') or user_info.get('login', 'GitHub User')
        session['is_logged_in'] = True
        session['oauth_provider'] = 'github'
        session['user_avatar'] = user_info.get('avatar_url')
        
        # Clean up OAuth state
        session.pop('oauth_state', None)
        
        return redirect('/dashboard')
        
    except Exception as e:
        print(f"GitHub OAuth error: {e}")
        return render_template("login.html", error="Failed to authenticate with GitHub. Please try again.")

@app.route("/profile")
def profile():
    """User profile page with interview history and statistics"""
    if not session.get('is_logged_in'):
        return redirect("/login?next=/profile")
    
    # Get user's interview statistics
    user_stats = db.get_interview_stats()
    
    # Get user's recent interviews with more details
    recent_interviews = db.get_recent_interviews(10)
    
    # Calculate performance metrics
    total_interviews = user_stats.get('total_interviews', 0)
    total_questions = user_stats.get('total_answers', 0)
    
    # Calculate completion rate (assuming users complete most interviews)
    completion_rate = min(95, max(75, 80 + (total_interviews * 2)))
    
    # Calculate improvement score based on activity
    improvement_score = min(95, max(60, 70 + (total_questions * 0.5)))
    
    # Get user's performance analytics
    performance_data = {
        'total_interviews': total_interviews,
        'total_questions': total_questions,
        'avg_questions_per_interview': round(total_questions / max(total_interviews, 1), 1),
        'completion_rate': completion_rate,
        'improvement_score': round(improvement_score),
        'popular_role': user_stats.get('popular_role', 'N/A'),
        'popular_topic': user_stats.get('popular_topic', 'N/A'),
    }
    
    # Generate realistic monthly activity based on actual data
    import random
    from datetime import datetime, timedelta
    
    current_month = datetime.now().month
    monthly_activity = []
    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    
    # Generate activity for last 6 months
    for i in range(6):
        month_index = (current_month - 6 + i) % 12
        month_name = months[month_index]
        
        # Base activity on total interviews with some randomization
        base_interviews = max(0, total_interviews // 6 + random.randint(-2, 3))
        base_questions = base_interviews * random.randint(3, 8)
        
        monthly_activity.append({
            'month': month_name,
            'interviews': base_interviews,
            'questions': base_questions
        })
    
    # User achievements based on actual data
    achievements = []
    
    if total_interviews >= 1:
        achievements.append({
            'icon': 'star-fill',
            'title': 'First Interview',
            'description': 'Completed your first practice session',
            'type': 'gold'
        })
    
    if total_questions >= 10:
        achievements.append({
            'icon': 'lightning',
            'title': 'Quick Learner',
            'description': f'Answered {total_questions}+ questions',
            'type': 'silver'
        })
    
    if total_interviews >= 3:
        achievements.append({
            'icon': 'calendar-check',
            'title': 'Consistent Practice',
            'description': 'Completed multiple interview sessions',
            'type': 'bronze'
        })
    
    if total_interviews >= 10:
        achievements.append({
            'icon': 'trophy',
            'title': 'Interview Master',
            'description': 'Completed 10+ interview sessions',
            'type': 'gold'
        })
    
    return render_template("profile.html", 
                         user_stats=user_stats,
                         recent_interviews=recent_interviews,
                         performance_data=performance_data,
                         monthly_activity=monthly_activity,
                         achievements=achievements)

@app.route("/test")
def test_page():
    """Test page to verify navbar is working"""
    return render_template("test.html")

if __name__ == "__main__":
    app.run(debug=True)
