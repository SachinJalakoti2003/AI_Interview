import os
from flask import Flask, render_template, request, session, jsonify, redirect
from dotenv import load_dotenv
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI
from database import db
import uuid

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-change-this')

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
    return {
        'current_user': {
            'is_logged_in': session.get('is_logged_in', False),
            'name': session.get('user_name', ''),
            'email': session.get('user_email', ''),
            'initials': session.get('user_name', 'U')[0].upper() if session.get('user_name') else 'U'
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

@app.route("/test")
def test_page():
    """Test page to verify navbar is working"""
    return render_template("test.html")

if __name__ == "__main__":
    app.run(debug=True)
