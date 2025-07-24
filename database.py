import sqlite3
import json
from datetime import datetime
import os

class InterviewDatabase:
    def __init__(self, db_path='interview_data.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create interviews table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS interviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                role TEXT NOT NULL,
                level TEXT NOT NULL,
                topic TEXT NOT NULL,
                questions TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create answers table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS answers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                interview_id INTEGER,
                question TEXT NOT NULL,
                answer TEXT NOT NULL,
                feedback TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (interview_id) REFERENCES interviews (id)
            )
        ''')
        
        # Create user_sessions table (optional - for tracking users)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE,
                user_ip TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_interview(self, role, level, topic, questions):
        """Save interview details and return interview ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Convert questions list to JSON string
        questions_json = json.dumps(questions) if isinstance(questions, list) else questions
        
        cursor.execute('''
            INSERT INTO interviews (role, level, topic, questions)
            VALUES (?, ?, ?, ?)
        ''', (role, level, topic, questions_json))
        
        interview_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return interview_id
    
    def save_answers(self, interview_id, qa_pairs):
        """Save question-answer pairs with feedback"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for qa_pair in qa_pairs:
            cursor.execute('''
                INSERT INTO answers (interview_id, question, answer, feedback)
                VALUES (?, ?, ?, ?)
            ''', (interview_id, qa_pair['question'], qa_pair['answer'], qa_pair.get('feedback', '')))
        
        conn.commit()
        conn.close()
    
    def get_interview_stats(self):
        """Get basic statistics about interviews"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total interviews
        cursor.execute('SELECT COUNT(*) FROM interviews')
        total_interviews = cursor.fetchone()[0]
        
        # Total answers
        cursor.execute('SELECT COUNT(*) FROM answers')
        total_answers = cursor.fetchone()[0]
        
        # Most popular role
        cursor.execute('''
            SELECT role, COUNT(*) as count 
            FROM interviews 
            GROUP BY role 
            ORDER BY count DESC 
            LIMIT 1
        ''')
        popular_role = cursor.fetchone()
        
        # Most popular topic
        cursor.execute('''
            SELECT topic, COUNT(*) as count 
            FROM interviews 
            GROUP BY topic 
            ORDER BY count DESC 
            LIMIT 1
        ''')
        popular_topic = cursor.fetchone()
        
        conn.close()
        
        return {
            'total_interviews': total_interviews,
            'total_answers': total_answers,
            'popular_role': popular_role[0] if popular_role else 'N/A',
            'popular_topic': popular_topic[0] if popular_topic else 'N/A'
        }
    
    def get_recent_interviews(self, limit=10):
        """Get recent interviews with their answers"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT i.id, i.role, i.level, i.topic, i.created_at,
                   COUNT(a.id) as answer_count
            FROM interviews i
            LEFT JOIN answers a ON i.id = a.interview_id
            GROUP BY i.id
            ORDER BY i.created_at DESC
            LIMIT ?
        ''', (limit,))
        
        interviews = cursor.fetchall()
        conn.close()
        
        return [
            {
                'id': row[0],
                'role': row[1],
                'level': row[2],
                'topic': row[3],
                'created_at': row[4],
                'answer_count': row[5]
            }
            for row in interviews
        ]
    
    def export_data_to_json(self, output_file='interview_export.json'):
        """Export all data to JSON file"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get all interviews with their answers
        cursor.execute('''
            SELECT i.id, i.role, i.level, i.topic, i.questions, i.created_at,
                   a.question, a.answer, a.feedback, a.created_at as answer_time
            FROM interviews i
            LEFT JOIN answers a ON i.id = a.interview_id
            ORDER BY i.created_at DESC, a.id
        ''')
        
        rows = cursor.fetchall()
        conn.close()
        
        # Group data by interview
        interviews = {}
        for row in rows:
            interview_id = row[0]
            if interview_id not in interviews:
                interviews[interview_id] = {
                    'id': row[0],
                    'role': row[1],
                    'level': row[2],
                    'topic': row[3],
                    'questions': json.loads(row[4]) if row[4] else [],
                    'created_at': row[5],
                    'answers': []
                }
            
            if row[6]:  # If there's an answer
                interviews[interview_id]['answers'].append({
                    'question': row[6],
                    'answer': row[7],
                    'feedback': row[8],
                    'answered_at': row[9]
                })
        
        # Export to JSON
        with open(output_file, 'w') as f:
            json.dump(list(interviews.values()), f, indent=2, default=str)
        
        return output_file

# Initialize database instance
db = InterviewDatabase()