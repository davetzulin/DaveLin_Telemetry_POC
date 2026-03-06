#!/usr/bin/env python3
"""
Email Newsletter Generation System
Main Flask application for ingesting emails, classifying them, and generating newsletters.
"""

import os
import json
import email
import logging
import io
from datetime import datetime, timezone
import snowflake.connector
from snowflake.connector import DictCursor
from email.utils import parsedate_to_datetime
import re
import sqlite3
from pathlib import Path

from flask import Flask, request, render_template, jsonify, redirect, url_for, flash, send_file, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, JSON, Boolean
from werkzeug.utils import secure_filename
import openai
from email_reply_parser import EmailReplyParser
from bs4 import BeautifulSoup
import bleach
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///newsletter_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Initialize database
db = SQLAlchemy(app)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize OpenAI client
openai.api_key = os.environ.get('OPENAI_API_KEY')

# Categories configuration
CATEGORIES = [
    "Experiments",
    "Things I have to do", 
    "Meeting invites",
    "Status updates",
    "Social"
]

# Database Models
class Email(db.Model):
    __tablename__ = 'emails'
    
    id = Column(Integer, primary_key=True)
    original_filename = Column(String(500))
    ingest_time = Column(DateTime, default=datetime.utcnow)
    date = Column(DateTime)
    from_addr = Column(String(500))
    subject = Column(Text)
    body_original = Column(Text)
    body_clean = Column(Text)
    attachments = Column(JSON)
    thread_id = Column(String(200))
    predicted_category = Column(String(100))
    category_confidence = Column(Float)
    candidate_categories = Column(JSON)
    classification_run_id = Column(String(100))
    redaction_flags = Column(JSON)

class Newsletter(db.Model):
    __tablename__ = 'newsletters'
    
    id = Column(Integer, primary_key=True)
    category = Column(String(100))
    created_by = Column(String(100), default='system')
    created_at = Column(DateTime, default=datetime.utcnow)
    model_used = Column(String(100))
    prompt_template_id = Column(String(100))
    generated_markdown = Column(Text)
    generated_html = Column(Text)
    final_markdown = Column(Text)
    final_html = Column(Text)
    approved_by = Column(String(100))
    approved_at = Column(DateTime)
    extra = Column(JSON)
    email_ids = Column(JSON)  # List of email IDs included

class ClassificationRun(db.Model):
    __tablename__ = 'classification_runs'

    id = Column(Integer, primary_key=True)
    run_id = Column(String(100), unique=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    total_emails = Column(Integer)
    model_used = Column(String(100))
    total_cost = Column(Float)
    extra = Column(JSON)


class Chat(db.Model):
    __tablename__ = 'chats'

    id = Column(Integer, primary_key=True)
    name = Column(String(200), default='New Chat')
    created_at = Column(DateTime, default=datetime.utcnow)
    archived = Column(Boolean, default=False)
    messages = db.relationship('Message', backref='chat', lazy=True,
                               cascade='all, delete-orphan',
                               order_by='Message.created_at')


class Message(db.Model):
    __tablename__ = 'messages'

    id = Column(Integer, primary_key=True)
    chat_id = Column(Integer, db.ForeignKey('chats.id'), nullable=False)
    role = Column(String(20))       # 'user' or 'assistant'
    content = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    tool_calls = Column(JSON)       # stores model/token metadata for inspector


# Utility Functions
def clean_html(html_content):
    """Strip HTML tags and return clean text"""
    if not html_content:
        return ""
    
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Remove script and style elements
    for script in soup(["script", "style"]):
        script.decompose()
    
    # Get text and clean up whitespace
    text = soup.get_text()
    lines = (line.strip() for line in text.splitlines())
    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
    text = ' '.join(chunk for chunk in chunks if chunk)
    
    return text

def extract_signatures_and_replies(text):
    """Remove email signatures and quoted replies"""
    if not text:
        return text
    
    # Use email_reply_parser to remove quoted content
    cleaned = EmailReplyParser.parse_reply(text)
    
    # Additional signature patterns
    signature_patterns = [
        r'\n--\s*\n.*',  # Standard -- signature separator
        r'\n_{3,}.*',    # Underline separators
        r'\nSent from my.*',  # Mobile signatures
        r'\nGet Outlook for.*',  # Outlook signatures
        r'\n\n.*\(\d{3}\)\s*\d{3}-\d{4}.*',  # Phone number signatures
    ]
    
    for pattern in signature_patterns:
        cleaned = re.sub(pattern, '', cleaned, flags=re.DOTALL | re.IGNORECASE)
    
    return cleaned.strip()

def redact_pii(text):
    """Redact personally identifiable information"""
    if not text:
        return text, []
    
    redaction_flags = []
    
    # Social Security Numbers
    ssn_pattern = r'\b\d{3}-?\d{2}-?\d{4}\b'
    if re.search(ssn_pattern, text):
        text = re.sub(ssn_pattern, '[REDACTED_SSN]', text)
        redaction_flags.append('ssn')
    
    # Credit Card Numbers (basic pattern)
    cc_pattern = r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
    if re.search(cc_pattern, text):
        text = re.sub(cc_pattern, '[REDACTED_CC]', text)
        redaction_flags.append('credit_card')
    
    # Simple password patterns
    password_pattern = r'(?i)password[:=]\s*\S+'
    if re.search(password_pattern, text):
        text = re.sub(password_pattern, 'password: [REDACTED]', text)
        redaction_flags.append('password')
    
    return text, redaction_flags

def parse_eml_file(file_path):
    """Parse a .eml file and extract structured data"""
    try:
        with open(file_path, 'rb') as f:
            msg = email.message_from_bytes(f.read())
        
        # Extract basic headers
        from_addr = msg.get('From', '')
        subject = msg.get('Subject', '')
        date_str = msg.get('Date', '')
        
        # Parse date
        email_date = None
        if date_str:
            try:
                email_date = parsedate_to_datetime(date_str)
            except Exception as e:
                logger.warning(f"Could not parse date '{date_str}': {e}")
        
        # Extract body content
        body_text = ""
        body_html = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    charset = part.get_content_charset() or 'utf-8'
                    body_text += part.get_payload(decode=True).decode(charset, errors='ignore')
                elif part.get_content_type() == "text/html":
                    charset = part.get_content_charset() or 'utf-8'
                    body_html += part.get_payload(decode=True).decode(charset, errors='ignore')
        else:
            if msg.get_content_type() == "text/plain":
                charset = msg.get_content_charset() or 'utf-8'
                body_text = msg.get_payload(decode=True).decode(charset, errors='ignore')
            elif msg.get_content_type() == "text/html":
                charset = msg.get_content_charset() or 'utf-8'
                body_html = msg.get_payload(decode=True).decode(charset, errors='ignore')
        
        # Prefer text content, fall back to cleaned HTML
        body_original = body_text if body_text else clean_html(body_html)
        
        # Clean the body
        body_clean = extract_signatures_and_replies(body_original)
        body_clean, redaction_flags = redact_pii(body_clean)
        
        # Extract attachments info
        attachments = []
        if msg.is_multipart():
            for part in msg.walk():
                filename = part.get_filename()
                if filename:
                    attachments.append({
                        'filename': filename,
                        'content_type': part.get_content_type(),
                        'size': len(part.get_payload(decode=True) or b'')
                    })
        
        return {
            'from_addr': from_addr,
            'subject': subject,
            'date': email_date,
            'body_original': body_original,
            'body_clean': body_clean,
            'attachments': attachments,
            'redaction_flags': redaction_flags,
            'thread_id': msg.get('Message-ID', '')
        }
    
    except Exception as e:
        logger.error(f"Error parsing email file {file_path}: {e}")
        return None

# Classification Functions
def classify_email_with_openai(email_text, email_subject=""):
    """Classify an email using OpenAI API"""
    try:
        # Prepare the prompt
        prompt = f"""
Classify the following email into one of these categories:
- Experiments (A/B tests, product experiments, data analysis results)
- Things I have to do (Tasks, action items, deadlines, assignments)
- Meeting invites (Calendar invitations, meeting requests, scheduling)
- Status updates (Progress reports, team updates, weekly summaries)
- Social (Team events, celebrations, personal messages, farewell messages)

Email Subject: {email_subject}
Email Content: {email_text[:2000]}  

Respond with ONLY the category name from the list above. Choose the most appropriate category based on the primary purpose of the email.
"""

        client = openai.OpenAI(api_key=openai.api_key)
        
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are an email classifier. Respond only with the exact category name."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=50
        )
        
        predicted_category = response.choices[0].message.content.strip()
        
        # Validate the category is in our list
        if predicted_category not in CATEGORIES:
            # Find the closest match
            for category in CATEGORIES:
                if category.lower() in predicted_category.lower():
                    predicted_category = category
                    break
            else:
                predicted_category = "Social"  # Default fallback
        
        # Calculate confidence (simplified for now)
        confidence = 0.85  # We could enhance this with a second API call
        
        return {
            'category': predicted_category,
            'confidence': confidence,
            'tokens_used': response.usage.total_tokens,
            'cost_estimate': response.usage.total_tokens * 0.00015 / 1000  # Rough estimate
        }
        
    except Exception as e:
        logger.error(f"OpenAI classification error: {e}")
        return None

def classify_emails_batch():
    """Classify all unclassified emails"""
    unclassified = Email.query.filter(Email.predicted_category.is_(None)).all()
    
    if not unclassified:
        return {'success': True, 'count': 0, 'message': 'No emails to classify'}
    
    run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    classification_run = ClassificationRun(
        run_id=run_id,
        total_emails=len(unclassified),
        model_used="gpt-4o-mini"
    )
    db.session.add(classification_run)
    
    total_cost = 0
    classified_count = 0
    
    try:
        for email in unclassified:
            text_to_classify = email.body_clean or email.body_original or ""
            if len(text_to_classify) < 10:  # Skip very short emails
                continue
                
            result = classify_email_with_openai(text_to_classify, email.subject)
            if result:
                email.predicted_category = result['category']
                email.category_confidence = result['confidence']
                email.classification_run_id = run_id
                total_cost += result.get('cost_estimate', 0)
                classified_count += 1
        
        classification_run.completed_at = datetime.utcnow()
        classification_run.total_cost = total_cost
        classification_run.extra = {'classified_count': classified_count}
        
        db.session.commit()
        
        return {
            'success': True, 
            'count': classified_count,
            'cost': total_cost,
            'run_id': run_id
        }
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Batch classification error: {e}")
        return {'success': False, 'error': str(e)}

def generate_newsletter_with_openai(emails, category):
    """Generate newsletter content using OpenAI"""
    try:
        # Prepare email summaries for the prompt
        email_summaries = []
        for i, email in enumerate(emails, 1):
            summary = f"""
{i}. **{email.subject}** (from {email.from_addr})
   Date: {email.date.strftime('%Y-%m-%d') if email.date else 'Unknown'}
   Content: {(email.body_clean or email.body_original or '')[:300]}...
"""
            email_summaries.append(summary)
        
        emails_text = "\n".join(email_summaries)
        
        # Create the newsletter generation prompt
        prompt = f"""
Create a professional newsletter for the "{category}" category. Use a casual, conversational tone suitable for a team newsletter.

Here are the emails to include:
{emails_text}

Please generate a newsletter with:
1. A catchy title related to "{category}"
2. A brief intro paragraph (2-3 sentences)
3. 5-8 curated summaries of the most important emails (1-3 sentences each)
4. A friendly closing line

Format the output as clean Markdown. Make it engaging and easy to read. Focus on the key insights and actionable information from each email.
"""

        client = openai.OpenAI(api_key=openai.api_key)
        
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a skilled newsletter writer. Create engaging, well-structured content in Markdown format."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=1500
        )
        
        markdown_content = response.choices[0].message.content.strip()
        
        # Convert Markdown to basic HTML (simple conversion)
        html_content = markdown_to_html(markdown_content)
        
        return {
            'markdown': markdown_content,
            'html': html_content,
            'tokens_used': response.usage.total_tokens,
            'cost_estimate': response.usage.total_tokens * 0.00015 / 1000
        }
        
    except Exception as e:
        logger.error(f"Newsletter generation error: {e}")
        return None

def markdown_to_html(markdown_text):
    """Simple Markdown to HTML conversion"""
    import re
    
    html = markdown_text
    
    # Headers
    html = re.sub(r'^# (.*)', r'<h1>\1</h1>', html, flags=re.MULTILINE)
    html = re.sub(r'^## (.*)', r'<h2>\1</h2>', html, flags=re.MULTILINE)
    html = re.sub(r'^### (.*)', r'<h3>\1</h3>', html, flags=re.MULTILINE)
    
    # Bold and italic
    html = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', html)
    html = re.sub(r'\*(.*?)\*', r'<em>\1</em>', html)
    
    # Links
    html = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', html)
    
    # Line breaks
    html = html.replace('\n\n', '</p><p>')
    html = f'<p>{html}</p>'
    
    # Lists
    html = re.sub(r'^\d+\.\s(.+)', r'<li>\1</li>', html, flags=re.MULTILINE)
    html = re.sub(r'(<li>.*</li>)', r'<ol>\1</ol>', html, flags=re.DOTALL)
    
    html = re.sub(r'^[-*]\s(.+)', r'<li>\1</li>', html, flags=re.MULTILINE)
    html = re.sub(r'(<li>.*</li>)', r'<ul>\1</ul>', html, flags=re.DOTALL)
    
    return html

# Routes
@app.route('/')
def index():
    """Main dashboard"""
    email_count = Email.query.count()
    newsletter_count = Newsletter.query.count()
    
    # Get category distribution
    category_stats = db.session.query(
        Email.predicted_category, 
        db.func.count(Email.id)
    ).group_by(Email.predicted_category).all()
    
    return render_template('index.html', 
                         email_count=email_count,
                         newsletter_count=newsletter_count,
                         category_stats=category_stats,
                         categories=CATEGORIES)

@app.route('/upload', methods=['GET', 'POST'])
def upload_emails():
    """Upload and ingest email files"""
    if request.method == 'POST':
        if 'email_files' not in request.files:
            flash('No files selected')
            return redirect(request.url)
        
        files = request.files.getlist('email_files')
        processed_count = 0
        errors = []
        
        for file in files:
            if file.filename == '':
                continue
            
            if file and file.filename.endswith('.eml'):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                # Parse the email
                email_data = parse_eml_file(file_path)
                if email_data:
                    try:
                        # Check if email already exists
                        existing = Email.query.filter_by(
                            from_addr=email_data['from_addr'],
                            subject=email_data['subject'],
                            date=email_data['date']
                        ).first()
                        
                        if not existing:
                            email_obj = Email(
                                original_filename=filename,
                                **email_data
                            )
                            db.session.add(email_obj)
                            processed_count += 1
                        else:
                            logger.info(f"Duplicate email skipped: {filename}")
                            
                    except Exception as e:
                        errors.append(f"Error processing {filename}: {e}")
                        logger.error(f"Database error for {filename}: {e}")
                else:
                    errors.append(f"Could not parse {filename}")
                
                # Clean up uploaded file
                os.remove(file_path)
            else:
                errors.append(f"Invalid file type: {file.filename}")
        
        try:
            db.session.commit()
            flash(f'Successfully processed {processed_count} emails')
            if errors:
                for error in errors[:5]:  # Show first 5 errors
                    flash(f'Error: {error}', 'error')
        except Exception as e:
            db.session.rollback()
            flash(f'Database error: {e}', 'error')
        
        return redirect(url_for('upload_emails'))
    
    return render_template('upload.html')

@app.route('/emails')
def list_emails():
    """List all emails with pagination"""
    page = request.args.get('page', 1, type=int)
    category_filter = request.args.get('category', '')
    
    query = Email.query
    if category_filter:
        query = query.filter(Email.predicted_category == category_filter)
    
    emails = query.order_by(Email.date.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    return render_template('emails.html', 
                         emails=emails, 
                         categories=CATEGORIES,
                         current_category=category_filter)

# API Routes
@app.route('/api/stats')
def api_stats():
    """Get system statistics"""
    total_emails = Email.query.count()
    classified_emails = Email.query.filter(Email.predicted_category.isnot(None)).count()
    
    return jsonify({
        'total_emails': total_emails,
        'classified_emails': classified_emails,
        'unclassified_emails': total_emails - classified_emails
    })

@app.route('/api/email/<int:email_id>')
def api_email_detail(email_id):
    """Get detailed email information"""
    email = Email.query.get_or_404(email_id)
    
    return jsonify({
        'id': email.id,
        'from_addr': email.from_addr,
        'subject': email.subject,
        'date': email.date.isoformat() if email.date else None,
        'body_original': email.body_original,
        'body_clean': email.body_clean,
        'predicted_category': email.predicted_category,
        'category_confidence': email.category_confidence,
        'candidate_categories': email.candidate_categories or [],
        'redaction_flags': email.redaction_flags or [],
        'attachments': email.attachments or []
    })

@app.route('/api/email/<int:email_id>/reclassify', methods=['POST'])
def api_reclassify_email(email_id):
    """Reclassify a single email"""
    email = Email.query.get_or_404(email_id)
    
    text_to_classify = email.body_clean or email.body_original or ""
    if len(text_to_classify) < 10:
        return jsonify({'success': False, 'error': 'Email content too short to classify'})
    
    result = classify_email_with_openai(text_to_classify, email.subject)
    if result:
        email.predicted_category = result['category']
        email.category_confidence = result['confidence']
        db.session.commit()
        
        return jsonify({
            'success': True,
            'category': result['category'],
            'confidence': result['confidence']
        })
    else:
        return jsonify({'success': False, 'error': 'Classification failed'})

@app.route('/classify', methods=['POST'])
def classify_all_emails():
    """Classify all unclassified emails"""
    result = classify_emails_batch()
    return jsonify(result)

@app.route('/generate-newsletter', methods=['POST'])
def generate_newsletter():
    """Generate a newsletter for a specific category"""
    data = request.get_json()
    category = data.get('category')
    
    if not category:
        return jsonify({'success': False, 'error': 'Category is required'})
    
    # Get emails for this category from last 7 days
    from datetime import timedelta
    cutoff_date = datetime.now() - timedelta(days=7)
    
    emails = Email.query.filter(
        Email.predicted_category == category,
        Email.category_confidence >= 0.6,
        Email.date >= cutoff_date
    ).order_by(Email.date.desc()).limit(8).all()
    
    if not emails:
        return jsonify({
            'success': False, 
            'error': f'No recent emails found in category "{category}"'
        })
    
    # Generate newsletter using OpenAI
    newsletter_content = generate_newsletter_with_openai(emails, category)
    
    if newsletter_content:
        # Save newsletter to database
        newsletter = Newsletter(
            category=category,
            model_used="gpt-4o-mini",
            generated_markdown=newsletter_content['markdown'],
            generated_html=newsletter_content['html'],
            email_ids=[email.id for email in emails],
            extra={
                'total_emails': len(emails),
                'tokens_used': newsletter_content.get('tokens_used', 0),
                'cost_estimate': newsletter_content.get('cost_estimate', 0)
            }
        )
        db.session.add(newsletter)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'newsletter_id': newsletter.id,
            'email_count': len(emails)
        })
    else:
        return jsonify({'success': False, 'error': 'Newsletter generation failed'})

@app.route('/newsletter/<int:newsletter_id>')
def view_newsletter(newsletter_id):
    """View and edit a newsletter"""
    newsletter = Newsletter.query.get_or_404(newsletter_id)
    
    # Get the source emails
    source_emails = []
    if newsletter.email_ids:
        source_emails = Email.query.filter(Email.id.in_(newsletter.email_ids)).all()
    
    return render_template('newsletter.html', 
                         newsletter=newsletter,
                         source_emails=source_emails)

@app.route('/newsletter/<int:newsletter_id>/update', methods=['POST'])
def update_newsletter(newsletter_id):
    """Update newsletter content"""
    newsletter = Newsletter.query.get_or_404(newsletter_id)
    data = request.get_json()
    
    newsletter.final_markdown = data.get('markdown', newsletter.generated_markdown)
    newsletter.final_html = data.get('html', newsletter.generated_html)
    
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/newsletter/<int:newsletter_id>/approve', methods=['POST'])
def approve_newsletter(newsletter_id):
    """Approve a newsletter"""
    newsletter = Newsletter.query.get_or_404(newsletter_id)
    
    newsletter.approved_by = 'user'  # In a real app, this would be the logged-in user
    newsletter.approved_at = datetime.utcnow()
    
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/newsletter/<int:newsletter_id>/export/<format>')
def export_newsletter(newsletter_id, format):
    """Export newsletter in specified format"""
    newsletter = Newsletter.query.get_or_404(newsletter_id)
    
    content = newsletter.final_markdown or newsletter.generated_markdown
    filename = f"newsletter_{newsletter.category}_{newsletter.created_at.strftime('%Y%m%d')}"
    
    if format == 'markdown':
        response = send_file(
            io.BytesIO(content.encode()),
            mimetype='text/markdown',
            as_attachment=True,
            download_name=f"{filename}.md"
        )
    elif format == 'html':
        html_content = newsletter.final_html or newsletter.generated_html
        response = send_file(
            io.BytesIO(html_content.encode()),
            mimetype='text/html',
            as_attachment=True,
            download_name=f"{filename}.html"
        )
    else:
        return "Invalid format", 400
    
    return response

# ── Snowflake Connection ──────────────────────────────────────────────────────

_sf_conn = None

def get_snowflake_conn():
    global _sf_conn
    try:
        if _sf_conn is not None and not _sf_conn.is_closed():
            return _sf_conn
    except Exception:
        pass
    _sf_conn = snowflake.connector.connect(
        user=os.environ.get('SNOWFLAKE_USER'),
        account=os.environ.get('SNOWFLAKE_ACCOUNT'),
        authenticator='externalbrowser',
        warehouse=os.environ.get('SNOWFLAKE_WAREHOUSE', 'ADHOC'),
        role=os.environ.get('SNOWFLAKE_ROLE'),
        client_store_temporary_credential=True,
    )
    return _sf_conn


# ── Behavior API ─────────────────────────────────────────────────────────────

@app.route('/api/behavior/event-labels')
def api_behavior_event_labels():
    date = request.args.get('date', '2026-03-01')
    try:
        conn = get_snowflake_conn()
        cursor = conn.cursor(DictCursor)
        cursor.execute("""
            SELECT DISTINCT event_label
            FROM EDW.CONSUMER.UNIFIED_CONSUMER_EVENTS
            WHERE event_date = %s
              AND event_label IS NOT NULL
              AND event_label != ''
            LIMIT 10
        """, (date,))
        rows = cursor.fetchall()
        labels = [row.get('EVENT_LABEL') or row.get('event_label', '') for row in rows]
        return jsonify({'labels': labels, 'date': date})
    except Exception as e:
        logger.error(f'Behavior event labels error: {e}')
        return jsonify({'error': str(e)}), 500


@app.route('/api/behavior/event-count')
def api_behavior_event_count():
    event_label = request.args.get('event_label', '').strip()
    date = request.args.get('date', '2026-03-01')
    if not event_label:
        return jsonify({'error': 'event_label is required'}), 400
    try:
        conn = get_snowflake_conn()
        cursor = conn.cursor(DictCursor)
        cursor.execute("""
            SELECT COUNT(DISTINCT user_id) AS user_count
            FROM EDW.CONSUMER.UNIFIED_CONSUMER_EVENTS
            WHERE event_date = %s
              AND event_label = %s
        """, (date, event_label))
        row = cursor.fetchone()
        count = 0
        if row:
            count = row.get('USER_COUNT') or row.get('user_count') or 0
        return jsonify({'event_label': event_label, 'user_count': int(count), 'date': date})
    except Exception as e:
        logger.error(f'Behavior event count error: {e}')
        return jsonify({'error': str(e)}), 500


# ── Triage Helpers ───────────────────────────────────────────────────────────

def build_event_description(event_name, event_label):
    """Build a human-readable one-line description of a user action."""
    name = (event_name or '').strip().lower()
    label = (event_label or '').strip()

    if not name and not label:
        return ''

    # Strip common DoorDash/analytics prefixes
    for prefix in ('consumer_', 'cx_', 'dd_consumer_', 'dd_', 'user_'):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break

    # Verb patterns matched by suffix
    verb_map = [
        (['_viewed', '_view', '_shown', '_impression', '_screen_view', '_page_view'], 'Viewed'),
        (['_clicked', '_click', '_tapped', '_tap', '_pressed', '_selected', '_toggled'], 'Tapped'),
        (['_submitted', '_submit', '_confirmed', '_placed', '_completed', '_finished'], 'Submitted'),
        (['_started', '_initiated', '_launched', '_opened'], 'Started'),
        (['_dismissed', '_closed', '_exited', '_cancelled', '_canceled'], 'Dismissed'),
        (['_loaded', '_fetched', '_received'], 'Loaded'),
        (['_searched', '_search', '_queried'], 'Searched'),
        (['_added', '_add'], 'Added'),
        (['_removed', '_remove', '_deleted'], 'Removed'),
        (['_updated', '_update', '_changed', '_edited'], 'Updated'),
        (['_failed', '_error', '_errored'], 'Encountered error on'),
    ]

    action = None
    subject = name
    for suffixes, verb in verb_map:
        for suffix in suffixes:
            if name.endswith(suffix):
                action = verb
                subject = name[:-len(suffix)].rstrip('_')
                break
        if action:
            break

    # Keyword fallbacks for common patterns
    if not action:
        if 'add_to_cart' in name or 'add_item' in name:
            action, subject = 'Added to cart', ''
        elif 'checkout' in name:
            action, subject = 'Checkout', name.replace('checkout', '').replace('_', ' ').strip()
        elif 'search' in name:
            action, subject = 'Searched', name.replace('search', '').replace('_', ' ').strip()

    subject_str = subject.replace('_', ' ').strip()

    # Drop subjects that are too generic to add meaning
    generic_subjects = {'search', 'button', 'screen', 'page', 'item', 'event', 'tap', 'click'}
    if subject_str.lower() in generic_subjects:
        subject_str = ''

    if action and subject_str:
        desc = f"{action} {subject_str}"
    elif action:
        desc = action
    else:
        desc = name.replace('_', ' ')

    # Append label if it adds context not already present
    if label and label.lower().replace('_', ' ') not in desc.lower():
        if action == 'Searched' and not subject_str:
            desc = f"Searched for {label}"
        else:
            desc = f"{desc} · {label}"

    return desc.strip()


# ── Triage API ────────────────────────────────────────────────────────────────

@app.route('/api/triage/schema')
def api_triage_schema():
    try:
        conn = get_snowflake_conn()
        cursor = conn.cursor(DictCursor)
        cursor.execute("SELECT * FROM EDW.CONSUMER.UNIFIED_CONSUMER_EVENTS LIMIT 1")
        cols = [desc[0] for desc in cursor.description]
        return jsonify({'columns': cols})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/triage/events')
def api_triage_events():
    user_input = request.args.get('user_id', '').strip()
    date = request.args.get('date', datetime.now().strftime('%Y-%m-%d'))
    mode = request.args.get('mode', '')

    if not user_input:
        return jsonify({'error': 'user_id is required'}), 400

    is_email = '@' in user_input

    try:
        conn = get_snowflake_conn()
        cursor = conn.cursor(DictCursor)

        resolved_user_id = user_input

        if is_email:
            # Step 1: resolve email → user_id
            # Try multiple common email field paths; first check the requested
            # date, then fall back to the last 30 days if nothing is found.
            email_sql = """
                SELECT user_id
                FROM EDW.CONSUMER.UNIFIED_CONSUMER_EVENTS
                WHERE {date_filter}
                  AND COALESCE(
                        event_properties:email::STRING,
                        event_properties:consumer_email::STRING,
                        event_properties:user_email::STRING,
                        event_properties:email_address::STRING
                      ) = %s
                  AND user_id IS NOT NULL
                LIMIT 1
            """
            # First try: exact date (fast, partition-pruned)
            cursor.execute(
                email_sql.format(date_filter='event_date = %s'),
                (date, user_input)
            )
            row = cursor.fetchone()

            # Second try: last 30 days (catches users with no events on that date)
            if not row:
                cursor.execute(
                    email_sql.format(date_filter='event_date >= DATEADD(day, -30, %s::DATE)'),
                    (date, user_input)
                )
                row = cursor.fetchone()

            if not row:
                return jsonify({'error': f'No user found for email: {user_input}'}), 404
            resolved_user_id = str(row.get('USER_ID') or row.get('user_id', ''))

        order_timestamp = None

        if mode == 'recent_order':
            # Find the most recent order event in the last 90 days
            cursor.execute("""
                SELECT event_date,
                       TO_VARCHAR(event_timestamp, 'YYYY-MM-DD HH24:MI:SS') AS order_timestamp
                FROM EDW.CONSUMER.UNIFIED_CONSUMER_EVENTS
                WHERE user_id = %s
                  AND event_date >= DATEADD(day, -90, CURRENT_DATE)
                  AND (
                      LOWER(event_name) LIKE '%order_placed%'
                   OR LOWER(event_name) LIKE '%order_submitted%'
                   OR LOWER(event_name) LIKE '%order_confirmed%'
                   OR LOWER(event_name) LIKE '%checkout_completed%'
                   OR LOWER(event_name) LIKE '%checkout_submitted%'
                  )
                ORDER BY event_timestamp DESC
                LIMIT 1
            """, (resolved_user_id,))
            order_row = cursor.fetchone()
            if not order_row:
                return jsonify({'error': 'No recent orders found for this user'}), 404
            date = str(order_row.get('EVENT_DATE') or order_row.get('event_date', ''))
            order_timestamp = order_row.get('ORDER_TIMESTAMP') or order_row.get('order_timestamp', '')

        # Fetch events for the resolved date
        if order_timestamp:
            # recent_order mode: only events up to and including the order
            cursor.execute("""
                SELECT
                    TO_VARCHAR(event_timestamp, 'YYYY-MM-DD HH24:MI:SS') AS event_timestamp,
                    event_name,
                    event_label,
                    COALESCE(
                        event_properties:store_name::STRING,
                        event_properties:business_name::STRING
                    ) AS store_name,
                    COALESCE(
                        event_properties:item_name::STRING,
                        event_properties:menu_item_name::STRING
                    ) AS item_name
                FROM EDW.CONSUMER.UNIFIED_CONSUMER_EVENTS
                WHERE user_id = %s
                  AND event_date = %s
                  AND event_timestamp <= %s
                ORDER BY event_timestamp DESC
                LIMIT 500
            """, (resolved_user_id, date, order_timestamp))
        else:
            cursor.execute("""
                SELECT
                    TO_VARCHAR(event_timestamp, 'YYYY-MM-DD HH24:MI:SS') AS event_timestamp,
                    event_name,
                    event_label,
                    COALESCE(
                        event_properties:store_name::STRING,
                        event_properties:business_name::STRING
                    ) AS store_name,
                    COALESCE(
                        event_properties:item_name::STRING,
                        event_properties:menu_item_name::STRING
                    ) AS item_name
                FROM EDW.CONSUMER.UNIFIED_CONSUMER_EVENTS
                WHERE user_id = %s
                  AND event_date = %s
                ORDER BY event_timestamp DESC
                LIMIT 500
            """, (resolved_user_id, date))
        rows = cursor.fetchall()

        events = []
        for row in rows:
            event_name = row.get('EVENT_NAME') or row.get('event_name', '')
            event_label = row.get('EVENT_LABEL') or row.get('event_label', '')
            store_name = row.get('STORE_NAME') or row.get('store_name') or ''
            item_name = row.get('ITEM_NAME') or row.get('item_name') or ''
            events.append({
                'timestamp': row.get('EVENT_TIMESTAMP') or row.get('event_timestamp', ''),
                'description': build_event_description(event_name, event_label),
                'event_name': event_name,
                'event_label': event_label,
                'store_name': store_name,
                'item_name': item_name,
            })

        return jsonify({
            'events': events,
            'count': len(events),
            'user': resolved_user_id,
            'email': user_input if is_email else None,
            'date': date,
            'mode': mode or None,
            'order_timestamp': order_timestamp,
        })

    except Exception as e:
        logger.error(f'Snowflake triage error: {e}')
        return jsonify({'error': str(e)}), 500


@app.route('/api/triage/summarize', methods=['POST'])
def api_triage_summarize():
    data = request.get_json() or {}
    events = data.get('events', [])
    user = data.get('user', '')
    email_addr = data.get('email', '')
    date = data.get('date', '')

    if not events:
        return jsonify({'error': 'No events provided'}), 400

    user_label = f"{email_addr} (ID: {user})" if email_addr else user

    # Reverse to chronological order for the prompt
    chron_events = list(reversed(events))

    # Build a compact event log for the prompt
    event_lines = []
    for i, e in enumerate(chron_events, 1):
        parts = [f"{i}. [{e.get('timestamp', '')}] {e.get('event_name', '')}"]
        if e.get('event_label'):
            parts[0] += f" | label: {e['event_label']}"
        if e.get('store_name'):
            parts[0] += f" | store: {e['store_name']}"
        if e.get('item_name'):
            parts[0] += f" | item: {e['item_name']}"
        if e.get('description'):
            parts[0] += f" | desc: {e['description']}"
        event_lines.append(parts[0])

    event_log = '\n'.join(event_lines)

    system_prompt = (
        "You are a DoorDash support analyst. Given a chronological list of app events for a consumer, "
        "produce a concise narrative summary in the following exact format:\n\n"
        "Here's the most recent consumer order for [user] on [date]…\n\n"
        "## Most recent order\n"
        "- **Delivery ID**: [from event_label of an order_placed or checkout event, or 'not found']\n"
        "- **Store**: [store name if available]\n"
        "- **Placed**: [timestamp of order placement]\n"
        "- **Delivered**: [timestamp of delivery confirmation, or 'not yet delivered']\n\n"
        "## What they browsed before checkout\n"
        "1. [numbered list of stores/items viewed or searched before the order]\n\n"
        "## Notes\n"
        "- [any notable observations: errors, retries, long gaps, unusual patterns]\n\n"
        "If there is no order in the events, describe the browsing session instead. "
        "Be concise. Use only information present in the events."
    )

    user_prompt = (
        f"User: {user_label}\n"
        f"Date: {date}\n"
        f"Total events: {len(chron_events)}\n\n"
        f"Event log (chronological):\n{event_log}"
    )

    try:
        client = openai.OpenAI(api_key=openai.api_key)
        response = client.chat.completions.create(
            model='gpt-4o-mini',
            messages=[
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': user_prompt},
            ],
            temperature=0.4,
            max_tokens=1200,
        )
        summary = response.choices[0].message.content.strip()
        return jsonify({'summary': summary})
    except Exception as e:
        logger.error(f'Triage summarize error: {e}')
        return jsonify({'error': str(e)}), 500


# ── Workbench / Chat API ─────────────────────────────────────────────────────

@app.route('/workbench')
def workbench():
    """Serve the AI Labs Data Workbench UI"""
    return send_from_directory('telemetry_poc', 'index.html')


@app.route('/api/chats', methods=['GET'])
def api_get_chats():
    show_archived = request.args.get('archived', 'false').lower() == 'true'
    chats = Chat.query.filter(Chat.archived == show_archived) \
                      .order_by(Chat.created_at.desc()).all()
    return jsonify([{
        'id': c.id,
        'name': c.name,
        'created_at': c.created_at.strftime('%b %d, %I:%M %p'),
        'archived': c.archived,
    } for c in chats])


@app.route('/api/chats', methods=['POST'])
def api_create_chat():
    chat = Chat(name='New Chat')
    db.session.add(chat)
    db.session.commit()
    return jsonify({'id': chat.id, 'name': chat.name}), 201


@app.route('/api/chats/<int:chat_id>', methods=['PATCH'])
def api_update_chat(chat_id):
    chat = Chat.query.get_or_404(chat_id)
    data = request.get_json() or {}
    if 'name' in data:
        chat.name = data['name'].strip() or 'Untitled'
    if 'archived' in data:
        chat.archived = bool(data['archived'])
    db.session.commit()
    return jsonify({'success': True, 'name': chat.name})


@app.route('/api/chats/<int:chat_id>', methods=['DELETE'])
def api_delete_chat(chat_id):
    chat = Chat.query.get_or_404(chat_id)
    db.session.delete(chat)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/chats/<int:chat_id>/messages', methods=['GET'])
def api_get_messages(chat_id):
    chat = Chat.query.get_or_404(chat_id)
    return jsonify({
        'chat': {'id': chat.id, 'name': chat.name},
        'messages': [{
            'id': m.id,
            'role': m.role,
            'content': m.content,
            'created_at': m.created_at.strftime('%b %d, %I:%M %p'),
            'tool_calls': m.tool_calls,
        } for m in chat.messages],
    })


@app.route('/api/chats/<int:chat_id>/messages', methods=['POST'])
def api_send_message(chat_id):
    chat = Chat.query.get_or_404(chat_id)
    data = request.get_json() or {}
    user_content = (data.get('content') or '').strip()

    if not user_content:
        return jsonify({'error': 'Message content is required'}), 400

    # Auto-name chat from the first user message (check before adding)
    is_first_message = Message.query.filter_by(chat_id=chat_id).count() == 0

    # Persist user message
    user_msg = Message(chat_id=chat_id, role='user', content=user_content)
    db.session.add(user_msg)

    if is_first_message:
        chat.name = user_content[:50] + ('…' if len(user_content) > 50 else '')

    db.session.flush()

    # Build full conversation history for the model
    history = [{'role': m.role, 'content': m.content} for m in chat.messages]

    system_prompt = (
        "You are Dashie, an AI assistant inside DoorDash's internal AI Labs Data Workbench. "
        "You help data scientists, engineers, and product managers analyze data, write SQL, "
        "interpret A/B experiment results, and answer questions about DoorDash's systems and "
        "metrics. Be concise, technically precise, and helpful."
    )

    try:
        client = openai.OpenAI(api_key=openai.api_key)
        response = client.chat.completions.create(
            model='gpt-4o-mini',
            messages=[{'role': 'system', 'content': system_prompt}] + history,
            temperature=0.7,
            max_tokens=1000,
        )

        assistant_content = response.choices[0].message.content
        tokens_used = response.usage.total_tokens

        assistant_msg = Message(
            chat_id=chat_id,
            role='assistant',
            content=assistant_content,
            tool_calls={'model': 'gpt-4o-mini', 'tokens_used': tokens_used},
        )
        db.session.add(assistant_msg)
        db.session.commit()

        return jsonify({
            'message': {
                'id': assistant_msg.id,
                'role': 'assistant',
                'content': assistant_content,
                'created_at': assistant_msg.created_at.strftime('%b %d, %I:%M %p'),
            },
            'metadata': {
                'model': 'gpt-4o-mini',
                'tokens_used': tokens_used,
                'chat_name': chat.name,
            },
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f'Chat completion error: {e}')
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug=True, host='0.0.0.0', port=5000)
