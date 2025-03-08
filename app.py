from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from dateutil.relativedelta import relativedelta
from werkzeug.utils import secure_filename
import os
from slugify import slugify

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dairy_management.db'
UPLOAD_FOLDER = os.path.join('static', 'franchises')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)  # Phone number can be null initially
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # Only 'user' or 'owner' roles
    forum_topics = db.relationship('ForumTopic', backref='author', lazy=True)
    forum_replies = db.relationship('ForumReply', backref='author', lazy=True)
    support_tickets = db.relationship('Support', backref='user', lazy=True)
    franchise_inquiries = db.relationship('FranchiseInquiry', backref='user', lazy=True)

class Support(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='open')
    category = db.Column(db.String(50), nullable=False, default='general')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    responses = db.relationship('TicketResponse', backref='ticket', lazy=True, cascade='all, delete-orphan')

class TicketResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ticket_id = db.Column(db.Integer, db.ForeignKey('support.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='ticket_responses', lazy=True)

class ForumTopic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False, default='general')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    replies = db.relationship('ForumReply', backref='topic', lazy=True, cascade='all, delete-orphan')
    views = db.Column(db.Integer, default=0)
    is_pinned = db.Column(db.Boolean, default=False)
    is_closed = db.Column(db.Boolean, default=False)
    notify_author = db.Column(db.Boolean, default=True)

class ForumReply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    topic_id = db.Column(db.Integer, db.ForeignKey('forum_topic.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Franchise(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    min_investment = db.Column(db.Float, nullable=False)
    max_investment = db.Column(db.Float, nullable=False)
    brand_image = db.Column(db.String(200), nullable=False)
    locations = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    owner = db.relationship('User', backref='owned_franchises', lazy=True)

class FranchiseInquiryResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    inquiry_id = db.Column(db.Integer, db.ForeignKey('franchise_inquiry.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='franchise_responses', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'message': self.message,
            'created_at': self.created_at.isoformat(),
            'user_name': self.user.username,
            'user_id': self.user_id
        }

class FranchiseInquiry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    investment_capacity = db.Column(db.Float, nullable=False)
    preferred_location = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    franchise_id = db.Column(db.Integer, db.ForeignKey('franchise.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    franchise = db.relationship('Franchise', backref='inquiries', lazy=True)
    responses = db.relationship('FranchiseInquiryResponse', backref='inquiry', lazy=True, cascade='all, delete-orphan')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    # Get franchises not owned by current user if logged in
    if current_user.is_authenticated:
        franchises = Franchise.query.filter(
            Franchise.owner_id != current_user.id
        ).order_by(Franchise.created_at.desc()).limit(6).all()
    else:
        franchises = Franchise.query.order_by(Franchise.created_at.desc()).limit(6).all()
    
    forum_topics = ForumTopic.query.order_by(ForumTopic.created_at.desc()).limit(5).all()
    return render_template('home.html', franchises=franchises, forum_topics=forum_topics)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username,
            email=email,
            phone=phone,
            password=hashed_password,
            role=role
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('An error occurred. Please try again.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.', 'danger')
            return redirect(url_for('login'))
        
        login_user(user, remember=remember)
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_topics = ForumTopic.query.filter_by(user_id=current_user.id).all()
    user_tickets = Support.query.filter_by(user_id=current_user.id).all()
    user_inquiries = FranchiseInquiry.query.filter_by(user_id=current_user.id).all()
    
    return render_template('dashboard.html',
                         topics=user_topics,
                         tickets=user_tickets,
                         inquiries=user_inquiries)

@app.route('/support', methods=['GET', 'POST'])
@login_required
def support():
    tickets = Support.query.filter_by(user_id=current_user.id).order_by(Support.created_at.desc()).all()
    forum_topics = ForumTopic.query.order_by(ForumTopic.created_at.desc()).limit(5).all()
    franchises = Franchise.query.order_by(Franchise.created_at.desc()).all()
    
    community_stats = {
        'active_members': User.query.count(),
        'total_topics': ForumTopic.query.count(),
        'total_replies': ForumReply.query.count(),
        'franchises': Franchise.query.count()
    }
    
    return render_template('support.html',
                         tickets=tickets,
                         forum_topics=forum_topics,
                         franchises=franchises,
                         community_stats=community_stats,
                         user_role=current_user.role)

@app.route('/create-ticket', methods=['POST'])
@login_required
def create_ticket():
    subject = request.form.get('subject')
    message = request.form.get('message')
    category = request.form.get('category')
    
    ticket = Support(
        subject=subject,
        message=message,
        status='open',
        user_id=current_user.id
    )
    
    try:
        db.session.add(ticket)
        db.session.commit()
        flash('Support ticket created successfully!', 'success')
    except:
        flash('An error occurred while creating the ticket.', 'danger')
    
    return redirect(url_for('support'))

@app.route('/create-franchise', methods=['POST'])
@login_required
def create_franchise():
    if current_user.role != 'owner':
        flash('Only dairy owners can create franchise listings.', 'danger')
        return redirect(url_for('support'))

    name = request.form.get('franchise_name')
    description = request.form.get('franchise_description')
    min_investment = float(request.form.get('min_investment'))
    max_investment = float(request.form.get('max_investment'))
    locations = request.form.get('locations')
    
    # Handle brand image upload
    if 'brand_image' not in request.files:
        flash('Brand image is required.', 'danger')
        return redirect(url_for('support'))
    
    brand_image = request.files['brand_image']
    if brand_image.filename == '':
        flash('No selected file.', 'danger')
        return redirect(url_for('support'))
    
    if brand_image and allowed_file(brand_image.filename):
        # Secure the filename and save the file
        filename = secure_filename(brand_image.filename)
        # Create a unique filename using franchise name and timestamp
        unique_filename = f"{slugify(name)}_{int(datetime.utcnow().timestamp())}{os.path.splitext(filename)[1]}"
        brand_image.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
    else:
        flash('Invalid file type. Please upload an image file (JPG, PNG).', 'danger')
        return redirect(url_for('support'))
    
    franchise = Franchise(
        name=name,
        description=description,
        min_investment=min_investment,
        max_investment=max_investment,
        brand_image=unique_filename,
        locations=locations,
        owner_id=current_user.id
    )
    
    try:
        db.session.add(franchise)
        db.session.commit()
        flash('Franchise listing created successfully!', 'success')
    except:
        if os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)):
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
        flash('An error occurred while creating the franchise listing.', 'danger')
    
    return redirect(url_for('support'))

@app.route('/forum/create-topic', methods=['POST'])
@login_required
def create_topic():
    title = request.form.get('title')
    description = request.form.get('description')
    category = request.form.get('category', 'general')
    notify = True if request.form.get('notify') else False
    
    topic = ForumTopic(
        title=title,
        description=description,
        category=category,
        user_id=current_user.id,
        notify_author=notify
    )
    
    try:
        db.session.add(topic)
        db.session.commit()
        flash('Forum topic created successfully!', 'success')
    except:
        db.session.rollback()
        flash('An error occurred while creating the topic.', 'danger')
    
    return redirect(url_for('support'))

@app.route('/forum/reply/<int:topic_id>', methods=['POST'])
@login_required
def reply_topic(topic_id):
    content = request.form.get('content')
    
    reply = ForumReply(
        content=content,
        topic_id=topic_id,
        user_id=current_user.id
    )
    
    try:
        db.session.add(reply)
        db.session.commit()
        flash('Reply posted successfully!', 'success')
    except:
        flash('An error occurred while posting the reply.', 'danger')
    
    return redirect(url_for('support'))

@app.route('/forum/topic/<int:topic_id>')
@login_required
def view_topic(topic_id):
    topic = ForumTopic.query.get_or_404(topic_id)
    topic.views += 1
    db.session.commit()
    return render_template('view_topic.html', topic=topic)

@app.route('/forum/search')
@login_required
def search_forum():
    query = request.args.get('q', '')
    topics = ForumTopic.query.filter(
        (ForumTopic.title.ilike(f'%{query}%')) |
        (ForumTopic.description.ilike(f'%{query}%'))
    ).order_by(ForumTopic.created_at.desc()).all()
    return render_template('forum_search.html', topics=topics, query=query)

@app.route('/franchise/view/<int:franchise_id>')
@login_required
def view_franchise(franchise_id):
    franchise = Franchise.query.get_or_404(franchise_id)
    
    # Find similar franchises based on investment range overlap
    similar_franchises = Franchise.query.filter(
        Franchise.id != franchise_id,
        Franchise.min_investment <= franchise.max_investment * 1.2,
        Franchise.max_investment >= franchise.min_investment * 0.8
    ).limit(5).all()
    
    return render_template('view_franchise.html', franchise=franchise, similar_franchises=similar_franchises)

@app.route('/franchise/search')
@login_required
def search_franchises():
    query = request.args.get('q', '')
    min_investment = request.args.get('min_investment', type=float)
    max_investment = request.args.get('max_investment', type=float)
    location = request.args.get('location', '')
    
    # Start with franchises not owned by current user
    franchises_query = Franchise.query.filter(Franchise.owner_id != current_user.id)
    
    if query:
        franchises_query = franchises_query.filter(
            (Franchise.name.ilike(f'%{query}%')) |
            (Franchise.description.ilike(f'%{query}%'))
        )
    
    if min_investment:
        franchises_query = franchises_query.filter(Franchise.min_investment >= min_investment)
    
    if max_investment:
        franchises_query = franchises_query.filter(Franchise.max_investment <= max_investment)
    
    if location:
        franchises_query = franchises_query.filter(Franchise.locations.ilike(f'%{location}%'))
    
    franchises = franchises_query.order_by(Franchise.created_at.desc()).all()
    return render_template('franchise_search.html', franchises=franchises)

@app.route('/create-inquiry', methods=['POST'])
@login_required
def create_inquiry():
    franchise_id = request.form.get('franchise_id')
    message = request.form.get('message')
    investment_capacity = float(request.form.get('investment_capacity'))
    preferred_location = request.form.get('preferred_location')
    
    inquiry = FranchiseInquiry(
        message=message,
        investment_capacity=investment_capacity,
        preferred_location=preferred_location,
        franchise_id=franchise_id,
        user_id=current_user.id
    )
    
    try:
        db.session.add(inquiry)
        db.session.commit()
        flash('Inquiry sent successfully!', 'success')
    except:
        flash('An error occurred while sending the inquiry.', 'danger')
    
    return redirect(url_for('search_franchises'))

@app.route('/forum/topic/<int:topic_id>/manage', methods=['POST'])
@login_required
def manage_topic(topic_id):
    topic = ForumTopic.query.get_or_404(topic_id)
    if topic.user_id != current_user.id and current_user.role != 'owner':
        flash('You do not have permission to manage this topic.', 'danger')
        return redirect(url_for('view_topic', topic_id=topic_id))
    
    action = request.form.get('action')
    if action == 'pin':
        topic.is_pinned = not topic.is_pinned
        message = 'Topic pinned successfully!' if topic.is_pinned else 'Topic unpinned successfully!'
    elif action == 'close':
        topic.is_closed = not topic.is_closed
        message = 'Topic closed successfully!' if topic.is_closed else 'Topic reopened successfully!'
    elif action == 'delete':
        db.session.delete(topic)
        db.session.commit()
        flash('Topic deleted successfully!', 'success')
        return redirect(url_for('support'))
    
    try:
        db.session.commit()
        flash(message, 'success')
    except:
        flash('An error occurred while managing the topic.', 'danger')
    
    return redirect(url_for('view_topic', topic_id=topic_id))

@app.route('/franchise/inquiry/<int:inquiry_id>/manage', methods=['POST'])
@login_required
def manage_inquiry(inquiry_id):
    inquiry = FranchiseInquiry.query.get_or_404(inquiry_id)
    franchise = inquiry.franchise
    
    if franchise.owner_id != current_user.id:
        flash('You do not have permission to manage this inquiry.', 'danger')
        return redirect(url_for('search_franchises'))
    
    action = request.form.get('action')
    if action in ['accept', 'reject']:
        inquiry.status = action + 'ed'
        message = f'Inquiry {action}ed successfully!'
        
        # Send notification to the user (you can implement this later)
        # notify_user(inquiry.user_id, f'Your franchise inquiry has been {action}ed')
    
    try:
        db.session.commit()
        flash(message, 'success')
    except:
        flash('An error occurred while managing the inquiry.', 'danger')
    
    return redirect(url_for('search_franchises'))

@app.route('/franchise/stats')
@login_required
def franchise_stats():
    # Get overall statistics
    total_franchises = Franchise.query.count()
    total_inquiries = FranchiseInquiry.query.count()
    pending_inquiries = FranchiseInquiry.query.filter_by(status='pending').count()
    accepted_inquiries = FranchiseInquiry.query.filter_by(status='accepted').count()
    rejected_inquiries = FranchiseInquiry.query.filter_by(status='rejected').count()
    
    # Calculate average investment range
    franchises = Franchise.query.all()
    if total_franchises > 0:
        avg_min_investment = sum(f.min_investment for f in franchises) / total_franchises
        avg_max_investment = sum(f.max_investment for f in franchises) / total_franchises
        avg_investment = (avg_min_investment + avg_max_investment) / 2
    else:
        avg_investment = 0
    
    # Get unique locations
    unique_locations = len(set(location.strip() for f in franchises for location in f.locations.split(',')))
    
    # Get monthly statistics for the past 6 months
    monthly_stats = []
    for i in range(5, -1, -1):
        start_date = datetime.now() - relativedelta(months=i)
        end_date = start_date + relativedelta(months=1)
        count = Franchise.query.filter(
            Franchise.created_at >= start_date,
            Franchise.created_at < end_date
        ).count()
        monthly_stats.append({
            'month': start_date.strftime('%B %Y'),
            'count': count
        })
    
    stats = {
        'total_franchises': total_franchises,
        'total_inquiries': total_inquiries,
        'pending_inquiries': pending_inquiries,
        'accepted_inquiries': accepted_inquiries,
        'rejected_inquiries': rejected_inquiries,
        'avg_investment': avg_investment,
        'locations': unique_locations
    }
    
    return render_template('franchise_stats.html', stats=stats, monthly_stats=monthly_stats)

@app.route('/quick-help')
def quick_help():
    return render_template('quick_help.html')

@app.route('/documentation')
def documentation():
    return render_template('documentation.html')

@app.route('/video-tutorials')
def video_tutorials():
    return render_template('video_tutorials.html')

@app.route('/faqs')
def faqs():
    return render_template('faqs.html')

@app.route('/profile/update', methods=['GET', 'POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        phone = request.form.get('phone')
        
        try:
            current_user.phone = phone
            db.session.commit()
            flash('Profile updated successfully!', 'success')
        except:
            flash('An error occurred while updating your profile.', 'danger')
        
        return redirect(url_for('dashboard'))
    
    return render_template('update_profile.html')

# API Routes for Ticket Management
@app.route('/api/tickets/<int:ticket_id>', methods=['GET'])
@login_required
def get_ticket_details(ticket_id):
    ticket = Support.query.get_or_404(ticket_id)
    
    # Check if user has permission to view this ticket
    if ticket.user_id != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    responses = TicketResponse.query.filter_by(ticket_id=ticket_id).order_by(TicketResponse.created_at).all()
    
    return jsonify({
        'id': ticket.id,
        'subject': ticket.subject,
        'message': ticket.message,
        'status': ticket.status,
        'category': ticket.category,
        'created_at': ticket.created_at.isoformat(),
        'responses': [{
            'id': response.id,
            'message': response.message,
            'author': response.user.username,
            'created_at': response.created_at.isoformat()
        } for response in responses]
    })

@app.route('/api/tickets/<int:ticket_id>/respond', methods=['POST'])
@login_required
def add_ticket_response(ticket_id):
    ticket = Support.query.get_or_404(ticket_id)
    
    # Check if user has permission to respond to this ticket
    if ticket.user_id != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({'error': 'Message is required'}), 400
    
    response = TicketResponse(
        message=data['message'],
        ticket_id=ticket_id,
        user_id=current_user.id
    )
    db.session.add(response)
    
    # Update ticket status if it was new
    if ticket.status == 'open':
        ticket.status = 'in_progress'
    
    db.session.commit()
    
    return jsonify({
        'id': response.id,
        'message': response.message,
        'author': current_user.username,
        'created_at': response.created_at.isoformat()
    })

@app.route('/franchise/my-inquiries')
@login_required
def my_franchise_inquiries():
    if current_user.role != 'owner':
        flash('Only franchise owners can view inquiries.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get all franchises owned by the current user
    owned_franchises = Franchise.query.filter_by(owner_id=current_user.id).all()
    
    # Get all inquiries for these franchises
    franchise_inquiries = {}
    for franchise in owned_franchises:
        inquiries = FranchiseInquiry.query.filter_by(franchise_id=franchise.id)\
            .order_by(FranchiseInquiry.created_at.desc()).all()
        franchise_inquiries[franchise.id] = inquiries
    
    return render_template('franchise_inquiries.html', 
                         franchises=owned_franchises,
                         franchise_inquiries=franchise_inquiries)

@app.route('/franchise/inquiry/<int:inquiry_id>/respond', methods=['POST'])
@login_required
def respond_to_inquiry(inquiry_id):
    inquiry = FranchiseInquiry.query.get_or_404(inquiry_id)
    franchise = inquiry.franchise
    
    # Check if user is the franchise owner or the inquiry creator
    if not (franchise.owner_id == current_user.id or inquiry.user_id == current_user.id):
        flash('You do not have permission to respond to this inquiry.', 'danger')
        return redirect(url_for('dashboard'))
    
    message = request.form.get('response_message')
    if not message:
        flash('Response message is required.', 'danger')
        return redirect(url_for('my_franchise_inquiries'))
    
    response = FranchiseInquiryResponse(
        message=message,
        inquiry_id=inquiry_id,
        user_id=current_user.id
    )
    
    try:
        db.session.add(response)
        db.session.commit()
        flash('Response sent successfully!', 'success')
    except:
        flash('An error occurred while sending the response.', 'danger')
    
    # Redirect based on user role
    if current_user.role == 'owner':
        return redirect(url_for('my_franchise_inquiries'))
    else:
        return redirect(url_for('dashboard'))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 