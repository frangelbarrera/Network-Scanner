from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()

class User(db.Model):
    """User model for authentication and team management"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='user')  # admin, user, viewer
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    learning_mode = db.Column(db.Boolean, default=True)
    
    # Relationships
    projects = db.relationship('Project', backref='owner', lazy=True, cascade='all, delete-orphan')
    scan_results = db.relationship('ScanResult', backref='user', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat(),
            'is_active': self.is_active,
            'learning_mode': self.learning_mode
        }

class Project(db.Model):
    """Project model for organizing scans and targets"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    target = db.Column(db.String(255), nullable=False)
    project_type = db.Column(db.String(50))  # web, network, mobile, etc.
    status = db.Column(db.String(20), default='active')  # active, completed, archived
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    scan_results = db.relationship('ScanResult', backref='project', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Project {self.name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'target': self.target,
            'project_type': self.project_type,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'user_id': self.user_id,
            'scan_count': len(self.scan_results)
        }

class ScanResult(db.Model):
    """Scan result model for storing all scan data"""
    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(50), nullable=False)  # subdomain, port, vuln, comprehensive
    target = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='running')  # running, completed, failed
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    duration = db.Column(db.Integer)  # in seconds
    
    # Scan results stored as JSON
    results = db.Column(db.Text)  # JSON string of scan results
    ai_analysis = db.Column(db.Text)  # JSON string of AI analysis
    
    # Metadata
    scan_options = db.Column(db.Text)  # JSON string of scan options
    error_message = db.Column(db.Text)
    
    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=True)
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='scan_result', lazy=True, cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', backref='scan_result', lazy=True)
    
    def __repr__(self):
        return f'<ScanResult {self.scan_type} - {self.target}>'
    
    def to_dict(self, include_results=False):
        data = {
            'id': self.id,
            'scan_type': self.scan_type,
            'target': self.target,
            'status': self.status,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': self.duration,
            'user_id': self.user_id,
            'project_id': self.project_id,
            'vulnerability_count': len(self.vulnerabilities)
        }
        
        if include_results:
            data['results'] = json.loads(self.results) if self.results else {}
            data['ai_analysis'] = json.loads(self.ai_analysis) if self.ai_analysis else {}
            data['scan_options'] = json.loads(self.scan_options) if self.scan_options else {}
        
        return data
    
    def set_results(self, results_dict):
        """Set results as JSON string"""
        self.results = json.dumps(results_dict)
    
    def get_results(self):
        """Get results as dictionary"""
        return json.loads(self.results) if self.results else {}
    
    def set_ai_analysis(self, analysis_dict):
        """Set AI analysis as JSON string"""
        self.ai_analysis = json.dumps(analysis_dict)
    
    def get_ai_analysis(self):
        """Get AI analysis as dictionary"""
        return json.loads(self.ai_analysis) if self.ai_analysis else {}

class Vulnerability(db.Model):
    """Individual vulnerability findings"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20), nullable=False)  # Critical, High, Medium, Low
    vulnerability_type = db.Column(db.String(100))  # XSS, SQLi, etc.
    cve_id = db.Column(db.String(20))  # CVE identifier if applicable
    cvss_score = db.Column(db.Float)
    
    # Location information
    host = db.Column(db.String(255))
    port = db.Column(db.Integer)
    service = db.Column(db.String(50))
    url = db.Column(db.String(500))
    
    # Technical details
    proof_of_concept = db.Column(db.Text)  # PoC or reproduction steps
    recommendation = db.Column(db.Text)
    references = db.Column(db.Text)  # JSON array of reference URLs
    
    # Status tracking
    status = db.Column(db.String(20), default='open')  # open, fixed, false_positive, risk_accepted
    verified = db.Column(db.Boolean, default=False)
    
    # Timestamps
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Foreign keys
    scan_result_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'), nullable=False)
    
    def __repr__(self):
        return f'<Vulnerability {self.title} - {self.severity}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'vulnerability_type': self.vulnerability_type,
            'cve_id': self.cve_id,
            'cvss_score': self.cvss_score,
            'host': self.host,
            'port': self.port,
            'service': self.service,
            'url': self.url,
            'proof_of_concept': self.proof_of_concept,
            'recommendation': self.recommendation,
            'references': json.loads(self.references) if self.references else [],
            'status': self.status,
            'verified': self.verified,
            'discovered_at': self.discovered_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'scan_result_id': self.scan_result_id
        }

class AuditLog(db.Model):
    """Audit log for tracking user actions and system events"""
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50))  # scan, project, user, etc.
    resource_id = db.Column(db.Integer)
    details = db.Column(db.Text)  # JSON string with additional details
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    scan_result_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'), nullable=True)
    
    def __repr__(self):
        return f'<AuditLog {self.action} - {self.timestamp}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'details': json.loads(self.details) if self.details else {},
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'timestamp': self.timestamp.isoformat(),
            'user_id': self.user_id,
            'scan_result_id': self.scan_result_id
        }

class ScanTemplate(db.Model):
    """Predefined scan templates for common scenarios"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(50))  # web, network, mobile, etc.
    scan_types = db.Column(db.Text)  # JSON array of scan types
    default_options = db.Column(db.Text)  # JSON object with default options
    is_public = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Foreign keys
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def __repr__(self):
        return f'<ScanTemplate {self.name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'category': self.category,
            'scan_types': json.loads(self.scan_types) if self.scan_types else [],
            'default_options': json.loads(self.default_options) if self.default_options else {},
            'is_public': self.is_public,
            'created_at': self.created_at.isoformat(),
            'created_by': self.created_by
        }

class ApiKey(db.Model):
    """API keys for programmatic access"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    key_hash = db.Column(db.String(128), nullable=False, unique=True)
    permissions = db.Column(db.Text)  # JSON array of permissions
    is_active = db.Column(db.Boolean, default=True)
    last_used = db.Column(db.DateTime)
    usage_count = db.Column(db.Integer, default=0)
    rate_limit = db.Column(db.Integer, default=1000)  # requests per hour
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    
    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def __repr__(self):
        return f'<ApiKey {self.name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'permissions': json.loads(self.permissions) if self.permissions else [],
            'is_active': self.is_active,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'usage_count': self.usage_count,
            'rate_limit': self.rate_limit,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'user_id': self.user_id
        }
