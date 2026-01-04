import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash
from markupsafe import Markup
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

app = Flask(__name__)

# --- CONFIGURAÇÕES GERAIS ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'chave-secreta-mude-em-producao')
basedir = os.path.abspath(os.path.dirname(__file__))

# --- CONFIGURAÇÃO DE E-MAIL (BREVO / SMTP) ---
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp-relay.brevo.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- BANCO DE DADOS (PostgreSQL ou SQLite) ---
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///' + os.path.join(basedir, 'meu_banco.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- SISTEMA DE LOGIN ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- MODELOS (TABELAS) ---

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)

class User(UserMixin, db.Model): 
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    historico_acessos = db.relationship('LoginHistory', backref='usuario', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class LoginHistory(db.Model):
    __tablename__ = 'login_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    data_acesso = db.Column(db.DateTime, default=datetime.now)

class FailedLogin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)

# --- ROTAS PRINCIPAIS ---

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        if not current_user.is_authenticated:
            flash('Faça login para adicionar nomes.', 'warning')
            return redirect(url_for('login'))
        nome_form = request.form.get('nome')
        if nome_form:
            novo_usuario = Usuario(nome=nome_form)
            db.session.add(novo_usuario)
            db.session.commit()
        return redirect(url_for('home'))
    
    usuarios = Usuario.query.all()
    return render_template('index.html', usuarios=usuarios)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Limpeza de tentativas antigas
        um_minuto_atras = datetime.now() - timedelta(minutes=1)
        FailedLogin.query.filter(FailedLogin.timestamp < um_minuto_atras).delete()
        db.session.commit()
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            FailedLogin.query.filter_by(username=username).delete()
            novo_acesso = LoginHistory(user_id=user.id)
            db.session.add(novo_acesso)
            db.session.commit()
            return redirect(url_for('home'))
        else:
            nova_falha = FailedLogin(username=username)
            db.session.add(nova_falha)
            db.session.commit()
            
            qtd_erros = FailedLogin.query.filter(FailedLogin.username == username, FailedLogin.timestamp >= um_minuto_atras).count()
            if qtd_erros >= 3:
                link = url_for('recuperar_senha')
                msg = Markup(f"Muitas tentativas. <a href='{link}' class='alert-link'>Clique aqui para recuperar sua senha.</a>")
                flash(msg, 'danger')
            else:
                flash('Login ou senha inválidos.', 'warning')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/recuperar', methods=['GET', 'POST'])
def recuperar_senha():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(email, salt='recuperar-senha')
            link = url_for('resetar_senha_token', token=token, _external=True)
            msg = Message('Recuperação de Senha', recipients=[email])
            msg.body = f'Olá {user.username},\n\nClique no link para redefinir sua senha:\n{link}\n\nO link expira em 1 hora.'
            try:
                mail.send(msg)
                flash(f'Sucesso! Instruções enviadas para {email}.', 'success')
            except Exception as e:
                flash(f'Erro ao enviar e-mail: {str(e)}', 'danger')
            return redirect(url_for('login'))
        flash('E-mail não encontrado.', 'danger')
    return render_template('recuperar.html')

@app.route('/resetar-senha/<token>', methods=['GET', 'POST'])
def resetar_senha_token(token):
    try:
        email = serializer.loads(token, salt='recuperar-senha', max_age=3600)
    except:
        flash('Link inválido ou expirado.', 'danger')
        return redirect(url_for('recuperar_senha'))
    
    if request.method == 'POST':
        nova_senha = request.form.get('password')
        user = User.query.filter_by(email=email).first_or_404()
        user.set_password(nova_senha)
        db.session.commit()
        flash('Senha redefinida com sucesso!', 'success')
        return redirect(url_for('login'))
    return render_template('resetar_token.html')

@app.route('/registrar', methods=['GET', 'POST'])
def registrar():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Usuário já existe.', 'warning')
            return redirect(url_for('registrar'))
        
        novo_user = User(username=username, email=email)
        novo_user.set_password(password)
        db.session.add(novo_user)
        db.session.commit()
        flash('Conta criada com sucesso!', 'success')
        return redirect(url_for('login'))
    return render_template('registrar.html')

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    if not current_user.is_admin:
        flash("Acesso negado.", 'danger')
        return redirect(url_for('home'))
    usuario = Usuario.query.get_or_404(id)
    db.session.delete(usuario)
    db.session.commit()
    return redirect(url_for('home'))

# --- FERRAMENTAS DO SISTEMA ---

@app.route('/setup-banco')
def setup_banco():
    with app.app_context():
        db.drop_all()
        db.create_all()
    return "Banco de dados resetado com sucesso!"

@app.route('/criar-admin')
def criar_admin():
    if not User.query.filter_by(username='admin').first():
        # Busca o e-mail real das variáveis de ambiente
        email_admin = os.environ.get('MAIL_DEFAULT_SENDER') or 'admin@admin.com'
        
        admin = User(username='admin', email=email_admin, is_admin=True)
        admin.set_password('123')
        db.session.add(admin)
        db.session.commit()
        return f"Admin criado! E-mail de login: {email_admin}"
    return "O usuário Admin já existe."

@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_admin:
        flash("Acesso restrito a administradores.", 'danger')
        return redirect(url_for('home'))
    total_users = User.query.count()
    lista_users = User.query.all()
    return render_template('dashboard.html', total=total_users, lista=lista_users, limite=100)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)