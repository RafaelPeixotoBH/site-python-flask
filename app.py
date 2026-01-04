# --- CORREÇÃO DE REDE (Force IPv4) ---
# Essencial para o Render funcionar com Gmail
import socket
def getaddrinfo(*args, **kwargs):
    responses = socket._getaddrinfo(*args, **kwargs)
    return [r for r in responses if r[0] == socket.AF_INET]
socket._getaddrinfo = socket.getaddrinfo
socket.getaddrinfo = getaddrinfo
# -------------------------------------

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
app.config['SECRET_KEY'] = 'chave-secreta-mude-em-producao'
basedir = os.path.abspath(os.path.dirname(__file__))

# --- CONFIGURAÇÃO DE E-MAIL (PADRÃO 587/TLS) ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEBUG'] = True # Ajuda a ver erros nos logs
app.config['MAIL_MAX_EMAILS'] = None

# Fallback para o remetente
if app.config['MAIL_USERNAME']:
    app.config['MAIL_DEFAULT_SENDER'] = ('Suporte Agenda', app.config['MAIL_USERNAME'])
else:
    app.config['MAIL_DEFAULT_SENDER'] = ('Suporte Agenda', 'noreply@agenda.com')

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Configuração do Banco
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

# --- MODELOS ---

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
    
    historico_acessos = db.relationship('LoginHistory', backref='usuario', lazy=True)

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

# --- ROTAS ---

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        if not current_user.is_authenticated:
            flash('Faça login para adicionar nomes.')
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
        
        um_minuto_atras = datetime.now() - timedelta(minutes=1)
        db.session.query(FailedLogin).filter(FailedLogin.timestamp < um_minuto_atras).delete()
        db.session.commit()

        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            db.session.query(FailedLogin).filter_by(username=username).delete()
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
                msg_erro = Markup("Muitas tentativas. <a href='/recuperar' class='alert-link'>Clique aqui para recuperar sua senha.</a>")
                flash(msg_erro, 'danger')
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
            # Verifica se as variáveis existem
            if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
                flash('ERRO DE CONFIGURAÇÃO: Verifique as variáveis MAIL_USERNAME e MAIL_PASSWORD no Render.', 'danger')
                return redirect(url_for('login'))

            token = serializer.dumps(email, salt='recuperar-senha')
            link = url_for('resetar_senha_token', token=token, _external=True)
            
            msg = Message('Recuperação de Senha', recipients=[email])
            msg.body = f'Olá {user.username},\n\nPara redefinir sua senha, clique no link abaixo:\n{link}\n\nO link expira em 1 hora.'
            
            try:
                mail.send(msg)
                flash(f'Sucesso! Link enviado para {email}.', 'success')
            except Exception as e:
                # AQUI ESTÁ O TRUQUE: Mostra o erro real na tela
                erro_real = str(e)
                print(f"ERRO EMAIL: {erro_real}")
                flash(f'ERRO TÉCNICO: {erro_real}', 'danger')
            
            return redirect(url_for('login'))
        else:
            flash('E-mail não encontrado.', 'danger')
            
    return render_template('recuperar.html')

@app.route('/resetar-senha/<token>', methods=['GET', 'POST'])
def resetar_senha_token(token):
    try:
        email = serializer.loads(token, salt='recuperar-senha', max_age=3600)
    except SignatureExpired:
        flash('O link expirou. Solicite um novo.', 'danger')
        return redirect(url_for('recuperar_senha'))
    except:
        flash('Link inválido.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        nova_senha = request.form.get('password')
        user = User.query.filter_by(email=email).first_or_404()
        user.set_password(nova_senha)
        db.session.commit()
        flash('Senha redefinida com sucesso! Faça login.', 'success')
        return redirect(url_for('login'))

    return render_template('resetar_token.html')

@app.route('/registrar', methods=['GET', 'POST'])
def registrar():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.count() >= 101: 
            flash('Limite de usuários atingido!', 'danger')
            return redirect(url_for('login'))
        if User.query.filter_by(username=username).first():
            flash('Usuário já existe.', 'warning')
            return redirect(url_for('registrar'))
        if User.query.filter_by(email=email).first():
            flash('E-mail já cadastrado.', 'warning')
            return redirect(url_for('registrar'))

        novo_user = User(username=username, email=email, is_admin=False)
        novo_user.set_password(password)
        db.session.add(novo_user)
        db.session.commit()
        flash('Conta criada com sucesso!', 'success')
        return redirect(url_for('login'))
    return render_template('registrar.html')

@app.route('/mudar-senha', methods=['GET', 'POST'])
@login_required
def mudar_senha():
    if request.method == 'POST':
        email_novo = request.form.get('email')
        senha_atual = request.form.get('senha_atual')
        nova_senha = request.form.get('nova_senha')

        if not current_user.check_password(senha_atual):
            flash('Senha atual incorreta.', 'danger')
            return redirect(url_for('mudar_senha'))
        
        if email_novo and email_novo != current_user.email:
            if User.query.filter_by(email=email_novo).first():
                flash('E-mail já em uso.', 'warning')
                return redirect(url_for('mudar_senha'))
            current_user.email = email_novo

        if nova_senha:
            current_user.set_password(nova_senha)

        db.session.commit()
        flash('Dados atualizados!', 'success')
        return redirect(url_for('home'))
    return render_template('mudar_senha.html')

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    if not current_user.is_admin:
        flash("Permissão negada.", 'danger')
        return redirect(url_for('home'))
    usuario = Usuario.query.get_or_404(id)
    db.session.delete(usuario)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/setup-banco')
def setup_banco():
    with app.app_context():
        db.drop_all()
        db.create_all()
    return "Banco resetado!"

@app.route('/criar-admin')
def criar_admin():
    if not User.query.filter_by(username='admin').first():
        email_admin = os.environ.get('MAIL_USERNAME') or 'admin@admin.com'
        admin = User(username='admin', email=email_admin, is_admin=True)
        admin.set_password('123')
        db.session.add(admin)
        db.session.commit()
        return f"Admin criado! E-mail: {email_admin}"
    return "Admin já existe."

@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_admin:
        flash("Acesso restrito.", 'danger')
        return redirect(url_for('home'))
    total = User.query.count()
    limite = 1000
    porcentagem = min((total / limite) * 100, 100)
    lista = User.query.all()
    return render_template('dashboard.html', total=total, limite=limite, porcentagem=porcentagem, lista=lista)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)