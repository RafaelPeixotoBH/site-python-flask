import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash
from markupsafe import Markup
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message # Importação para E-mail
from itsdangerous import URLSafeTimedSerializer, SignatureExpired # Para gerar o token seguro

app = Flask(__name__)

# --- CONFIGURAÇÕES GERAIS ---
app.config['SECRET_KEY'] = 'chave-secreta-mude-em-producao'
basedir = os.path.abspath(os.path.dirname(__file__))

# --- CONFIGURAÇÃO DO SERVIDOR DE E-MAIL (GMAIL) ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'nossaagendasuporte@gmail.com'  # <--- COLOQUE SEU GMAIL AQUI
app.config['MAIL_PASSWORD'] = 'zrkb zmvh vkhb vlif'       # <--- COLOQUE A SENHA DE APP AQUI (16 letras)
app.config['MAIL_DEFAULT_SENDER'] = ('Suporte Agenda', app.config['MAIL_USERNAME'])

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY']) # Gerador de Tokens

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

class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    data_acesso = db.Column(db.DateTime, default=datetime.now)

class FailedLogin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)

class User(UserMixin, db.Model): 
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

# --- ROTAS PRINCIPAIS ---

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

# --- LOGIN ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Limpa logs antigos
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
                msg_erro = Markup(f"Muitas tentativas. <a href='/recuperar' class='alert-link'>Clique aqui para recuperar sua senha.</a>")
                flash(msg_erro, 'danger')
            else:
                flash('Login ou senha inválidos.', 'warning')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# --- RECUPERAÇÃO DE SENHA (ENVIO DE E-MAIL REAL) ---
@app.route('/recuperar', methods=['GET', 'POST'])
def recuperar_senha():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            # 1. Gera um token seguro (válido por 1 hora)
            token = serializer.dumps(email, salt='recuperar-senha')
            
            # 2. Cria o Link (Se estiver local usa localhost, se estiver no render usa o dominio do render)
            link = url_for('resetar_senha_token', token=token, _external=True)
            
            # 3. Monta o E-mail
            msg = Message('Recuperação de Senha', recipients=[email])
            msg.body = f'Olá {user.username},\n\nPara redefinir sua senha, clique no link abaixo:\n{link}\n\nO link expira em 1 hora.'
            
            # 4. Envia
            try:
                mail.send(msg)
                flash(f'E-mail de recuperação enviado para {email}. Verifique sua caixa de entrada (e spam).', 'success')
            except Exception as e:
                flash(f'Erro ao enviar e-mail: {str(e)}', 'danger')
            
            return redirect(url_for('login'))
        else:
            flash('E-mail não encontrado no sistema.', 'danger')
            
    return render_template('recuperar.html')

# --- NOVA ROTA: ONDE O USUÁRIO CRIA A NOVA SENHA ---
@app.route('/resetar-senha/<token>', methods=['GET', 'POST'])
def resetar_senha_token(token):
    try:
        # Tenta decodificar o token (máximo 3600 segundos = 1 hora)
        email = serializer.loads(token, salt='recuperar-senha', max_age=3600)
    except SignatureExpired:
        flash('O link de recuperação expirou. Solicite um novo.', 'danger')
        return redirect(url_for('recuperar_senha'))
    except:
        flash('Link inválido.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        nova_senha = request.form.get('password')
        user = User.query.filter_by(email=email).first_or_404()
        
        user.set_password(nova_senha)
        db.session.commit()
        
        flash('Sua senha foi redefinida com sucesso! Faça login.', 'success')
        return redirect(url_for('login'))

    return render_template('resetar_token.html')

# --- CADASTRO ---
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

# --- MEUS DADOS ---
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

# --- EXCLUIR ---
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

# --- FERRAMENTAS ---
@app.route('/setup-banco')
def setup_banco():
    db.drop_all()
    db.create_all()
    return "Banco resetado!"

@app.route('/criar-admin')
def criar_admin():
    if not User.query.filter_by(username='admin').first():
        # ADMIN PADRÃO
        admin = User(username='admin', email='seu.email.real@gmail.com', is_admin=True)
        admin.set_password('123')
        db.session.add(admin)
        db.session.commit()
        return "Admin criado!"
    return "Admin já existe."

# --- DASHBOARD ---
@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_admin:
        flash("Acesso restrito.", 'danger')
        return redirect(url_for('home'))
    total = User.query.count()
    limite = 100
    porcentagem = min((total / limite) * 100, 100)
    lista = User.query.all()
    return render_template('dashboard.html', total=total, limite=limite, porcentagem=porcentagem, lista=lista)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)