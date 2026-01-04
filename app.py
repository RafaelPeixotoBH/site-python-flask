import os
from datetime import datetime, timedelta # Importação do timedelta é essencial
from flask import Flask, render_template, request, redirect, url_for, flash, Markup
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- CONFIGURAÇÕES ---
app.config['SECRET_KEY'] = 'chave-secreta-mude-em-producao'
basedir = os.path.abspath(os.path.dirname(__file__))

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

# --- MODELOS (TABELAS) ---

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)

class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    data_acesso = db.Column(db.DateTime, default=datetime.now)

# NOVO: Tabela para rastrear tentativas de login falhas
class FailedLogin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False) # Quem tentou logar
    timestamp = db.Column(db.DateTime, default=datetime.now) # Quando

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

# --- LOGIN (ATUALIZADO COM LÓGICA DE 3 TENTATIVAS) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # 1. Limpeza: Remove registros de erros antigos (mais de 1 minuto)
        # Isso evita que o banco fique cheio de lixo
        um_minuto_atras = datetime.now() - timedelta(minutes=1)
        db.session.query(FailedLogin).filter(FailedLogin.timestamp < um_minuto_atras).delete()
        db.session.commit()

        user = User.query.filter_by(username=username).first()
        
        # Se login for SUCESSO
        if user and user.check_password(password):
            login_user(user)
            
            # Limpa falhas desse usuário ao logar com sucesso
            db.session.query(FailedLogin).filter_by(username=username).delete()
            
            # Registra histórico
            novo_acesso = LoginHistory(user_id=user.id)
            db.session.add(novo_acesso)
            db.session.commit()

            return redirect(url_for('home'))
        
        # Se login for FALHA (Senha errada ou usuário não existe)
        else:
            # Registra a falha
            nova_falha = FailedLogin(username=username)
            db.session.add(nova_falha)
            db.session.commit()

            # Conta falhas no último minuto para este usuário
            qtd_erros = FailedLogin.query.filter(
                FailedLogin.username == username,
                FailedLogin.timestamp >= um_minuto_atras
            ).count()

            if qtd_erros >= 3:
                # Usa Markup para permitir HTML no flash (o link <a>)
                msg_erro = Markup(f"Muitas tentativas falhas. <a href='/recuperar' class='alert-link'>Esqueceu sua senha? Clique aqui para recuperar.</a>")
                flash(msg_erro, 'danger')
            else:
                flash('Login ou senha inválidos.', 'warning')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# --- ROTA DE RECUPERAÇÃO (SIMULAÇÃO) ---
@app.route('/recuperar', methods=['GET', 'POST'])
def recuperar_senha():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Como não temos servidor de e-mail real configurado (SMTP),
            # vamos apenas simular que enviamos.
            flash(f'Um link de redefinição foi enviado para {email} (Simulação).', 'success')
            return redirect(url_for('login'))
        else:
            flash('E-mail não encontrado no sistema.', 'danger')
            
    return render_template('recuperar.html')

# --- CADASTRO ---
@app.route('/registrar', methods=['GET', 'POST'])
def registrar():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.count() >= 101: 
            flash('Limite de usuários atingido! Contate o suporte.')
            return redirect(url_for('login'))

        if User.query.filter_by(username=username).first():
            flash('Este nome de usuário já está em uso.')
            return redirect(url_for('registrar'))

        if User.query.filter_by(email=email).first():
            flash('Este e-mail já está cadastrado no sistema.')
            return redirect(url_for('registrar'))

        novo_user = User(username=username, email=email, is_admin=False)
        novo_user.set_password(password)
        db.session.add(novo_user)
        db.session.commit()
        
        flash('Conta criada com sucesso! Faça login.')
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
            flash('A senha atual está incorreta. Nada foi alterado.')
            return redirect(url_for('mudar_senha'))

        if email_novo and email_novo != current_user.email:
            if User.query.filter_by(email=email_novo).first():
                flash('Este e-mail já está em uso por outro usuário.')
                return redirect(url_for('mudar_senha'))
            current_user.email = email_novo

        if nova_senha:
            current_user.set_password(nova_senha)

        db.session.commit()
        flash('Seus dados foram atualizados com sucesso!')
        return redirect(url_for('home'))

    return render_template('mudar_senha.html')

# --- EXCLUIR ---
@app.route('/delete/<int:id>')
@login_required
def delete(id):
    if not current_user.is_admin:
        flash("Apenas administradores podem excluir dados.")
        return redirect(url_for('home'))

    usuario_para_deletar = Usuario.query.get_or_404(id)
    db.session.delete(usuario_para_deletar)
    db.session.commit()
    return redirect(url_for('home'))

# --- FERRAMENTAS ---
@app.route('/setup-banco')
def setup_banco():
    db.drop_all()
    db.create_all()
    return "Banco de dados limpo e recriado (Tabela de Falhas Adicionada)!"

@app.route('/criar-admin')
def criar_admin():
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@seusistema.com', is_admin=True)
        admin.set_password('123')
        db.session.add(admin)
        db.session.commit()
        return "Usuário Admin criado! Login: admin | Senha: 123"
    return "Admin já existe."

# --- DASHBOARD ---
@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_admin:
        flash("Acesso restrito ao administrador.")
        return redirect(url_for('home'))
    
    total_usuarios = User.query.count()
    limite = 100
    porcentagem = min((total_usuarios / limite) * 100, 100)
    
    lista_usuarios = User.query.all()
    
    return render_template('dashboard.html', 
                           total=total_usuarios, 
                           limite=limite, 
                           porcentagem=porcentagem,
                           lista=lista_usuarios)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)