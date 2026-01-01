import os
from flask import Flask, render_template, request, redirect, url_for, flash
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

class User(UserMixin, db.Model): 
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False) # NOVA COLUNA: Define se é chefe

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --- ROTAS ---

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        # Apenas usuários logados podem adicionar nomes na lista
        if not current_user.is_authenticated:
            flash('Faça login para adicionar.')
            return redirect(url_for('login'))
            
        nome_form = request.form.get('nome')
        if nome_form:
            novo_usuario = Usuario(nome=nome_form)
            db.session.add(novo_usuario)
            db.session.commit()
        return redirect(url_for('home'))

    try:
        usuarios = Usuario.query.all()
    except:
        usuarios = []
    return render_template('index.html', usuarios=usuarios)

# --- ROTA DE LOGIN ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login inválido.')
    return render_template('login.html')

# --- NOVA ROTA: CADASTRAR NOVO USUÁRIO ---
@app.route('/registrar', methods=['GET', 'POST'])
def registrar():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # 1. Verifica se já existem 100 usuários
        total_users = User.query.count()
        if total_users >= 101: # 1 Admin + 100 usuários
            flash('Limite de usuários atingido! Entre em contato com o suporte.')
            return redirect(url_for('login'))

        # 2. Verifica se o nome já existe
        if User.query.filter_by(username=username).first():
            flash('Este usuário já existe.')
            return redirect(url_for('registrar'))

        # 3. Cria usuário COMUM (is_admin=False)
        novo_user = User(username=username, is_admin=False)
        novo_user.set_password(password)
        db.session.add(novo_user)
        db.session.commit()
        
        flash('Conta criada com sucesso! Faça login.')
        return redirect(url_for('login'))

    return render_template('registrar.html')

# --- NOVA ROTA: MUDAR SENHA ---
@app.route('/mudar-senha', methods=['GET', 'POST'])
@login_required
def mudar_senha():
    if request.method == 'POST':
        senha_atual = request.form.get('senha_atual')
        nova_senha = request.form.get('nova_senha')

        # Verifica se a senha atual está certa
        if not current_user.check_password(senha_atual):
            flash('A senha atual está incorreta.')
            return redirect(url_for('mudar_senha'))

        # Troca pela nova
        current_user.set_password(nova_senha)
        db.session.commit()
        flash('Senha alterada com sucesso!')
        return redirect(url_for('home'))

    return render_template('mudar_senha.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# --- EXCLUIR (SÓ PARA ADMIN) ---
@app.route('/delete/<int:id>')
@login_required
def delete(id):
    # Trava de segurança no Back-end: Se não for admin, chuta fora
    if not current_user.is_admin:
        flash("Apenas administradores podem excluir.")
        return redirect(url_for('home'))

    usuario_para_deletar = Usuario.query.get_or_404(id)
    db.session.delete(usuario_para_deletar)
    db.session.commit()
    return redirect(url_for('home'))

# --- CONFIGURAÇÃO DO BANCO ---
@app.route('/setup-banco')
def setup_banco():
    try:
        db.drop_all()
        db.create_all()
        return "Banco RESETADO! Tabelas recriadas com suporte a Admin."
    except Exception as e:
        return f"Erro: {str(e)}"

@app.route('/criar-admin')
def criar_admin():
    try:
        if User.query.filter_by(username='admin').first():
            return "Admin já existe!"
        
        # Cria o ADMIN SUPREMO (is_admin=True)
        novo_admin = User(username='admin', is_admin=True)
        novo_admin.set_password('123') 
        db.session.add(novo_admin)
        db.session.commit()
        return "Admin criado com sucesso! Login: admin / Senha: 123"
    except Exception as e:
        return f"Erro: {str(e)}"

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)