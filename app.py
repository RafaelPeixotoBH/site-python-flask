import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- CONFIGURAÇÕES ---
app.config['SECRET_KEY'] = 'uma-chave-muito-secreta-mude-isso-em-producao'
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

class User(UserMixin, db.Model): # Tabela de Admins
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    # AQUI ESTAVA O ERRO: Mudamos de 128 para 256
    password_hash = db.Column(db.String(256))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --- ROTAS ---

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        nome_form = request.form.get('nome')
        if nome_form:
            novo_usuario = Usuario(nome=nome_form)
            db.session.add(novo_usuario)
            db.session.commit()
        return redirect(url_for('home'))

    # Tenta buscar usuários, se a tabela não existir, retorna lista vazia para não dar erro
    try:
        usuarios = Usuario.query.all()
    except:
        usuarios = []
    return render_template('index.html', usuarios=usuarios)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash('Login inválido.')
        except:
            flash('Erro ao conectar no banco. Rode o /setup-banco')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    usuario_para_deletar = Usuario.query.get_or_404(id)
    db.session.delete(usuario_para_deletar)
    db.session.commit()
    return redirect(url_for('home'))

# --- ROTA DE RESET DO BANCO (Atualizada) ---
@app.route('/setup-banco')
def setup_banco():
    try:
        # Apaga as tabelas velhas (com coluna pequena) e cria as novas (com coluna grande)
        db.drop_all()
        db.create_all()
        return "Banco RESETADO com sucesso! Tabelas novas criadas. Agora vá para /criar-admin"
    except Exception as e:
        return f"Erro ao resetar banco: {str(e)}"

@app.route('/criar-admin')
def criar_admin():
    try:
        if User.query.filter_by(username='admin').first():
            return "Admin já existe!"
        
        novo_admin = User(username='admin')
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