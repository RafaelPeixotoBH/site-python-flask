import os
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# --- CONFIGURAÇÃO INTELIGENTE DO BANCO ---
# 1. Tenta pegar o endereço do banco do ambiente (Render)
database_url = os.environ.get('DATABASE_URL')

# 2. Correção necessária para o Render (bug do "postgres://")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

# 3. Se não tiver URL (estamos no PC), usa SQLite local
app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///meu_banco.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- MODELO ---
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)

# Cria o banco
with app.app_context():
    db.create_all()

# --- ROTA (AQUI ESTÁ A CORREÇÃO DO ERRO 405) ---
@app.route('/', methods=['GET', 'POST']) 
def home():
    if request.method == 'POST':
        nome_form = request.form.get('nome')
        if nome_form:
            novo_usuario = Usuario(nome=nome_form)
            db.session.add(novo_usuario)
            db.session.commit()
        return redirect(url_for('home'))

    usuarios = Usuario.query.all()
    return render_template('index.html', usuarios=usuarios)
# --- ROTA DE EXCLUIR ---
@app.route('/delete/<int:id>')
def delete(id):
    usuario_para_deletar = Usuario.query.get_or_404(id)
    db.session.delete(usuario_para_deletar)
    db.session.commit()
    return redirect(url_for('home'))
if __name__ == '__main__':
    app.run(debug=True)