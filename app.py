import os
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# --- CONFIGURAÇÃO DO BANCO ---
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'meu_banco.db')
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

if __name__ == '__main__':
    app.run(debug=True)