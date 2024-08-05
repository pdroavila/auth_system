from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta
import uuid
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha = db.Column(db.String(255), nullable=False)
    reset_token = db.Column(db.String(100), unique=True, nullable=True)
    reset_token_expiracao = db.Column(db.DateTime, nullable=True)
    tentativas = db.Column(db.Integer, default=0)
    ultima_tentativa = db.Column(db.DateTime, nullable=True)
    
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        usuario = request.form['usuario']
        email = request.form['email']
        senha = request.form['senha']
        hashed_senha = generate_password_hash(senha, method='pbkdf2:sha256')
        
        new_user = User(usuario=usuario, email=email, senha=hashed_senha)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registro realizado com sucesso!', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('O email ou nome de usuário já está em uso. Por favor, tente outro.', 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        senha = request.form['senha']
        
        user = User.query.filter_by(usuario=usuario).first()
        if user and check_password_hash(user.senha, senha):
            session['user_id'] = user.id
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Usuário ou senha inválidos.', 'error')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', usuario=user.usuario)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('home'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            # verifica se o usuário está bloqueado
            if user.tentativas >= 5 and user.ultima_tentativa:
                time_diff = datetime.utcnow() - user.ultima_tentativa
                if time_diff < timedelta(minutes=15):
                    flash('Muitas tentativas. Tente novamente em 15 minutos.', 'error')
                    return redirect(url_for('login'))
                else:
                    # reseta o contador após 15 minutos
                    user.tentativas = 0
                    user.ultima_tentativa = None
            
            token = str(uuid.uuid4())
            user.reset_token = token
            user.reset_token_expiracao = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            
            reset_link = url_for('reset_password', token=token, _external=True)
            send_reset_email(user.email, reset_link)
        
        flash('Se o e-mail estiver registrado, você receberá um link para redefinir sua senha.', 'info')
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    
    if user is None or (user.reset_token_expiracao is not None and user.reset_token_expiracao < datetime.utcnow()):   
        # incrementa o contador de tentativas falhas
        if user:
            user.tentativas += 1
            user.ultima_tentativa = datetime.utcnow()
            db.session.commit()
        
        flash('O link de redefinição de senha é inválido ou expirou.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_senha = request.form['senha']
        user.senha = generate_password_hash(new_senha, method='pbkdf2:sha256')
        user.reset_token = None
        user.reset_token_expiracao = None
        user.tentativas = 0  # Reseta o contador após sucesso
        user.ultima_tentativa = None
        db.session.commit()
        
        flash('Sua senha foi redefinida com sucesso!', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

def send_reset_email(email, reset_link):
    smtp_server = os.getenv('MAIL_SERVER')
    smtp_port = os.getenv('MAIL_PORT')
    sender_email = os.getenv('MAIL_USERNAME')
    sender_senha = os.getenv('MAIL_PASSWORD')

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = email
    message["Subject"] = "Redefinição de senha"

    # corpo email
    body = f"""
    Você solicitou a redefinição de sua senha.
    Clique no link abaixo para redefinir sua senha:
    {reset_link}
    
    Este link expirará em 1 hora.
    Se você não solicitou esta redefinição, ignore este e-mail.
    """
    message.attach(MIMEText(body, "plain"))

    # envio do email
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(sender_email, sender_senha)
        server.send_message(message)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)