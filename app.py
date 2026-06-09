from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import url_for

from flask_login import LoginManager
from flask_login import login_user
from flask_login import logout_user
from flask_login import login_required
from flask_login import current_user

from flask_bcrypt import Bcrypt

from models import db
from models import Usuario

app = Flask(__name__)

app.config.from_pyfile("config.py")

db.init_app(app)

bcrypt = Bcrypt(app)


login_manager = LoginManager()

login_manager.init_app(app)

login_manager.login_view = "login"

login_manager.login_message = (
    "Debes iniciar sesión para acceder."
)

login_manager.login_message_category = "warning"


@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))


@app.route("/")
def inicio():

    return redirect(
        url_for("login")
    )


@app.route("/crear")
def crear():

    usuario = Usuario.query.filter_by(
        username="admin"
    ).first()

    if not usuario:

        password_hash = bcrypt.generate_password_hash(
            "123456"
        ).decode("utf-8")

        nuevo_usuario = Usuario(
            username="admin",
            password=password_hash
        )

        db.session.add(
            nuevo_usuario
        )

        db.session.commit()

        return """
        Usuario creado correctamente<br>
        Usuario: admin<br>
        Contraseña: 123456
        """

    return "El usuario admin ya existe"

@app.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        username = request.form.get(
            "username"
        )

        password = request.form.get(
            "password"
        )

        usuario = Usuario.query.filter_by(
            username=username
        ).first()

        if usuario and bcrypt.check_password_hash(
            usuario.password,
            password
        ):

            login_user(
                usuario
            )

            return redirect(
                url_for("dashboard")
            )

        return render_template(
            "login.html",
            error="Usuario o contraseña incorrectos"
        )

    return render_template(
        "login.html"
    )


@app.route("/registro", methods=["GET", "POST"])
def registro():

    if request.method == "POST":

        username = request.form.get(
            "username"
        )

        password = request.form.get(
            "password"
        )

        if len(password) < 6:

            return render_template(
                "registro.html",
                error="La contraseña debe tener al menos 6 caracteres"
            )

        existe = Usuario.query.filter_by(
            username=username
        ).first()

        if existe:

            return render_template(
                "registro.html",
                error="El usuario ya existe"
            )

        password_hash = bcrypt.generate_password_hash(
            password
        ).decode("utf-8")

        nuevo_usuario = Usuario(
            username=username,
            password=password_hash
        )

        db.session.add(
            nuevo_usuario
        )

        db.session.commit()

        return redirect(
            url_for("login")
        )

    return render_template(
        "registro.html"
    )


@app.route("/dashboard")
@login_required
def dashboard():

    return render_template(
        "dashboard.html",
        usuario=current_user
    )

@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect(
        url_for("login")
    )

@app.route("/perfil")
@login_required
def perfil():

    return render_template(
        "perfil.html",
        usuario=current_user
    )

@app.route(
    "/configuracion",
    methods=["POST"]
)
@login_required
def configuracion():

    actual = request.form["actual"]

    nueva = request.form["nueva"]

    if bcrypt.check_password_hash(
        current_user.password,
        actual
    ):

        current_user.password = (
            bcrypt.generate_password_hash(
                nueva
            ).decode("utf-8")
        )

        db.session.commit()

    return redirect(
        url_for("dashboard")
    )

if __name__ == "__main__":

    with app.app_context():

        db.create_all()

    app.run(
        debug=True
    )