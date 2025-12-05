import os
import secrets
import qrcode
from xhtml2pdf import pisa
from io import BytesIO


from datetime import datetime, date, timedelta
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    url_for,
    redirect,
    flash,
    session,
    Blueprint,
    current_app,
    make_response,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func

from config import Config

print(generate_password_hash("admin123"))  # Para crear hash inicial de admin

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)

# ======================================
#           MODELOS / TABLAS
# ======================================


class Empleado(db.Model):
    __tablename__ = "empleados"
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    contraseña = db.Column(db.String(255))
    puesto = db.Column(db.String(100))
    activo = db.Column(db.Boolean, default=True)
    creado_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Token único para acceso vía QR
    token_acceso = db.Column(db.String(64), unique=True, index=True, nullable=False)

    asistencias = db.relationship("Asistencia", back_populates="empleado", lazy=True)
    alertas = db.relationship("Alerta", back_populates="empleado", lazy=True)
    qr_filename = db.Column(db.String(255), nullable=True)


class Admin(db.Model):
    __tablename__ = "admins"
    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(80), unique=True, nullable=False)
    contraseña = db.Column(db.String(255), nullable=False)
    creado_at = db.Column(db.DateTime, default=datetime.utcnow)


class Asistencia(db.Model):
    __tablename__ = "asistencia"
    id = db.Column(db.Integer, primary_key=True)
    empleado_id = db.Column(db.Integer, db.ForeignKey("empleados.id"), nullable=False)
    fecha = db.Column(db.Date, nullable=False, default=lambda: datetime.utcnow().date())
    hora = db.Column(db.Time, nullable=False, default=lambda: datetime.utcnow().time())
    ip_cliente = db.Column(db.String(45))
    metodo = db.Column(db.String(50), default="QR")
    creado_at = db.Column(db.DateTime, default=datetime.utcnow)

    empleado = db.relationship("Empleado", back_populates="asistencias")


class AlertaRegla(db.Model):
    __tablename__ = "alertas_reglas"

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)  # Ej: "Faltas consecutivas"
    tipo = db.Column(
        db.Enum(
            "FALTAS_CONSECUTIVAS",
            "MUCHAS_FALTAS_EN_RANGO",
            "DIAS_SIN_FALTAR",
            name="tipo_alerta_enum",
        ),
        nullable=False,
    )

    umbral_dias = db.Column(db.Integer)  # X días (30, 90, etc.)
    umbral_faltas = db.Column(db.Integer)  # X faltas (2, 3, 5, etc.)
    descripcion = db.Column(db.Text)
    nivel = db.Column(db.String(20), default="info")  # info / warning / critico
    activo = db.Column(db.Boolean, default=True)
    creado_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relación inversa: qué alertas se generaron con esta regla
    alertas = db.relationship("Alerta", back_populates="regla", lazy=True)


class Alerta(db.Model):
    __tablename__ = "alertas"
    id = db.Column(db.Integer, primary_key=True)

    empleado_id = db.Column(db.Integer, db.ForeignKey("empleados.id"), nullable=True)
    regla_id = db.Column(db.Integer, db.ForeignKey("alertas_reglas.id"), nullable=True)

    # Código de alerta (puede coincidir con el tipo de la regla)
    tipo = db.Column(db.String(100))  # Ej: 'FALTAS_CONSECUTIVAS'
    descripcion = db.Column(db.Text)
    nivel = db.Column(db.String(20))  # info / warning / critico

    generado_en = db.Column(db.DateTime, default=datetime.utcnow)
    leido = db.Column(db.Boolean, default=False)

    # Campos de contexto (para explicar por qué se disparó)
    periodo_inicio = db.Column(db.Date)  # desde cuándo se analizó
    periodo_fin = db.Column(db.Date)  # hasta cuándo
    valor_dias = db.Column(db.Integer)  # días de racha o ventana
    valor_faltas = db.Column(db.Integer)  # cuántas faltas se detectaron
    valor_asistencias = db.Column(
        db.Integer
    )  # cuántas asistencias (para racha sin faltar)

    empleado = db.relationship("Empleado", back_populates="alertas")
    regla = db.relationship("AlertaRegla", back_populates="alertas")


# ======================================
#           LOGIN / AUTH
# ======================================


def login_requerido(vista_func):
    @wraps(vista_func)
    def wrapper(*args, **kwargs):
        if "admin_id" not in session:
            flash("Debes iniciar sesión como administrador.", "warning")
            return redirect(url_for("login", next=request.path))
        return vista_func(*args, **kwargs)

    return wrapper


# ======================================
#           HELPERS
# ======================================


def generar_token_empleado():
    """
    Genera un token aleatorio, URL-safe, para identificar
    al empleado en el enlace del QR.
    """
    return secrets.token_urlsafe(24)  # ~32 caracteres visibles


@app.context_processor
def inject_alertas_no_leidas():
    try:
        count = Alerta.query.filter_by(leido=False).count()
    except Exception:
        count = 0
    return dict(alertas_no_leidas=count)


def calcular_historial_con_faltas(empleado_id, fecha_fin=None):
    """
    Regresa:
      - historial: lista de dicts con fecha, hora, metodo, ip_cliente, estado ('A' o 'F')
      - total_dias: días totales del periodo
      - total_faltas: cuántos días sin asistencia
    """
    qs = Asistencia.query.filter_by(empleado_id=empleado_id).order_by(
        Asistencia.fecha.asc()
    )
    asistencias = qs.all()

    if not asistencias:
        # Nunca ha registrado asistencia
        return [], 0, 0

    fecha_inicio = asistencias[0].fecha
    if fecha_fin is None:
        fecha_fin = date.today()

    # Mapa fecha -> lista de asistencias de ese día
    mapa_por_fecha = {}
    for a in asistencias:
        mapa_por_fecha.setdefault(a.fecha, []).append(a)

    historial = []
    total_faltas = 0

    dia = fecha_inicio
    while dia <= fecha_fin:
        registros_dia = mapa_por_fecha.get(dia)

        if registros_dia:
            # Hay una o varias asistencias este día
            for a in registros_dia:
                historial.append(
                    {
                        "fecha": dia,
                        "hora": a.hora,
                        "metodo": a.metodo,
                        "ip_cliente": a.ip_cliente,
                        "estado": "A",
                    }
                )
        else:
            # Día sin asistencia → falta
            historial.append(
                {
                    "fecha": dia,
                    "hora": None,
                    "metodo": None,
                    "ip_cliente": None,
                    "estado": "F",
                }
            )
            total_faltas += 1

        dia += timedelta(days=1)

    total_dias = (fecha_fin - fecha_inicio).days + 1

    return historial, total_dias, total_faltas


def procesar_alertas_empleado(empleado_id: int, fecha_fin: date | None = None):
    """
    Recalcula las alertas para un empleado en función de las reglas activas.
    No hace commit, deja que el que llama haga el db.session.commit().
    """
    if fecha_fin is None:
        fecha_fin = date.today()

    reglas = AlertaRegla.query.filter_by(activo=True).all()

    for regla in reglas:
        if regla.tipo == "FALTAS_CONSECUTIVAS":
            _evaluar_faltas_consecutivas(empleado_id, regla, fecha_fin)
        elif regla.tipo == "MUCHAS_FALTAS_EN_RANGO":
            _evaluar_muchas_faltas_en_rango(empleado_id, regla, fecha_fin)
        elif regla.tipo == "DIAS_SIN_FALTAR":
            _evaluar_racha_sin_faltar(empleado_id, regla, fecha_fin)


def _evaluar_faltas_consecutivas(empleado_id: int, regla: AlertaRegla, fecha_fin: date):
    """
    Regla: FALTAS_CONSECUTIVAS
    Dispara cuando el empleado tiene >= umbral_faltas días seguidos de 'F'
    hasta fecha_fin.
    """
    historial, total_dias, total_faltas = calcular_historial_con_faltas(
        empleado_id, fecha_fin
    )
    if not historial or not regla.umbral_faltas:
        return

    # Contar racha de faltas al final del historial
    racha = 0
    for dia in reversed(historial):
        if dia["fecha"] > fecha_fin:
            continue
        if dia["estado"] == "F":
            racha += 1
        else:
            break

    if racha < regla.umbral_faltas:
        return

    # Evitar duplicar alerta si ya existe para ese periodo_fin
    alerta_existente = Alerta.query.filter_by(
        empleado_id=empleado_id, regla_id=regla.id, periodo_fin=fecha_fin
    ).first()
    if alerta_existente:
        return

    periodo_inicio = historial[-racha]["fecha"]  # primer día de la racha de faltas

    alerta = Alerta(
        empleado_id=empleado_id,
        regla_id=regla.id,
        tipo=regla.tipo,
        descripcion=f"El empleado tiene {racha} faltas consecutivas hasta el día {fecha_fin}.",
        nivel=regla.nivel,
        periodo_inicio=periodo_inicio,
        periodo_fin=fecha_fin,
        valor_dias=racha,
        valor_faltas=racha,
    )
    db.session.add(alerta)


def _evaluar_muchas_faltas_en_rango(
    empleado_id: int, regla: AlertaRegla, fecha_fin: date
):
    """
    Regla: MUCHAS_FALTAS_EN_RANGO
    Ventana de 'umbral_dias' días hacia atrás desde fecha_fin.
    Dispara si faltas >= umbral_faltas.
    """
    if not regla.umbral_dias or not regla.umbral_faltas:
        return

    historial, total_dias, total_faltas = calcular_historial_con_faltas(
        empleado_id, fecha_fin
    )
    if not historial:
        return

    ventana_dias = regla.umbral_dias
    periodo_inicio = fecha_fin - timedelta(days=ventana_dias - 1)

    faltas_en_rango = sum(
        1
        for d in historial
        if periodo_inicio <= d["fecha"] <= fecha_fin and d["estado"] == "F"
    )

    if faltas_en_rango < regla.umbral_faltas:
        return

    # Evitar duplicado
    alerta_existente = Alerta.query.filter_by(
        empleado_id=empleado_id,
        regla_id=regla.id,
        periodo_inicio=periodo_inicio,
        periodo_fin=fecha_fin,
    ).first()
    if alerta_existente:
        return

    alerta = Alerta(
        empleado_id=empleado_id,
        regla_id=regla.id,
        tipo=regla.tipo,
        descripcion=(
            f"El empleado acumula {faltas_en_rango} faltas entre "
            f"{periodo_inicio} y {fecha_fin}."
        ),
        nivel=regla.nivel,
        periodo_inicio=periodo_inicio,
        periodo_fin=fecha_fin,
        valor_dias=ventana_dias,
        valor_faltas=faltas_en_rango,
    )
    db.session.add(alerta)


def _evaluar_racha_sin_faltar(empleado_id: int, regla: AlertaRegla, fecha_fin: date):
    """
    Regla: DIAS_SIN_FALTAR
    Dispara cuando el empleado lleva 'umbral_dias' o más días seguidos sin faltas (solo 'A').
    """
    if not regla.umbral_dias:
        return

    historial, total_dias, total_faltas = calcular_historial_con_faltas(
        empleado_id, fecha_fin
    )
    if not historial:
        return

    # Contar racha de asistencias (A) al final del historial
    racha = 0
    for dia in reversed(historial):
        if dia["fecha"] > fecha_fin:
            continue
        if dia["estado"] == "A":
            racha += 1
        else:
            break

    if racha < regla.umbral_dias:
        return

    periodo_inicio = fecha_fin - timedelta(days=racha - 1)

    alerta_existente = Alerta.query.filter_by(
        empleado_id=empleado_id,
        regla_id=regla.id,
        periodo_inicio=periodo_inicio,
        periodo_fin=fecha_fin,
    ).first()
    if alerta_existente:
        return

    alerta = Alerta(
        empleado_id=empleado_id,
        regla_id=regla.id,
        tipo=regla.tipo,
        descripcion=(
            f"El empleado lleva {racha} días consecutivos sin registrar faltas "
            f"hasta el {fecha_fin}."
        ),
        nivel=regla.nivel,
        periodo_inicio=periodo_inicio,
        periodo_fin=fecha_fin,
        valor_dias=racha,
        valor_asistencias=racha,
    )
    db.session.add(alerta)


def procesar_alertas_todos(fecha_fin: date | None = None):
    """
    Útil para probar: recalcula alertas para TODOS los empleados activos.
    Llamable desde flask shell.
    """
    if fecha_fin is None:
        fecha_fin = date.today()

    empleados = Empleado.query.filter_by(activo=True).all()
    for emp in empleados:
        procesar_alertas_empleado(emp.id, fecha_fin)


def generar_insights_dashboard_ia(dias_analisis=30, limite_empleados=3):
    hoy = date.today()
    fecha_inicio = hoy - timedelta(days=dias_analisis)
    insights = []

    # 0) Detectar última asistencia registrada en TODO el sistema
    ultima_asistencia = db.session.query(func.max(Asistencia.fecha)).scalar()

    if ultima_asistencia is None:
        insights.append(
            {
                "tipo": "sistema",
                "titulo": "Sin registros de asistencia",
                "detalle": (
                    "La IA no encuentra registros de asistencia. "
                    "Es posible que el sistema sea reciente o que aún no se haya utilizado "
                    "para registrar entradas del personal."
                ),
            }
        )
    else:
        dias_sin_registro = (hoy - ultima_asistencia).days
        if dias_sin_registro >= 1:
            texto_gravedad = "ligera"
            if dias_sin_registro >= 7:
                texto_gravedad = "crítica"
            elif dias_sin_registro >= 3:
                texto_gravedad = "moderada"

            insights.append(
                {
                    "tipo": "sistema",
                    "titulo": "Ausencia de registros recientes",
                    "detalle": (
                        f"La IA detecta que no se han registrado asistencias desde el día "
                        f"{ultima_asistencia.isoformat()} (hace {dias_sin_registro} días). "
                        "Esto puede indicar periodo de descanso general, cierre temporal del negocio "
                        "o falta de uso del sistema. Se recomienda verificar esta situación "
                        f"debido a su relevancia {texto_gravedad}."
                    ),
                }
            )

    # 1) Empleados con más alertas críticas / de faltas en el periodo
    subq_alertas = (
        db.session.query(
            Empleado.id.label("emp_id"),
            Empleado.nombre.label("nombre"),
            func.count(Alerta.id).label("total_alertas"),
        )
        .join(Alerta, Alerta.empleado_id == Empleado.id)
        .filter(
            Alerta.generado_en >= fecha_inicio,
            Alerta.generado_en <= hoy,
            Alerta.nivel.in_(["warning", "critico"]),
        )
        .group_by(Empleado.id, Empleado.nombre)
        .order_by(func.count(Alerta.id).desc())
        .limit(limite_empleados)
        .all()
    )

    if subq_alertas:
        for rank, row in enumerate(subq_alertas, start=1):
            insights.append(
                {
                    "tipo": "riesgo",
                    "titulo": f"Empleado en riesgo #{rank}: {row.nombre}",
                    "detalle": (
                        f"La IA detecta que {row.nombre} ha acumulado {row.total_alertas} "
                        f"alertas de asistencia en los últimos {dias_analisis} días. "
                        "Considerando un día de descanso semanal, el modelo sugiere "
                        "dar seguimiento cercano para evitar mayores incidencias."
                    ),
                }
            )
    else:
        insights.append(
            {
                "tipo": "info",
                "titulo": "Sin empleados en riesgo crítico",
                "detalle": (
                    f"La IA no identifica empleados con alertas críticas o de advertencia "
                    f"en los últimos {dias_analisis} días, considerando el día de descanso semanal."
                ),
            }
        )

    # 2) Empleados con mejor asistencia (más registros en el periodo)
    subq_asistencias = (
        db.session.query(
            Empleado.id.label("emp_id"),
            Empleado.nombre.label("nombre"),
            func.count(Asistencia.id).label("total_asistencias"),
        )
        .join(Asistencia, Asistencia.empleado_id == Empleado.id)
        .filter(
            Asistencia.fecha >= fecha_inicio,
            Asistencia.fecha <= hoy,
            Empleado.activo.is_(True),
        )
        .group_by(Empleado.id, Empleado.nombre)
        .order_by(func.count(Asistencia.id).desc())
        .limit(limite_empleados)
        .all()
    )

    if subq_asistencias:
        for rank, row in enumerate(subq_asistencias, start=1):
            insights.append(
                {
                    "tipo": "positivo",
                    "titulo": f"Mejor asistencia #{rank}: {row.nombre}",
                    "detalle": (
                        f"Según el modelo de IA, {row.nombre} registra {row.total_asistencias} "
                        f"asistencias en los últimos {dias_analisis} días, manteniendo un patrón "
                        "constante de asistencia aun considerando su día de descanso semanal."
                    ),
                }
            )

    # 3) Estimar 'día de descanso' general (día con menos asistencias históricas)
    dia_menos_actividad = (
        db.session.query(
            func.dayofweek(Asistencia.fecha).label("dow"),
            func.count(Asistencia.id).label("total"),
        )
        .group_by("dow")
        .order_by(func.count(Asistencia.id).asc())
        .first()
    )

    if dia_menos_actividad:
        dow = dia_menos_actividad.dow  # 1..7 (MySQL)
        nombres_dias = {
            1: "domingo",
            2: "lunes",
            3: "martes",
            4: "miércoles",
            5: "jueves",
            6: "viernes",
            7: "sábado",
        }
        nombre_dia = nombres_dias.get(dow, "un día específico de la semana")
        insights.append(
            {
                "tipo": "descanso",
                "titulo": "Día de descanso estimado por IA",
                "detalle": (
                    f"La IA identifica que el día con menor número de asistencias históricas "
                    f"es el {nombre_dia}. Esto sugiere que, para buena parte del personal, "
                    "ese día funciona como descanso semanal. Las evaluaciones de riesgo consideran "
                    "este patrón para evitar falsas alarmas."
                ),
            }
        )

    # 4) Días "inventario": fechas donde hay más de 3 registros (global)
    dias_inventario = (
        db.session.query(
            Asistencia.fecha.label("fecha"), func.count(Asistencia.id).label("total")
        )
        .group_by(Asistencia.fecha)
        .having(func.count(Asistencia.id) > 3)
        .order_by(Asistencia.fecha.desc())
        .limit(6)
        .all()
    )

    if dias_inventario:
        ult_fecha = dias_inventario[0].fecha
        insights.append(
            {
                "tipo": "inventario",
                "titulo": "Días de alta actividad detectados",
                "detalle": (
                    "La IA detecta fechas con más de tres registros de asistencia por jornada, "
                    "interpretándolos como posibles días de inventario o actividades especiales "
                    "que ocurren aproximadamente una vez al mes. "
                    f"La última fecha detectada fue el {ult_fecha.isoformat()}."
                ),
            }
        )

    # 5) Empleados que NO han llegado hoy (comparando activos vs asistencia del día)
    total_activos = (
        db.session.query(func.count(Empleado.id))
        .filter(Empleado.activo.is_(True))
        .scalar()
    ) or 0

    presentes_hoy_ids_subq = (
        db.session.query(Asistencia.empleado_id)
        .filter(Asistencia.fecha == hoy)
        .distinct()
        .subquery()
    )

    empleados_faltantes_hoy = Empleado.query.filter(
        Empleado.activo.is_(True), ~Empleado.id.in_(presentes_hoy_ids_subq)
    ).all()

    total_presentes_hoy = total_activos - len(empleados_faltantes_hoy)
    if total_activos > 0:
        porcentaje = round((total_presentes_hoy / total_activos) * 100, 1)
    else:
        porcentaje = 0.0

    if empleados_faltantes_hoy:
        nombres_preview = ", ".join(e.nombre for e in empleados_faltantes_hoy[:5])
        if len(empleados_faltantes_hoy) > 5:
            nombres_preview += " y otros…"

        insights.append(
            {
                "tipo": "hoy",
                "titulo": "Asistencia en tiempo real",
                "detalle": (
                    f"Para el día de hoy, la IA calcula que ha llegado el {porcentaje}% "
                    f"del personal activo ({total_presentes_hoy} de {total_activos}). "
                    f"Los siguientes empleados aún no registran asistencia: {nombres_preview}."
                ),
            }
        )
    else:
        if total_activos > 0:
            insights.append(
                {
                    "tipo": "hoy",
                    "titulo": "Asistencia completa hoy",
                    "detalle": (
                        f"La IA confirma que el 100% del personal activo ({total_activos} empleados) "
                        "ya registró asistencia el día de hoy."
                    ),
                }
            )

    # 6) Empleados con 3+ faltas (usando alertas existentes)
    faltas_criticas = (
        db.session.query(
            Empleado.id.label("emp_id"),
            Empleado.nombre.label("nombre"),
            func.coalesce(func.sum(Alerta.valor_faltas), 0).label("total_faltas"),
        )
        .join(Alerta, Alerta.empleado_id == Empleado.id)
        .filter(
            Alerta.generado_en >= fecha_inicio,
            Alerta.generado_en <= hoy,
            Alerta.tipo.in_(["FALTAS_CONSECUTIVAS", "MUCHAS_FALTAS_EN_RANGO"]),
        )
        .group_by(Empleado.id, Empleado.nombre)
        .having(func.coalesce(func.sum(Alerta.valor_faltas), 0) >= 3)
        .order_by(func.coalesce(func.sum(Alerta.valor_faltas), 0).desc())
        .limit(limite_empleados)
        .all()
    )

    for row in faltas_criticas:
        # Máxima racha consecutiva según alertas
        max_racha = (
            db.session.query(func.max(Alerta.valor_faltas))
            .filter(
                Alerta.empleado_id == row.emp_id,
                Alerta.tipo == "FALTAS_CONSECUTIVAS",
                Alerta.generado_en >= fecha_inicio,
                Alerta.generado_en <= hoy,
            )
            .scalar()
        ) or 0

        insights.append(
            {
                "tipo": "faltas",
                "titulo": f"Faltas relevantes: {row.nombre}",
                "detalle": (
                    f"La IA identifica que {row.nombre} acumula al menos {int(row.total_faltas)} faltas "
                    f"registradas en el periodo analizado. "
                    + (
                        f"La racha máxima consecutiva detectada es de {int(max_racha)} días sin asistir. "
                        if max_racha > 0
                        else ""
                    )
                    + "Se recomienda revisar su historial detallado para confirmar patrones "
                    "de ausencia en días específicos."
                ),
            }
        )

    # 7) Resumen general para vender el humo IA
    total_alertas_periodo = (
        db.session.query(func.count(Alerta.id))
        .filter(Alerta.generado_en >= fecha_inicio, Alerta.generado_en <= hoy)
        .scalar()
    ) or 0

    total_asistencias_periodo = (
        db.session.query(func.count(Asistencia.id))
        .filter(Asistencia.fecha >= fecha_inicio, Asistencia.fecha <= hoy)
        .scalar()
    ) or 0

    insights.append(
        {
            "tipo": "resumen",
            "titulo": "Resumen inteligente de asistencia",
            "detalle": (
                f"En los últimos {dias_analisis} días, la IA ha analizado "
                f"{total_asistencias_periodo} registros de asistencia y "
                f"{total_alertas_periodo} alertas generadas, "
                "identificando patrones de riesgo, reconocimiento al personal más constante, "
                "días de descanso y jornadas especiales como inventarios."
            ),
        }
    )

    return insights


# ======================================
#               RUTAS AUTH
# ======================================


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form.get("usuario")
        contraseña = request.form.get("contraseña")

        admin = Admin.query.filter_by(usuario=usuario).first()

        if admin and check_password_hash(admin.contraseña, contraseña):
            session["admin_id"] = admin.id
            session["admin_usuario"] = admin.usuario
            flash("Has iniciado sesión correctamente.", "success")

            next_url = request.args.get("next")
            return redirect(next_url or url_for("dashboard"))
        else:
            flash("Usuario o contraseña incorrectos.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Has cerrado sesión.", "info")
    return redirect(url_for("login"))


# ======================================
#               RUTAS ADMIN
# ======================================


@app.route("/")
def index():
    # Si ya hay sesión de admin, lo mando al dashboard;
    # si no, al login.
    if "admin_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_requerido
def dashboard():
    hoy = date.today()

    # 1) Empleados presentes hoy (evitar duplicados si un empleado marca varias veces)
    empleados_presentes = (
        db.session.query(func.count(func.distinct(Asistencia.empleado_id)))
        .filter(Asistencia.fecha == hoy)
        .scalar()
        or 0
    )

    # 2) Total de empleados activos
    total_activos = Empleado.query.filter(Empleado.activo.is_(True)).count()

    # 3) Faltas del día = empleados activos - presentes
    faltas_dia = max(total_activos - empleados_presentes, 0)

    # 4) Alertas generadas hoy (todas, leídas o no)
    alertas_hoy = (
        db.session.query(func.count(Alerta.id))
        .filter(func.date(Alerta.generado_en) == hoy)
        .scalar()
        or 0
    )

    insights_ia = generar_insights_dashboard_ia(dias_analisis=30, limite_empleados=3)

    return render_template(
        "dashboard.html",
        insights_ia=insights_ia,
        empleados_presentes=empleados_presentes,
        faltas_dia=faltas_dia,
        alertas_hoy=alertas_hoy,
    )


@app.route("/asistencias")
@login_requerido
def asistencias():
    registros = (
        db.session.query(Asistencia, Empleado)
        .join(Empleado, Asistencia.empleado_id == Empleado.id)
        .order_by(Asistencia.fecha.desc(), Asistencia.hora.desc())
        .all()
    )

    hoy = date.today()

    grupos = []
    fecha_actual = None

    for asistencia, empleado in registros:
        if asistencia.fecha != fecha_actual:
            grupos.append({"fecha": asistencia.fecha, "registros": []})
            fecha_actual = asistencia.fecha

        grupos[-1]["registros"].append({"asistencia": asistencia, "empleado": empleado})

    return render_template("asistencias.html", grupos=grupos, hoy=hoy)


@app.route("/empleados", methods=["GET", "POST"])
@login_requerido
def empleados():
    if request.method == "POST":
        nombre = request.form.get("nombre")
        puesto = request.form.get("puesto")
        contraseña = request.form.get("password")

        nuevo_empleado = Empleado(
            nombre=nombre,
            puesto=puesto,
            contraseña=contraseña,
            token_acceso=generar_token_empleado(),
        )

        db.session.add(nuevo_empleado)
        db.session.commit()  # obtener ID y token_acceso

        # URL relativa usando el TOKEN
        ruta_relativa = url_for(
            "asistencia_empleado_token", token=nuevo_empleado.token_acceso
        )

        # BASE_URL fija para la red local; si no está, usamos host actual
        base_url = app.config.get("BASE_URL", request.host_url.rstrip("/"))

        # URL completa
        qr_url = f"{base_url}{ruta_relativa}"
        print("URL para QR:", qr_url)

        # Generar el código QR
        qr_img = qrcode.make(qr_url)

        qr_folder = os.path.join(app.static_folder, "qr")
        os.makedirs(qr_folder, exist_ok=True)

        filename = f"empleado_{nuevo_empleado.id}.png"
        filepath = os.path.join(qr_folder, filename)

        qr_img.save(filepath)

        nuevo_empleado.qr_filename = filename
        db.session.commit()

    # 🔎 Filtros por estado
    estado = request.args.get("estado", "activos")  # activos / todos / baja

    query = Empleado.query
    if estado == "activos":
        query = query.filter_by(activo=True)
    elif estado == "baja":
        query = query.filter_by(activo=False)
    # si es "todos", no filtramos

    lista_empleados = query.order_by(Empleado.id).all()
    return render_template("empleados.html", empleados=lista_empleados, estado=estado)


@app.route("/empleados/<int:emp_id>/baja", methods=["POST"])
@login_requerido
def baja_empleado(emp_id):
    emp = Empleado.query.get_or_404(emp_id)
    emp.activo = False
    db.session.commit()

    estado = request.args.get("estado", "activos")
    return redirect(url_for("empleados", estado=estado))


@app.route("/empleados/<int:emp_id>/activar", methods=["POST"])
@login_requerido
def activar_empleado(emp_id):
    emp = Empleado.query.get_or_404(emp_id)
    emp.activo = True
    db.session.commit()

    estado = request.args.get("estado", "activos")
    return redirect(url_for("empleados", estado=estado))


@app.route("/empleados/<int:emp_id>/regenerar_qr", methods=["POST"])
@login_requerido
def regenerar_qr_empleado(emp_id):
    emp = Empleado.query.get_or_404(emp_id)

    # Usamos el MISMO token, solo cambiamos la URL base (por IP nueva)
    ruta_relativa = url_for("asistencia_empleado_token", token=emp.token_acceso)

    base_url = app.config.get("BASE_URL", request.host_url.rstrip("/"))
    qr_url = f"{base_url}{ruta_relativa}"
    print("Regenerando QR para:", qr_url)

    qr_img = qrcode.make(qr_url)

    qr_folder = os.path.join(app.static_folder, "qr")
    os.makedirs(qr_folder, exist_ok=True)

    filename = f"empleado_{emp.id}.png"
    filepath = os.path.join(qr_folder, filename)

    qr_img.save(filepath)

    emp.qr_filename = filename
    db.session.commit()

    estado = request.args.get("estado", "activos")
    return redirect(url_for("empleados", estado=estado))


@app.route("/alertas")
@login_requerido
def alertas():
    # 🔥 1) Recalcular alertas para TODOS antes de mostrar la pantalla
    # Usamos fecha de corte = ayer, para que el día de hoy aún no cuente
    fecha_corte = date.today() - timedelta(days=1)
    procesar_alertas_todos(fecha_fin=fecha_corte)
    db.session.commit()

    # 2) Filtros opcionales por query string
    tipo = request.args.get("tipo")  # ej: FALTAS_CONSECUTIVAS
    nivel = request.args.get("nivel")  # info / warning / critico
    estado = request.args.get("estado")  # todas / leidas / no_leidas

    query = Alerta.query.join(Empleado)

    if tipo:
        query = query.filter(Alerta.tipo == tipo)

    if nivel:
        query = query.filter(Alerta.nivel == nivel)

    if estado == "leidas":
        query = query.filter(Alerta.leido.is_(True))
    elif estado == "no_leidas":
        query = query.filter(Alerta.leido.is_(False))

    alertas = query.order_by(Alerta.generado_en.desc()).all()

    # Para llenar los combos de filtro
    tipos = [t[0] for t in db.session.query(Alerta.tipo).distinct().all() if t[0]]
    niveles = [n[0] for n in db.session.query(Alerta.nivel).distinct().all() if n[0]]

    return render_template(
        "alertas.html",
        alertas=alertas,
        tipos=tipos,
        niveles=niveles,
        tipo_seleccionado=tipo,
        nivel_seleccionado=nivel,
        estado_seleccionado=estado or "todas",
    )


@app.post("/alertas/<int:alerta_id>/toggle-leido")
@login_requerido
def toggle_alerta_leido(alerta_id):
    alerta = Alerta.query.get_or_404(alerta_id)
    alerta.leido = not alerta.leido
    db.session.commit()
    flash("Estado de la alerta actualizado.", "success")
    return redirect(url_for("alertas"))


@app.route("/alertas/reglas", methods=["GET", "POST"])
@login_requerido
def reglas_alertas():
    if request.method == "POST":
        regla_id = request.form.get("id")
        regla = AlertaRegla.query.get_or_404(regla_id)

        regla.umbral_dias = request.form.get("umbral_dias") or None
        if regla.umbral_dias is not None:
            regla.umbral_dias = int(regla.umbral_dias)

        regla.umbral_faltas = request.form.get("umbral_faltas") or None
        if regla.umbral_faltas is not None:
            regla.umbral_faltas = int(regla.umbral_faltas)

        regla.nivel = request.form.get("nivel") or regla.nivel
        regla.activo = True if request.form.get("activo") == "1" else False

        db.session.commit()
        flash("Regla actualizada correctamente.", "success")
        return redirect(url_for("reglas_alertas"))

    reglas = AlertaRegla.query.order_by(AlertaRegla.tipo, AlertaRegla.id).all()
    return render_template("reglas_alertas.html", reglas=reglas)


bp = Blueprint("reportes", __name__)


@bp.route("/reportes", methods=["GET"])
def reportes():
    empleados = Empleado.query.order_by(Empleado.nombre).all()

    empleado = None
    historial = []
    total_dias = 0
    total_faltas = 0
    alertas = []

    empleado_id = request.args.get("empleado_id", type=int)

    if empleado_id:
        empleado = Empleado.query.get_or_404(empleado_id)
        historial, total_dias, total_faltas = calcular_historial_con_faltas(empleado.id)
        alertas = (
            Alerta.query.filter_by(empleado_id=empleado.id)
            .order_by(Alerta.generado_en.desc())
            .all()
        )

    return render_template(
        "reportes.html",
        empleados=empleados,
        empleado=empleado,
        historial=historial,
        total_dias=total_dias,
        total_faltas=total_faltas,
        alertas=alertas,
        fecha_reporte=date.today(),
    )


@bp.route("/reportes/<int:empleado_id>/pdf", methods=["GET"])
def reporte_empleado_pdf(empleado_id):
    empleado = Empleado.query.get_or_404(empleado_id)
    historial, total_dias, total_faltas = calcular_historial_con_faltas(empleado.id)
    alertas = (
        Alerta.query.filter_by(empleado_id=empleado.id)
        .order_by(Alerta.generado_en.desc())
        .all()
    )
    fecha_reporte = date.today()

    # 1) Renderizamos el HTML como siempre
    html_str = render_template(
        "reporte_empleado_pdf.html",
        empleado=empleado,
        historial=historial,
        total_dias=total_dias,
        total_faltas=total_faltas,
        alertas=alertas,
        fecha_reporte=fecha_reporte,
    )

    # 2) Convertimos HTML -> PDF con xhtml2pdf
    result = BytesIO()
    pisa_status = pisa.CreatePDF(src=html_str, dest=result, encoding="utf-8")

    if pisa_status.err:
        # Por si algo sale mal, mostramos mensaje
        return "Error generando el PDF", 500

    pdf = result.getvalue()

    # 3) Regresamos el PDF como respuesta HTTP
    response = make_response(pdf)
    response.headers["Content-Type"] = "application/pdf"
    filename = f"reporte_{empleado.nombre}_{fecha_reporte.isoformat()}.pdf".replace(
        " ", "_"
    )
    response.headers["Content-Disposition"] = f"inline; filename={filename}"
    return response


app.register_blueprint(bp)


@app.route("/configuracion", methods=["GET", "POST"])
@login_requerido
def configuracion():
    # Admin logueado actual
    admin_actual = None
    if "admin_usuario" in session:
        admin_actual = Admin.query.filter_by(usuario=session["admin_usuario"]).first()

    if request.method == "POST":
        accion = request.form.get("accion")

        # 👉 Cambiar contraseña del admin actual
        if accion == "cambiar_password" and admin_actual:
            nueva_contraseña = request.form.get("password_nueva")

            if nueva_contraseña:
                admin_actual.contraseña = generate_password_hash(nueva_contraseña)
                db.session.commit()

        # 👉 Crear nuevo admin
        elif accion == "nuevo_admin":
            nuevo_usuario = request.form.get("usuario_nuevo")
            nueva_contraseña = request.form.get("password_nuevo")

            if nuevo_usuario and nueva_contraseña:
                nuevo_admin = Admin(
                    usuario=nuevo_usuario,
                    contraseña=generate_password_hash(nueva_contraseña),
                )
                db.session.add(nuevo_admin)
                db.session.commit()

        return redirect(url_for("configuracion"))

    # GET → Mostrar datos
    admins = Admin.query.order_by(Admin.creado_at.desc()).all()

    return render_template(
        "configuracion.html",
        admin_actual=admin_actual,
        admins=admins,
    )


# ======================================
#        RUTA PÚBLICA (EMPLEADOS)
# ======================================


@app.route("/asistencia/t/<string:token>", methods=["GET", "POST"])
@login_requerido
def asistencia_empleado_token(token):
    """
    Página que abre el empleado escaneando su QR.
    Usa el token para buscar al empleado y registrar la asistencia.
    """
    # Buscar empleado por token y que esté activo
    empleado = Empleado.query.filter_by(token_acceso=token, activo=True).first_or_404()

    mensaje = None

    if request.method == "POST":
        hoy = date.today()

        # Evitar doble asistencia el mismo día
        ya_hay = Asistencia.query.filter_by(empleado_id=empleado.id, fecha=hoy).first()

        if ya_hay:
            mensaje = f"Ya existe una asistencia registrada hoy para {empleado.nombre}."
        else:
            nueva = Asistencia(
                empleado_id=empleado.id, metodo="QR", ip_cliente=request.remote_addr
            )
            db.session.add(nueva)
            db.session.commit()

            mensaje = (
                f"Asistencia registrada para {empleado.nombre} "
                f"a las {datetime.utcnow().strftime('%H:%M:%S')} (UTC)"
            )

    return render_template(
        "asistencia_empleado.html", empleado=empleado, mensaje=mensaje
    )


# ======================================
#             MAIN
# ======================================

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
