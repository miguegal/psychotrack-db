-- ============================================================================
-- PROYECTO: Plataforma de Seguimiento Psicológico y Evaluación Terapéutica
--           (PsychoTrack DB)
-- MATERIA: Administración de Bases de Datos - CUCEI, Universidad de Guadalajara
-- AUTOR: Galvez Arceo Miguel Angel (Código: 220537132)
-- ARCHIVO: 01_ddl_esquema_tablas.sql
-- DESCRIPCIÓN: Creación de extensiones, tablas normalizadas (3FN), restricciones
--              semánticas (CHECK), integridad referencial (ON DELETE RESTRICT)
--              e indexación estratégica B-Tree.
-- ============================================================================

-- Habilitar extensión criptográfica nativa para cifrado a nivel de columna (AES-256) y SHA-256
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================================
-- 1. ENTIDAD: Terapeuta
-- Cédula profesional, especialidad clínica, credenciales con Salt + SHA-256 y rol RBAC
-- ============================================================================
CREATE TABLE IF NOT EXISTS terapeuta (
    id_terapeuta VARCHAR(25) PRIMARY KEY,            -- Ej. 'TER-84920-GDL'
    cedula_profesional VARCHAR(20) UNIQUE NOT NULL,  -- Ej. '84920'
    nombre_completo VARCHAR(120) NOT NULL,
    especialidad_clinica VARCHAR(100) NOT NULL,      -- Ej. 'Terapia Cognitivo-Conductual'
    correo_institucional VARCHAR(120) UNIQUE NOT NULL,
    usuario_db VARCHAR(50) UNIQUE NOT NULL,          -- Vinculado con CURRENT_USER / sesión RLS
    rol_operativo VARCHAR(30) NOT NULL CHECK (
        rol_operativo IN ('rol_terapeuta', 'rol_supervisor', 'rol_recepcion', 'rol_auditor', 'rol_dba_admin', 'rol_paciente')
    ),
    password_salt VARCHAR(64) NOT NULL,              -- Salt aleatorio de longitud fija
    password_hash VARCHAR(64) NOT NULL,              -- Hash determinista SHA-256(password || salt)
    estado_activo BOOLEAN NOT NULL DEFAULT TRUE,
    fecha_registro TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 2. ENTIDAD: Paciente
-- Identificador único, datos demográficos indispensables, estado clínico y contacto
-- ============================================================================
CREATE TABLE IF NOT EXISTS paciente (
    id_paciente VARCHAR(20) PRIMARY KEY,             -- Ej. 'PAC-2026-015'
    iniciales_referencia VARCHAR(20) NOT NULL,       -- Ej. 'C.R.M.' (Privacidad en listados)
    nombre_completo VARCHAR(120) NOT NULL,
    edad INTEGER NOT NULL CHECK (edad >= 5 AND edad <= 110),
    ocupacion_escolaridad VARCHAR(80) NOT NULL,      -- Ej. 'Estudiante', 'Posgrado'
    telefono_contacto VARCHAR(25) NOT NULL,
    contacto_emergencia_nombre VARCHAR(120) NOT NULL,
    contacto_emergencia_telefono VARCHAR(25) NOT NULL,
    fecha_ingreso DATE NOT NULL DEFAULT CURRENT_DATE,
    estado_clinico_general VARCHAR(30) NOT NULL DEFAULT 'Activo' CHECK (
        estado_clinico_general IN ('Activo', 'En Pausa', 'Alta Terapéutica', 'Remitido Urgencias', 'Deserción')
    ),
    password_salt VARCHAR(64) NOT NULL DEFAULT 'salt_pac_2026',
    password_hash VARCHAR(64) NOT NULL DEFAULT '',
    id_terapeuta_asignado VARCHAR(25) NOT NULL REFERENCES terapeuta(id_terapeuta) ON DELETE RESTRICT
);

-- ============================================================================
-- 3. ENTIDAD: DiagnosticoDSM
-- Catálogo estandarizado de trastornos codificados conforme al DSM-5 / CIE-11
-- ============================================================================
CREATE TABLE IF NOT EXISTS diagnostico_dsm (
    codigo_diagnostico VARCHAR(15) PRIMARY KEY,      -- Ej. 'F41.1', 'F32.2', 'F43.2'
    sistema_clasificacion VARCHAR(20) NOT NULL DEFAULT 'DSM-5 / CIE-10' CHECK (
        sistema_clasificacion IN ('DSM-5', 'CIE-11', 'DSM-5 / CIE-10', 'DSM-5 / CIE-11')
    ),
    nombre_trastorno VARCHAR(150) NOT NULL,
    descripcion_clinica TEXT NOT NULL,
    nivel_gravedad_base VARCHAR(30) NOT NULL CHECK (
        nivel_gravedad_base IN ('Leve', 'Moderado', 'Grave', 'En Remisión')
    ),
    comorbilidades_frecuentes VARCHAR(200)
);

-- ============================================================================
-- 4. ENTIDAD: ExpedienteClinico
-- Llave ligada al paciente, fecha de apertura, motivo de consulta (cifrado) y antecedentes
-- ============================================================================
CREATE TABLE IF NOT EXISTS expediente_clinico (
    id_expediente VARCHAR(20) PRIMARY KEY,           -- Ej. 'EXP-2026-1084'
    id_paciente VARCHAR(20) UNIQUE NOT NULL REFERENCES paciente(id_paciente) ON DELETE RESTRICT,
    id_terapeuta_titular VARCHAR(25) NOT NULL REFERENCES terapeuta(id_terapeuta) ON DELETE RESTRICT,
    codigo_diagnostico_primario VARCHAR(15) NOT NULL REFERENCES diagnostico_dsm(codigo_diagnostico) ON DELETE RESTRICT,
    fecha_apertura DATE NOT NULL DEFAULT CURRENT_DATE,
    -- Columnas cifradas con pgcrypto (pgp_sym_encrypt AES-256)
    motivo_consulta_cifrado BYTEA NOT NULL,
    antecedentes_psicosociales_cifrado BYTEA NOT NULL,
    comorbilidades_activas VARCHAR(200),
    nivel_riesgo_actual VARCHAR(20) NOT NULL DEFAULT 'Bajo' CHECK (
        nivel_riesgo_actual IN ('Bajo', 'Moderado', 'Alto - Alerta Crítica')
    ),
    ultima_actualizacion TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 5. ENTIDAD: PlanIntervencion
-- Objetivos terapéuticos acordados, enfoque clínico y número de sesiones estimadas
-- ============================================================================
CREATE TABLE IF NOT EXISTS plan_intervencion (
    id_plan SERIAL PRIMARY KEY,
    id_expediente VARCHAR(20) NOT NULL REFERENCES expediente_clinico(id_expediente) ON DELETE RESTRICT,
    objetivos_terapeuticos TEXT NOT NULL,
    enfoque_clinico VARCHAR(80) NOT NULL CHECK (
        enfoque_clinico IN (
            'Terapia Cognitivo-Conductual (TCC)',
            'Terapia de Aceptación y Compromiso (ACT)',
            'Psicoterapia Humanista-Existencial',
            'Terapia Breve Centrada en Soluciones',
            'Terapia Sistémica Familiar'
        )
    ),
    sesiones_estimadas INTEGER NOT NULL CHECK (sesiones_estimadas BETWEEN 1 AND 100),
    sesiones_completadas INTEGER NOT NULL DEFAULT 0 CHECK (sesiones_completadas >= 0),
    fecha_inicio DATE NOT NULL DEFAULT CURRENT_DATE,
    estado_plan VARCHAR(25) NOT NULL DEFAULT 'Vigente' CHECK (
        estado_plan IN ('Vigente', 'Completado', 'Reestructurado', 'Suspendido')
    )
);

-- ============================================================================
-- 6. ENTIDAD: SesionTerapeutica
-- Registro estructurado por sesión, técnica, cumplimiento y notas clínicas cifradas
-- ============================================================================
CREATE TABLE IF NOT EXISTS sesion_terapeutica (
    id_sesion SERIAL PRIMARY KEY,
    id_expediente VARCHAR(20) NOT NULL REFERENCES expediente_clinico(id_expediente) ON DELETE RESTRICT,
    id_paciente VARCHAR(20) NOT NULL REFERENCES paciente(id_paciente) ON DELETE RESTRICT,
    id_terapeuta VARCHAR(25) NOT NULL REFERENCES terapeuta(id_terapeuta) ON DELETE RESTRICT,
    numero_sesion INTEGER NOT NULL CHECK (numero_sesion >= 1),
    fecha_sesion TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    tecnica_implementada VARCHAR(150) NOT NULL,      -- Ej. 'Reestructuración Cognitiva y Registro de Pensamientos'
    cumplimiento_tareas VARCHAR(50) NOT NULL CHECK (
        cumplimiento_tareas IN (
            'Completo (100%)',
            'Parcial (50%)',
            'Mínimo (25%)',
            'No cumplido (0%)',
            'Sin tarea previa (Sesión Inicial)'
        )
    ),
    -- Columna crítica cifrada a nivel de columna mediante pgcrypto (AES-256)
    notas_clinicas_cifradas BYTEA NOT NULL,
    estado_cita VARCHAR(25) NOT NULL DEFAULT 'Completada' CHECK (
        estado_cita IN ('Programada', 'Completada', 'Cancelada', 'Inasistencia')
    ),
    UNIQUE (id_expediente, numero_sesion)
);

-- ============================================================================
-- 7. ENTIDAD: EscalaEvaluacion
-- Catálogo de inventarios psicométricos aplicables (BDI-II, HAM-A, PHQ-9)
-- ============================================================================
CREATE TABLE IF NOT EXISTS escala_evaluacion (
    id_escala VARCHAR(20) PRIMARY KEY,               -- Ej. 'BDI-II', 'HAM-A', 'PHQ-9'
    nombre_instrumento VARCHAR(150) NOT NULL,
    autor_referencia VARCHAR(120) NOT NULL,
    numero_reactivos INTEGER NOT NULL CHECK (numero_reactivos > 0),
    puntaje_minimo INTEGER NOT NULL CHECK (puntaje_minimo = 0),
    puntaje_maximo INTEGER NOT NULL CHECK (puntaje_maximo > puntaje_minimo),
    umbral_leve INTEGER NOT NULL,
    umbral_moderado INTEGER NOT NULL,
    umbral_severo INTEGER NOT NULL,
    descripcion_umbrales VARCHAR(250) NOT NULL
);

-- ============================================================================
-- 8. ENTIDAD: ResultadoPsicometrico
-- Puntuación bruta, reactivo crítico (ítem 9), baremo, delta longitudinal (Δ)
-- ============================================================================
CREATE TABLE IF NOT EXISTS resultado_psicometrico (
    id_resultado SERIAL PRIMARY KEY,
    id_sesion INTEGER NOT NULL REFERENCES sesion_terapeutica(id_sesion) ON DELETE RESTRICT,
    id_expediente VARCHAR(20) NOT NULL REFERENCES expediente_clinico(id_expediente) ON DELETE RESTRICT,
    id_paciente VARCHAR(20) NOT NULL REFERENCES paciente(id_paciente) ON DELETE RESTRICT,
    id_escala VARCHAR(20) NOT NULL REFERENCES escala_evaluacion(id_escala) ON DELETE RESTRICT,
    fecha_aplicacion TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    puntuacion_bruta INTEGER NOT NULL CHECK (puntuacion_bruta >= 0 AND puntuacion_bruta <= 63),
    -- Reactivos específicos destacados del inventario BDI-II (0 a 3)
    item_1_tristeza INTEGER NOT NULL DEFAULT 0 CHECK (item_1_tristeza BETWEEN 0 AND 3),
    item_9_ideacion_riesgo INTEGER NOT NULL DEFAULT 0 CHECK (item_9_ideacion_riesgo BETWEEN 0 AND 3),
    respuestas_json JSONB,                           -- Desglose completo de los 21 reactivos
    baremo_severidad VARCHAR(40) NOT NULL,           -- Ej. 'Mínimo', 'Leve', 'Moderado', 'Severo'
    puntaje_inicial_referencia INTEGER,              -- Puntaje de la Sesión #1
    delta_cambio INTEGER DEFAULT 0,                  -- Δ = Puntaje_actual - Puntaje_inicial
    interpretacion_clinica TEXT,
    bandera_emergencia BOOLEAN NOT NULL DEFAULT FALSE
);

-- ============================================================================
-- 9. ENTIDADES DE AUDITORÍA Y ALERTAS PREVENTIVAS (Gobernanza y Triggers)
-- ============================================================================
CREATE TABLE IF NOT EXISTS alerta_riesgo_clinico (
    id_alerta SERIAL PRIMARY KEY,
    id_resultado INTEGER REFERENCES resultado_psicometrico(id_resultado) ON DELETE RESTRICT,
    id_expediente VARCHAR(20) NOT NULL REFERENCES expediente_clinico(id_expediente) ON DELETE RESTRICT,
    id_paciente VARCHAR(20) NOT NULL REFERENCES paciente(id_paciente) ON DELETE RESTRICT,
    id_terapeuta VARCHAR(25) NOT NULL REFERENCES terapeuta(id_terapeuta) ON DELETE RESTRICT,
    fecha_alerta TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    tipo_reactivo VARCHAR(100) NOT NULL,             -- Ej. 'Ítem 9 BDI-II: Ideación o Deseos de Autolesión'
    puntuacion_reactivo INTEGER NOT NULL CHECK (puntuacion_reactivo BETWEEN 0 AND 3),
    puntuacion_total_test INTEGER NOT NULL,
    mensaje_alerta TEXT NOT NULL,
    notificacion_api_enviada BOOLEAN NOT NULL DEFAULT TRUE,
    canal_notificacion VARCHAR(80) NOT NULL DEFAULT 'API SendGrid / SMTP Supervisor Clínico',
    estado_alerta VARCHAR(30) NOT NULL DEFAULT 'Activa' CHECK (
        estado_alerta IN ('Activa', 'En Revisión por Supervisor', 'Atendida / Protocolo Activado')
    ),
    fecha_atencion TIMESTAMP WITH TIME ZONE,
    notas_resolucion TEXT
);

CREATE TABLE IF NOT EXISTS bitacora_respaldo_drp (
    id_respaldo SERIAL PRIMARY KEY,
    tipo_respaldo VARCHAR(50) NOT NULL CHECK (
        tipo_respaldo IN (
            'Respaldo Completo Semanal (pg_dump)',
            'Respaldo Diferencial Diario',
            'Archivado WAL Continuo (Point-in-Time)',
            'Backup Manual Consistente (DBA)'
        )
    ),
    fecha_ejecucion TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ruta_destino VARCHAR(200) NOT NULL,
    tamano_mb NUMERIC(8,2) NOT NULL,
    rpo_comprometido VARCHAR(30) NOT NULL DEFAULT '1.0 Hora',
    rto_objetivo VARCHAR(30) NOT NULL DEFAULT '< 2.0 Horas',
    hash_verificacion_sha256 VARCHAR(64) NOT NULL,
    usuario_ejecutor VARCHAR(50) NOT NULL DEFAULT 'rol_dba_admin',
    estado_respaldo VARCHAR(30) NOT NULL DEFAULT 'Exitoso (Verificado)'
);

-- ============================================================================
-- 10. INDEXACIÓN ESTRATÉGICA B-TREE (Sección 12.4 - Escalabilidad y Rendimiento)
-- Evita barridos secuenciales (Seq Scan) en columnas de filtrado frecuente
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_btree_paciente_terapeuta ON paciente USING btree (id_terapeuta_asignado);
CREATE INDEX IF NOT EXISTS idx_btree_expediente_paciente ON expediente_clinico USING btree (id_paciente);
CREATE INDEX IF NOT EXISTS idx_btree_expediente_diagnostico ON expediente_clinico USING btree (codigo_diagnostico_primario);
CREATE INDEX IF NOT EXISTS idx_btree_sesion_paciente_fecha ON sesion_terapeutica USING btree (id_paciente, fecha_sesion DESC);
CREATE INDEX IF NOT EXISTS idx_btree_resultado_paciente_fecha ON resultado_psicometrico USING btree (id_paciente, fecha_aplicacion DESC);
CREATE INDEX IF NOT EXISTS idx_btree_alerta_estado ON alerta_riesgo_clinico USING btree (estado_alerta);
