-- ============================================================================
-- PROYECTO: Plataforma de Seguimiento Psicológico y Evaluación Terapéutica
--           (PsychoTrack DB)
-- MATERIA: Administración de Bases de Datos - CUCEI, Universidad de Guadalajara
-- AUTOR: Galvez Arceo Miguel Angel (Código: 220537132)
-- ARCHIVO: 04_datos_semilla_anonimizados.sql
-- DESCRIPCIÓN: Población de catálogos DSM-5/CIE-11, escalas psicométricas
--              (BDI-II, HAM-A, PHQ-9), perfiles RBAC con hash SHA-256 + salt,
--              pacientes anonimizados, expedientes cifrados con pgcrypto
--              y sesiones históricas que reproducen fielmente los Mockups 1 a 4.
-- ============================================================================

-- Limpieza segura para re-ejecución idempotente en laboratorio
TRUNCATE TABLE
    alerta_riesgo_clinico,
    resultado_psicometrico,
    sesion_terapeutica,
    plan_intervencion,
    expediente_clinico,
    paciente,
    diagnostico_dsm,
    escala_evaluacion,
    bitacora_respaldo_drp,
    terapeuta
RESTART IDENTITY CASCADE;

-- ============================================================================
-- 1. PERSONAL CLÍNICO Y ADMINISTRATIVO (Terapeuta, Supervisor, Recepción, Auditor, DBA)
-- Contraseña de prueba para todos los usuarios: Psycho2026!
-- Hash calculado nativamente con encode(digest('Psycho2026!' || salt, 'sha256'), 'hex')
-- ============================================================================
INSERT INTO terapeuta (
    id_terapeuta, cedula_profesional, nombre_completo, especialidad_clinica,
    correo_institucional, usuario_db, rol_operativo, password_salt, password_hash, estado_activo
) VALUES
(
    'TER-84920-GDL', '84920', 'Dr. Alejandro Morales Ramos', 'Terapia Cognitivo-Conductual',
    'alejandro.morales@psychotrack.udg.mx', 'TER-84920-GDL', 'rol_terapeuta',
    'salt_tx84920_gdl_2026',
    encode(digest('Psycho2026!' || 'salt_tx84920_gdl_2026', 'sha256'), 'hex'),
    TRUE
),
(
    'TER-91045-GDL', '91045', 'Dra. Valeria Solís Mendoza', 'Terapia Sistémica y Humanista',
    'valeria.solis@psychotrack.udg.mx', 'TER-91045-GDL', 'rol_terapeuta',
    'salt_tx91045_gdl_2026',
    encode(digest('Psycho2026!' || 'salt_tx91045_gdl_2026', 'sha256'), 'hex'),
    TRUE
),
(
    'SUP-10200-GDL', '10200', 'Dr. Roberto Guzmán Cárdenas', 'Supervisión Clínica y Psiquiatría',
    'roberto.guzman@psychotrack.udg.mx', 'SUP-10200-GDL', 'rol_supervisor',
    'salt_sup10200_gdl_2026',
    encode(digest('Psycho2026!' || 'salt_sup10200_gdl_2026', 'sha256'), 'hex'),
    TRUE
),
(
    'REC-50012-GDL', '50012', 'Lic. Sofía Herrera Vázquez', 'Recepción y Control de Agenda Clínica',
    'sofia.herrera@psychotrack.udg.mx', 'REC-50012-GDL', 'rol_recepcion',
    'salt_rec50012_gdl_2026',
    encode(digest('Psycho2026!' || 'salt_rec50012_gdl_2026', 'sha256'), 'hex'),
    TRUE
),
(
    'AUD-30099-GDL', '30099', 'Mtro. Carlos Ibarra Montes', 'Auditoría Clínica y Dirección Universitaria',
    'carlos.ibarra@psychotrack.udg.mx', 'AUD-30099-GDL', 'rol_auditor',
    'salt_aud30099_gdl_2026',
    encode(digest('Psycho2026!' || 'salt_aud30099_gdl_2026', 'sha256'), 'hex'),
    TRUE
),
(
    'DBA-00001-GDL', '220537132', 'Ing. Miguel Angel Galvez Arceo', 'Administración de Bases de Datos y DRP',
    'miguel.galvez@alumnos.udg.mx', 'postgres', 'rol_dba_admin',
    'salt_dba00001_gdl_2026',
    encode(digest('Psycho2026!' || 'salt_dba00001_gdl_2026', 'sha256'), 'hex'),
    TRUE
);

-- ============================================================================
-- 2. CATÁLOGO DE DIAGNÓSTICOS CLÍNICOS (DSM-5 / CIE-11)
-- ============================================================================
INSERT INTO diagnostico_dsm (
    codigo_diagnostico, sistema_clasificacion, nombre_trastorno,
    descripcion_clinica, nivel_gravedad_base, comorbilidades_frecuentes
) VALUES
(
    'F41.1', 'DSM-5 / CIE-10', 'Trastorno de Ansiedad Generalizada',
    'Ansiedad y preocupación excesivas (expectación aprehensiva) que se producen durante más días de los que ha estado ausente durante un mínimo de seis meses, en relación con diversos sucesos o actividades académicas o laborales.',
    'Leve', 'Insomnio de conciliación, tensión muscular tónica'
),
(
    'F32.2', 'DSM-5 / CIE-10', 'Depresión Mayor Moderada',
    'Trastorno Depresivo Mayor, Episodio Único, Grave/Moderado sin síntomas psicóticos. Estado de ánimo deprimido la mayor parte del día, disminución importante del interés o el placer (anhedonia) y rumiación nocturna.',
    'Grave', 'Distorsiones cognitivas de catastrofización, aislamiento escolar'
),
(
    'F43.2', 'DSM-5 / CIE-10', 'Trastorno de Adaptación',
    'Desarrollo de síntomas emocionales o del comportamiento en respuesta a un factor o factores de estrés identificables que se producen en los tres meses siguientes al inicio del factor de estrés (ej. transición a posgrado).',
    'Leve', 'Estrés académico agudo'
),
(
    'F41.0', 'DSM-5 / CIE-11', 'Trastorno de Pánico',
    'Ataques de pánico imprevistos recurrentes con aparición súbita de miedo intenso o malestar intenso que alcanza su máxima expresión en minutos.',
    'Moderado', 'Conductas de evitación agorafóbica'
);

-- ============================================================================
-- 3. CATÁLOGO DE ESCALAS DE EVALUACIÓN PSICOMÉTRICA
-- ============================================================================
INSERT INTO escala_evaluacion (
    id_escala, nombre_instrumento, autor_referencia, numero_reactivos,
    puntaje_minimo, puntaje_maximo, umbral_leve, umbral_moderado, umbral_severo, descripcion_umbrales
) VALUES
(
    'BDI-II', 'Inventario de Depresión de Beck (BDI-II)', 'Aaron T. Beck, Robert A. Steer y Gregory K. Brown (1996)',
    21, 0, 63, 14, 20, 29,
    '0-13: Mínimo | 14-19: Leve | 20-28: Moderado | 29-63: Severo (Ítem 9 evalúa riesgo de ideación/autolesión)'
),
(
    'HAM-A', 'Escala de Ansiedad de Hamilton (Hamilton)', 'Max Hamilton (1959)',
    14, 0, 56, 14, 18, 25,
    '0-13: Mínimo/Ausente | 14-17: Ansiedad Leve | 18-24: Ansiedad Moderada | 25-56: Ansiedad Severa'
),
(
    'PHQ-9', 'Cuestionario de Salud del Paciente (PHQ-9)', 'Kroenke, Spitzer & Williams (2001)',
    9, 0, 27, 5, 10, 20,
    '0-4: Mínimo | 5-9: Leve | 10-14: Moderado | 15-19: Moderadamente Severo | 20-27: Severo'
);

-- ============================================================================
-- 4. PACIENTES ANONIMIZADOS (Separados por Terapeuta para demostrar RLS)
-- ============================================================================
INSERT INTO paciente (
    id_paciente, iniciales_referencia, nombre_completo, edad, ocupacion_escolaridad,
    telefono_contacto, contacto_emergencia_nombre, contacto_emergencia_telefono,
    fecha_ingreso, estado_clinico_general, password_salt, password_hash, id_terapeuta_asignado
) VALUES
-- 3 Pacientes principales del Mockup 2 asignados a TER-84920-GDL (Dr. Alejandro Morales)
(
    'PAC-2026-015', 'C.R.M. (22 años, Estudiante)', 'Camila Rodríguez Méndez', 22, 'Estudiante (Pregrado)',
    '33-1482-9901', 'Martha Méndez (Madre)', '33-1029-4411',
    '2026-08-15', 'Activo', 'salt_pac015_gdl_2026',
    encode(digest('Psycho2026!' || 'salt_pac015_gdl_2026', 'sha256'), 'hex'),
    'TER-84920-GDL'
),
(
    'PAC-2026-042', 'J.A.P. (20 años, Estudiante)', 'Jorge Alberto Pérez Soto', 20, 'Estudiante (Pregrado)',
    '33-2891-4052', 'Alberto Pérez (Padre)', '33-3910-2280',
    '2026-09-10', 'Activo', 'salt_pac042_gdl_2026',
    encode(digest('Psycho2026!' || 'salt_pac042_gdl_2026', 'sha256'), 'hex'),
    'TER-84920-GDL'
),
(
    'PAC-2026-088', 'M.F.S. (25 años, Posgrado)', 'María Fernanda Salazar Luna', 25, 'Posgrado (Maestría)',
    '33-1904-7731', 'Daniel Salazar (Hermano)', '33-1102-8843',
    '2026-07-02', 'Alta Terapéutica', 'salt_pac088_gdl_2026',
    encode(digest('Psycho2026!' || 'salt_pac088_gdl_2026', 'sha256'), 'hex'),
    'TER-84920-GDL'
),
-- Paciente asignado a OTRA terapeuta (TER-91045-GDL) para demostrar bloqueo infranqueable RLS
(
    'PAC-2026-109', 'L.G.V. (23 años, Estudiante)', 'Luis Gerardo Vargas Ortiz', 23, 'Estudiante (Pregrado)',
    '33-4012-5590', 'Elena Ortiz (Madre)', '33-4099-1122',
    '2026-09-20', 'Activo', 'salt_pac109_gdl_2026',
    encode(digest('Psycho2026!' || 'salt_pac109_gdl_2026', 'sha256'), 'hex'),
    'TER-91045-GDL'
);

-- ============================================================================
-- 5. EXPEDIENTES CLÍNICOS CON CIFRADO DE COLUMNA (pgcrypto AES-256)
-- ============================================================================
INSERT INTO expediente_clinico (
    id_expediente, id_paciente, id_terapeuta_titular, codigo_diagnostico_primario,
    fecha_apertura, motivo_consulta_cifrado, antecedentes_psicosociales_cifrado,
    comorbilidades_activas, nivel_riesgo_actual
) VALUES
(
    'EXP-2026-1015', 'PAC-2026-015', 'TER-84920-GDL', 'F41.1', '2026-08-15',
    fn_cifrar_columna_pgp('Consultante acude por inquietud constante, dificultad para concentrarse en exámenes parciales y tensión muscular cervical.'),
    fn_cifrar_columna_pgp('Estudiante foránea de 5to semestre. Red de apoyo familiar a distancia; alta autoexigencia académica.'),
    'Insomnio ocasional pre-exámenes', 'Bajo'
),
(
    'EXP-2026-1084', 'PAC-2026-042', 'TER-84920-GDL', 'F32.2', '2026-09-10',
    fn_cifrar_columna_pgp('Estado de ánimo deprimido, pérdida marcada de interés en actividades universitarias, rumiación nocturna y desesperanza.'),
    fn_cifrar_columna_pgp('Estudiante de 3er semestre de Ingeniería. Ruptura afectiva reciente y reprobación de dos asignaturas.'),
    'Rumiación nocturna severa y aislamiento social', 'Alto - Alerta Crítica'
),
(
    'EXP-2026-1088', 'PAC-2026-088', 'TER-84920-GDL', 'F43.2', '2026-07-02',
    fn_cifrar_columna_pgp('Sobrecarga emocional por inicio de tesis de posgrado y adaptación a nuevo laboratorio de investigación.'),
    fn_cifrar_columna_pgp('Becaria de posgrado a tiempo completo. Sin antecedentes psiquiátricos previos.'),
    'Ninguna', 'Bajo'
),
(
    'EXP-2026-1109', 'PAC-2026-109', 'TER-91045-GDL', 'F41.0', '2026-09-20',
    fn_cifrar_columna_pgp('Episodios de taquicardia y miedo súbito en el transporte público camino al centro universitario.'),
    fn_cifrar_columna_pgp('Estudiante de arquitectura; trabaja medio turno.'),
    'Agorafobia leve', 'Moderado'
);

-- ============================================================================
-- 6. PLANES DE INTERVENCIÓN
-- ============================================================================
INSERT INTO plan_intervencion (
    id_expediente, objetivos_terapeuticos, enfoque_clinico,
    sesiones_estimadas, sesiones_completadas, fecha_inicio, estado_plan
) VALUES
(
    'EXP-2026-1015',
    '1. Entrenamiento en relajación diafragmática. 2. Descatastrofización de evaluaciones académicas. 3. Higiene del sueño.',
    'Terapia Cognitivo-Conductual (TCC)', 12, 6, '2026-08-15', 'Vigente'
),
(
    'EXP-2026-1084',
    'Plan de Intervención: 10 sesiones estimadas con enfoque TCC. Activación conductual gradual, reestructuración de distorsiones cognitivas y protocolo de contención de riesgo.',
    'Terapia Cognitivo-Conductual (TCC)', 10, 3, '2026-09-10', 'Vigente'
),
(
    'EXP-2026-1088',
    '1. Gestión del tiempo y límites saludables en posgrado. 2. Técnicas de resolución de problemas.',
    'Terapia Breve Centrada en Soluciones', 8, 8, '2026-07-02', 'Completado'
),
(
    'EXP-2026-1109',
    '1. Psicoeducación del ciclo del pánico. 2. Exposición interoceptiva gradual.',
    'Terapia Cognitivo-Conductual (TCC)', 10, 2, '2026-09-20', 'Vigente'
);

-- ============================================================================
-- 7. SESIONES TERAPÉUTICAS Y RESULTADOS PSICOMÉTRICOS (Disparan SP y Triggers)
-- ============================================================================

-- 7.1 Historial de PAC-2026-015 (C.R.M. - Hamilton: Inicial 25 pts -> Actual 14 pts [Leve], Delta = -11 pts)
INSERT INTO sesion_terapeutica (
    id_expediente, id_paciente, id_terapeuta, numero_sesion, fecha_sesion,
    tecnica_implementada, cumplimiento_tareas, notas_clinicas_cifradas, estado_cita
) VALUES
(
    'EXP-2026-1015', 'PAC-2026-015', 'TER-84920-GDL', 1, '2026-08-15 10:00:00-06',
    'Entrevista Clínica Inicial y Línea Base', 'Sin tarea previa (Sesión Inicial)',
    fn_cifrar_columna_pgp('Se establece rapport adecuado. Aplicación inicial de escala Hamilton con puntaje de 25 pts.'),
    'Completada'
),
(
    'EXP-2026-1015', 'PAC-2026-015', 'TER-84920-GDL', 6, '2026-10-19 09:00:00-06',
    'Reestructuración Cognitiva y Respiración Diafragmática', 'Completo (100%)',
    fn_cifrar_columna_pgp('La paciente reporta reducción notable de ansiedad anticipatoria durante la semana de exámenes.'),
    'Completada'
);

INSERT INTO resultado_psicometrico (
    id_sesion, id_expediente, id_paciente, id_escala, fecha_aplicacion,
    puntuacion_bruta, item_1_tristeza, item_9_ideacion_riesgo, baremo_severidad
) VALUES
(1, 'EXP-2026-1015', 'PAC-2026-015', 'HAM-A', '2026-08-15 10:30:00-06', 25, 1, 0, 'Severo'),
(2, 'EXP-2026-1015', 'PAC-2026-015', 'HAM-A', '2026-10-19 09:40:00-06', 14, 0, 0, 'Leve');

-- 7.2 Historial de PAC-2026-042 (J.A.P. - Exp. #1084 - Mockup 2 y Mockup 3)
-- Sesión #1: 24 pts (Moderado) -> Sesión #2: 25 pts -> Sesión #3: 28 pts (Severo), Delta = +4 pts (Regresión/Riesgo), Ítem 9 = 2 (Trigger Activo)
INSERT INTO sesion_terapeutica (
    id_expediente, id_paciente, id_terapeuta, numero_sesion, fecha_sesion,
    tecnica_implementada, cumplimiento_tareas, notas_clinicas_cifradas, estado_cita
) VALUES
(
    'EXP-2026-1084', 'PAC-2026-042', 'TER-84920-GDL', 1, '2026-09-21 11:00:00-06',
    'Evaluación Diagnóstica y Encuadre TCC', 'Sin tarea previa (Sesión Inicial)',
    fn_cifrar_columna_pgp('Paciente ingresa con sintomatología depresiva moderada (BDI-II: 24 pts). Se acuerda plan de 10 sesiones.'),
    'Completada'
),
(
    'EXP-2026-1084', 'PAC-2026-042', 'TER-84920-GDL', 2, '2026-10-05 11:00:00-06',
    'Activación Conductual y Monitoreo del Estado de Ánimo', 'Parcial (50%)',
    fn_cifrar_columna_pgp('Dificultad para levantarse por las mañanas. Cumplimiento parcial de bitácora de actividades placenteras.'),
    'Completada'
),
(
    'EXP-2026-1084', 'PAC-2026-042', 'TER-84920-GDL', 3, '2026-10-19 11:00:00-06',
    'Reestructuración Cognitiva y Registro de Pensamientos', 'Parcial (50%)',
    fn_cifrar_columna_pgp('El paciente refiere incremento en la rumiación nocturna durante la semana. Manifiesta pérdida de interés en actividades escolares y desesperanza marcada. Se abordan distorsiones cognitivas de tipo catastrofización.'),
    'Completada'
);

INSERT INTO resultado_psicometrico (
    id_sesion, id_expediente, id_paciente, id_escala, fecha_aplicacion,
    puntuacion_bruta, item_1_tristeza, item_9_ideacion_riesgo, baremo_severidad
) VALUES
(3, 'EXP-2026-1084', 'PAC-2026-042', 'BDI-II', '2026-09-21 11:40:00-06', 24, 1, 0, 'Moderado'),
(4, 'EXP-2026-1084', 'PAC-2026-042', 'BDI-II', '2026-10-05 11:40:00-06', 25, 2, 1, 'Moderado'),
-- Esta inserción ejecuta automáticamente el Trigger BEFORE INSERT y AFTER INSERT al tener item_9 = 2 y puntaje = 28 (Delta = +4)
(5, 'EXP-2026-1084', 'PAC-2026-042', 'BDI-II', '2026-10-19 11:45:00-06', 28, 2, 2, 'Severo');

-- 7.3 Historial de PAC-2026-088 (M.F.S. - PHQ-9: Inicial 18 pts -> Actual 3 pts [Mínimo], Delta = -15 pts [Alta])
INSERT INTO sesion_terapeutica (
    id_expediente, id_paciente, id_terapeuta, numero_sesion, fecha_sesion,
    tecnica_implementada, cumplimiento_tareas, notas_clinicas_cifradas, estado_cita
) VALUES
(
    'EXP-2026-1088', 'PAC-2026-088', 'TER-84920-GDL', 1, '2026-07-02 13:00:00-06',
    'Evaluación Inicial y Jerarquización de Problemas', 'Sin tarea previa (Sesión Inicial)',
    fn_cifrar_columna_pgp('Inicio de intervención por estrés agudo de adaptación a maestría. PHQ-9 inicial de 18 puntos.'),
    'Completada'
),
(
    'EXP-2026-1088', 'PAC-2026-088', 'TER-84920-GDL', 8, '2026-10-19 13:00:00-06',
    'Prevención de Recaídas y Cierre por Alta Terapéutica', 'Completo (100%)',
    fn_cifrar_columna_pgp('Remisión completa de sintomatología adaptativa. La consultante alcanza metas terapéuticas (8/8 sesiones).'),
    'Completada'
);

INSERT INTO resultado_psicometrico (
    id_sesion, id_expediente, id_paciente, id_escala, fecha_aplicacion,
    puntuacion_bruta, item_1_tristeza, item_9_ideacion_riesgo, baremo_severidad
) VALUES
(6, 'EXP-2026-1088', 'PAC-2026-088', 'PHQ-9', '2026-07-02 13:40:00-06', 18, 2, 0, 'Moderado'),
(7, 'EXP-2026-1088', 'PAC-2026-088', 'PHQ-9', '2026-10-19 13:40:00-06', 3, 0, 0, 'Mínimo');

-- Corregir sesiones_completadas exactas tras las inserciones semilla para reflejar 6/12, 3/10 y 8/8 del Mockup 2
UPDATE plan_intervencion SET sesiones_completadas = 6 WHERE id_expediente = 'EXP-2026-1015';
UPDATE plan_intervencion SET sesiones_completadas = 3 WHERE id_expediente = 'EXP-2026-1084';
UPDATE plan_intervencion SET sesiones_completadas = 8 WHERE id_expediente = 'EXP-2026-1088';

-- Citas adicionales del día (para reflejar "5 sesiones hoy: 3 completadas • 2 pendientes" en Mockup 2)
INSERT INTO sesion_terapeutica (
    id_expediente, id_paciente, id_terapeuta, numero_sesion, fecha_sesion,
    tecnica_implementada, cumplimiento_tareas, notas_clinicas_cifradas, estado_cita
) VALUES
(
    'EXP-2026-1015', 'PAC-2026-015', 'TER-84920-GDL', 7, CURRENT_TIMESTAMP + INTERVAL '2 hours',
    'Seguimiento de Exposición y Reestructuración', 'Completo (100%)',
    fn_cifrar_columna_pgp('Sesión programada pendiente del turno vespertino.'),
    'Programada'
),
(
    'EXP-2026-1084', 'PAC-2026-042', 'TER-84920-GDL', 4, CURRENT_TIMESTAMP + INTERVAL '4 hours',
    'Sesión de Contención y Plan de Seguridad', 'Parcial (50%)',
    fn_cifrar_columna_pgp('Sesión de seguimiento prioritario programada tras alerta de riesgo.'),
    'Programada'
);

-- Sesión del otro terapeuta (Dra. Valeria Solís - TER-91045-GDL) oculta para TER-84920-GDL por RLS
INSERT INTO sesion_terapeutica (
    id_expediente, id_paciente, id_terapeuta, numero_sesion, fecha_sesion,
    tecnica_implementada, cumplimiento_tareas, notas_clinicas_cifradas, estado_cita
) VALUES
(
    'EXP-2026-1109', 'PAC-2026-109', 'TER-91045-GDL', 1, '2026-10-18 16:00:00-06',
    'Psicoeducación y Reentrenamiento Respiratorio', 'Sin tarea previa (Sesión Inicial)',
    fn_cifrar_columna_pgp('Nota clínica confidencial exclusiva de la Dra. Valeria Solís (aislada mediante RLS).'),
    'Completada'
);

INSERT INTO resultado_psicometrico (
    id_sesion, id_expediente, id_paciente, id_escala, fecha_aplicacion,
    puntuacion_bruta, item_1_tristeza, item_9_ideacion_riesgo, baremo_severidad
) VALUES
(10, 'EXP-2026-1109', 'PAC-2026-109', 'HAM-A', '2026-10-18 16:40:00-06', 21, 1, 0, 'Moderado');

-- ============================================================================
-- 8. BITÁCORA DE RESPALDOS Y CONTINGENCIA (DRP - Mockup 4)
-- ============================================================================
INSERT INTO bitacora_respaldo_drp (
    tipo_respaldo, fecha_ejecucion, ruta_destino, tamano_mb,
    rpo_comprometido, rto_objetivo, hash_verificacion_sha256, usuario_ejecutor, estado_respaldo
) VALUES
(
    'Respaldo Completo Semanal (pg_dump)',
    '2026-10-18 03:00:00-06',
    '/backups/full/psychotrack_full_20261018_0300.dump.gz',
    148.40,
    '1.0 Hora', '< 2.0 Horas',
    encode(digest('psychotrack_full_20261018_0300', 'sha256'), 'hex'),
    'rol_dba_admin', 'Activo • Verificado'
),
(
    'Respaldo Diferencial Diario',
    '2026-10-19 23:00:00-06',
    '/backups/diff/psychotrack_diff_20261019_2300.tar.zst',
    24.15,
    '1.0 Hora', '< 2.0 Horas',
    encode(digest('psychotrack_diff_20261019_2300', 'sha256'), 'hex'),
    'rol_dba_admin', 'Activo • Acumulativo de deltas'
),
(
    'Archivado WAL Continuo (Point-in-Time)',
    CURRENT_TIMESTAMP - INTERVAL '8 minutes',
    's3://airgapped-drp-udg/wal_archive/00000001000000000000004A',
    16.00,
    '1.0 Hora', '< 2.0 Horas',
    encode(digest('wal_segment_00000001000000000000004A', 'sha256'), 'hex'),
    'postgres_archiver', 'Sincronizado (Air-gapped)'
);
