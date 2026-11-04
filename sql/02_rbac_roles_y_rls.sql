-- ============================================================================
-- PROYECTO: Plataforma de Seguimiento Psicológico y Evaluación Terapéutica
--           (PsychoTrack DB)
-- MATERIA: Administración de Bases de Datos - CUCEI, Universidad de Guadalajara
-- AUTOR: Galvez Arceo Miguel Angel (Código: 220537132)
-- ARCHIVO: 02_rbac_roles_y_rls.sql
-- DESCRIPCIÓN: Configuración de Control de Acceso Basado en Roles (RBAC),
--              Principio del Menor Privilegio (GRANT/REVOKE), Vistas Protegidas
--              y Políticas de Seguridad a Nivel de Fila (Row-Level Security)
--              vinculadas a CURRENT_USER y variables de contexto clínicas.
-- ============================================================================

-- ============================================================================
-- 1. CREACIÓN DE ROLES OPERATIVOS EN EL MOTOR (Sección 3.B y 8.1)
-- ============================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rol_terapeuta') THEN
        CREATE ROLE rol_terapeuta NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rol_supervisor') THEN
        CREATE ROLE rol_supervisor NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rol_recepcion') THEN
        CREATE ROLE rol_recepcion NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rol_auditor') THEN
        CREATE ROLE rol_auditor NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rol_dba_admin') THEN
        CREATE ROLE rol_dba_admin SUPERUSER NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rol_paciente') THEN
        CREATE ROLE rol_paciente NOLOGIN;
    END IF;

    -- Usuarios individuales de terapeutas para validación nativa de CURRENT_USER en RLS
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'TER-84920-GDL') THEN
        CREATE ROLE "TER-84920-GDL" NOLOGIN IN ROLE rol_terapeuta;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'TER-91045-GDL') THEN
        CREATE ROLE "TER-91045-GDL" NOLOGIN IN ROLE rol_terapeuta;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'SUP-10200-GDL') THEN
        CREATE ROLE "SUP-10200-GDL" NOLOGIN IN ROLE rol_supervisor;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'REC-50012-GDL') THEN
        CREATE ROLE "REC-50012-GDL" NOLOGIN IN ROLE rol_recepcion;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'AUD-30099-GDL') THEN
        CREATE ROLE "AUD-30099-GDL" NOLOGIN IN ROLE rol_auditor;
    END IF;
END
$$;

-- ============================================================================
-- 2. REVOCACIÓN POR DEFECTO Y PRINCIPIO DE MENOR PRIVILEGIO (Saltzer & Schroeder)
-- ============================================================================
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO rol_terapeuta, rol_supervisor, rol_recepcion, rol_auditor, rol_dba_admin;

-- 2.1 Privilegios para rol_terapeuta:
-- Lectura (SELECT) y escritura (INSERT/UPDATE) acotadas a pacientes bajo su tutela (vía RLS)
GRANT SELECT ON terapeuta, diagnostico_dsm, escala_evaluacion TO rol_terapeuta;
GRANT SELECT, INSERT, UPDATE ON paciente, expediente_clinico, plan_intervencion, sesion_terapeutica, resultado_psicometrico, alerta_riesgo_clinico TO rol_terapeuta;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO rol_terapeuta;

-- 2.2 Privilegios para rol_supervisor (Rol_Supervisor_Clinico):
-- Consulta analítica sobre planes de intervención, notas clínicas y alertas con fines de docencia
GRANT SELECT ON ALL TABLES IN SCHEMA public TO rol_supervisor;
GRANT UPDATE (estado_alerta, fecha_atencion, notas_resolucion) ON alerta_riesgo_clinico TO rol_supervisor;

-- 2.3 Privilegios para rol_recepcion (Rol_Recepcion_Citas):
-- Acceso exclusivo a datos de contacto y agenda (SELECT / UPDATE de horarios) SIN acceso a diagnósticos ni notas clínicas
REVOKE ALL ON expediente_clinico, diagnostico_dsm, plan_intervencion, resultado_psicometrico, alerta_riesgo_clinico FROM rol_recepcion;
GRANT SELECT (id_paciente, iniciales_referencia, nombre_completo, edad, ocupacion_escolaridad, telefono_contacto, contacto_emergencia_nombre, contacto_emergencia_telefono, estado_clinico_general, id_terapeuta_asignado) ON paciente TO rol_recepcion;
GRANT SELECT (id_terapeuta, nombre_completo, especialidad_clinica, correo_institucional) ON terapeuta TO rol_recepcion;
GRANT SELECT (id_sesion, id_expediente, id_paciente, id_terapeuta, numero_sesion, fecha_sesion, estado_cita),
      UPDATE (fecha_sesion, estado_cita) ON sesion_terapeutica TO rol_recepcion;

-- 2.4 Privilegios para rol_auditor (Rol_Auditor_Direccion):
-- Privilegios de solo lectura limitados exclusivamente a vistas de indicadores agregados anonimizados
REVOKE ALL ON paciente, expediente_clinico, sesion_terapeutica, resultado_psicometrico FROM rol_auditor;
GRANT SELECT ON diagnostico_dsm, escala_evaluacion, bitacora_respaldo_drp TO rol_auditor;

-- 2.5 Privilegios para rol_dba_admin:
-- Control total DQL/DML y DDL para administración y planes de contingencia (DRP)
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO rol_dba_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO rol_dba_admin;

-- 2.6 Privilegios para rol_paciente (Portal del Paciente con RLS por id_paciente):
-- Acceso exclusivo al seguimiento de su propio plan terapéutico, agenda de citas,
-- evolución longitudinal (Delta) y contestación de autoevaluación psicométrica,
-- SIN acceso a las notas clínicas confidenciales del terapeuta (cifradas con pgcrypto).
REVOKE ALL ON alerta_riesgo_clinico, bitacora_respaldo_drp FROM rol_paciente;
GRANT SELECT (id_paciente, iniciales_referencia, nombre_completo, edad, ocupacion_escolaridad, telefono_contacto, contacto_emergencia_nombre, contacto_emergencia_telefono, fecha_ingreso, estado_clinico_general, id_terapeuta_asignado) ON paciente TO rol_paciente;
GRANT SELECT (id_expediente, id_paciente, id_terapeuta_titular, fecha_apertura) ON expediente_clinico TO rol_paciente;
GRANT SELECT (id_plan, id_expediente, objetivos_terapeuticos, enfoque_clinico, sesiones_estimadas, sesiones_completadas, fecha_inicio, estado_plan) ON plan_intervencion TO rol_paciente;
GRANT SELECT (id_sesion, id_expediente, id_paciente, id_terapeuta, numero_sesion, fecha_sesion, tecnica_implementada, cumplimiento_tareas, estado_cita),
      UPDATE (cumplimiento_tareas) ON sesion_terapeutica TO rol_paciente;
GRANT SELECT, INSERT ON resultado_psicometrico TO rol_paciente;
GRANT SELECT ON escala_evaluacion TO rol_paciente;

-- ============================================================================
-- 3. SEGURIDAD A NIVEL DE FILA (ROW-LEVEL SECURITY - RLS)
-- Garantiza mediante CURRENT_USER / app.current_terapeuta que un terapeuta
-- solo recupere y modifique las tuplas donde coincida su identificador profesional
-- ============================================================================

-- Función auxiliar que resuelve el identificador del terapeuta desde CURRENT_USER
-- o desde la variable de sesión de conexión (app.current_terapeuta)
CREATE OR REPLACE FUNCTION fn_obtener_terapeuta_actual()
RETURNS VARCHAR AS $$
BEGIN
    RETURN COALESCE(
        NULLIF(current_setting('app.current_terapeuta', true), ''),
        CURRENT_USER
    );
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Habilitar Row-Level Security en las tablas clínicas sensibles
ALTER TABLE paciente ENABLE ROW LEVEL SECURITY;
ALTER TABLE expediente_clinico ENABLE ROW LEVEL SECURITY;
ALTER TABLE sesion_terapeutica ENABLE ROW LEVEL SECURITY;
ALTER TABLE resultado_psicometrico ENABLE ROW LEVEL SECURITY;

-- Políticas RLS en tabla PACIENTE
DROP POLICY IF EXISTS pol_rls_paciente_terapeuta ON paciente;
CREATE POLICY pol_rls_paciente_terapeuta ON paciente
    FOR ALL
    TO rol_terapeuta
    USING (id_terapeuta_asignado = fn_obtener_terapeuta_actual())
    WITH CHECK (id_terapeuta_asignado = fn_obtener_terapeuta_actual());

DROP POLICY IF EXISTS pol_rls_paciente_supervisor_recepcion ON paciente;
CREATE POLICY pol_rls_paciente_supervisor_recepcion ON paciente
    FOR SELECT
    TO rol_supervisor, rol_recepcion, rol_dba_admin
    USING (true);

-- Políticas RLS en tabla EXPEDIENTE_CLINICO
DROP POLICY IF EXISTS pol_rls_expediente_terapeuta ON expediente_clinico;
CREATE POLICY pol_rls_expediente_terapeuta ON expediente_clinico
    FOR ALL
    TO rol_terapeuta
    USING (id_terapeuta_titular = fn_obtener_terapeuta_actual())
    WITH CHECK (id_terapeuta_titular = fn_obtener_terapeuta_actual());

DROP POLICY IF EXISTS pol_rls_expediente_supervisor ON expediente_clinico;
CREATE POLICY pol_rls_expediente_supervisor ON expediente_clinico
    FOR SELECT
    TO rol_supervisor, rol_dba_admin
    USING (true);

-- Políticas RLS en tabla SESION_TERAPEUTICA
DROP POLICY IF EXISTS pol_rls_sesion_terapeuta ON sesion_terapeutica;
CREATE POLICY pol_rls_sesion_terapeuta ON sesion_terapeutica
    FOR ALL
    TO rol_terapeuta
    USING (id_terapeuta = fn_obtener_terapeuta_actual())
    WITH CHECK (id_terapeuta = fn_obtener_terapeuta_actual());

DROP POLICY IF EXISTS pol_rls_sesion_supervisor_recepcion ON sesion_terapeutica;
CREATE POLICY pol_rls_sesion_supervisor_recepcion ON sesion_terapeutica
    FOR SELECT
    TO rol_supervisor, rol_recepcion, rol_dba_admin
    USING (true);

-- Políticas RLS en tabla RESULTADO_PSICOMETRICO
DROP POLICY IF EXISTS pol_rls_resultado_terapeuta ON resultado_psicometrico;
CREATE POLICY pol_rls_resultado_terapeuta ON resultado_psicometrico
    FOR ALL
    TO rol_terapeuta
    USING (
        EXISTS (
            SELECT 1 FROM expediente_clinico e
            WHERE e.id_expediente = resultado_psicometrico.id_expediente
              AND e.id_terapeuta_titular = fn_obtener_terapeuta_actual()
        )
    );

DROP POLICY IF EXISTS pol_rls_resultado_supervisor ON resultado_psicometrico;
CREATE POLICY pol_rls_resultado_supervisor ON resultado_psicometrico
    FOR SELECT
    TO rol_supervisor, rol_dba_admin
    USING (true);

-- ============================================================================
-- 4. VISTAS PROTEGIDAS POR ROL (Sección 3.B y 8.1)
-- ============================================================================

-- 4.1 Vista Segura con RLS para el Dashboard del Terapeuta (Mockup 2)
CREATE OR REPLACE VIEW vw_pacientes_asignados_rls AS
SELECT
    p.id_paciente,
    p.iniciales_referencia,
    p.nombre_completo,
    p.edad,
    p.ocupacion_escolaridad,
    p.estado_clinico_general,
    p.id_terapeuta_asignado,
    e.id_expediente,
    e.codigo_diagnostico_primario,
    d.nombre_trastorno AS diagnostico_nombre,
    e.nivel_riesgo_actual,
    COALESCE(pl.sesiones_completadas, 0) AS sesiones_completadas,
    COALESCE(pl.sesiones_estimadas, 10) AS sesiones_estimadas,
    ult.id_escala AS ultimo_test_escala,
    ult.puntuacion_bruta AS ultimo_test_puntaje,
    ult.baremo_severidad AS ultimo_test_severidad,
    ult.delta_cambio AS delta_psicometrico,
    ult.bandera_emergencia AS alerta_activa
FROM paciente p
JOIN expediente_clinico e ON p.id_paciente = e.id_paciente
JOIN diagnostico_dsm d ON e.codigo_diagnostico_primario = d.codigo_diagnostico
LEFT JOIN LATERAL (
    SELECT sesiones_completadas, sesiones_estimadas
    FROM plan_intervencion pi
    WHERE pi.id_expediente = e.id_expediente
    ORDER BY pi.id_plan DESC LIMIT 1
) pl ON true
LEFT JOIN LATERAL (
    SELECT id_escala, puntuacion_bruta, baremo_severidad, delta_cambio, bandera_emergencia
    FROM resultado_psicometrico rp
    WHERE rp.id_expediente = e.id_expediente
    ORDER BY rp.fecha_aplicacion DESC, rp.id_resultado DESC LIMIT 1
) ult ON true
WHERE p.id_terapeuta_asignado = fn_obtener_terapeuta_actual();

GRANT SELECT ON vw_pacientes_asignados_rls TO rol_terapeuta, rol_supervisor, rol_dba_admin;

-- 4.2 Vista Exclusiva para Recepción y Citas (Sin datos clínicos ni notas)
CREATE OR REPLACE VIEW vw_agenda_recepcion_segura AS
SELECT
    s.id_sesion,
    s.fecha_sesion,
    s.numero_sesion,
    s.estado_cita,
    p.id_paciente,
    p.iniciales_referencia,
    p.nombre_completo AS paciente_nombre,
    p.telefono_contacto,
    p.contacto_emergencia_nombre,
    p.contacto_emergencia_telefono,
    t.id_terapeuta,
    t.nombre_completo AS terapeuta_nombre,
    t.especialidad_clinica
FROM sesion_terapeutica s
JOIN paciente p ON s.id_paciente = p.id_paciente
JOIN terapeuta t ON s.id_terapeuta = t.id_terapeuta;

GRANT SELECT ON vw_agenda_recepcion_segura TO rol_recepcion, rol_dba_admin;

-- 4.3 Vista Anonimizada de Indicadores Agregados para Auditoría y Dirección
CREATE OR REPLACE VIEW vw_auditoria_indicadores_anonimizados AS
SELECT
    d.codigo_diagnostico,
    d.nombre_trastorno,
    COUNT(DISTINCT e.id_expediente) AS total_expedientes_activos,
    COUNT(s.id_sesion) AS volumen_consultas_registradas,
    ROUND(AVG(rp.puntuacion_bruta)::NUMERIC, 1) AS media_puntaje_psicometrico,
    ROUND(AVG(rp.delta_cambio)::NUMERIC, 1) AS promedio_delta_mejoria,
    SUM(CASE WHEN p.estado_clinico_general = 'Deserción' THEN 1 ELSE 0 END) AS casos_desercion
FROM diagnostico_dsm d
LEFT JOIN expediente_clinico e ON d.codigo_diagnostico = e.codigo_diagnostico_primario
LEFT JOIN paciente p ON e.id_paciente = p.id_paciente
LEFT JOIN sesion_terapeutica s ON e.id_expediente = s.id_expediente
LEFT JOIN resultado_psicometrico rp ON s.id_sesion = rp.id_sesion
GROUP BY d.codigo_diagnostico, d.nombre_trastorno;

GRANT SELECT ON vw_auditoria_indicadores_anonimizados TO rol_auditor, rol_supervisor, rol_dba_admin;
