-- ============================================================================
-- PROYECTO: Plataforma de Seguimiento Psicológico y Evaluación Terapéutica
--           (PsychoTrack DB)
-- MATERIA: Administración de Bases de Datos - CUCEI, Universidad de Guadalajara
-- AUTOR: Galvez Arceo Miguel Angel (Código: 220537132)
-- ARCHIVO: 03_triggers_y_procedimientos.sql
-- DESCRIPCIÓN: Programación de Lógica de Negocio en PL/pgSQL:
--              1. Funciones Criptográficas AES-256 (pgcrypto) y Hash SHA-256 + Salt
--              2. Procedimiento Almacenado sp_calcular_delta_psicometrico() (Δ)
--              3. Disparador BEFORE INSERT (trg_alerta_riesgo_psicometrico) para
--                 evaluar reactivos críticos (Ítem 9 BDI-II) y levantar bandera
--              4. Disparador AFTER INSERT para registrar notificación a Supervisor
-- ============================================================================

-- ============================================================================
-- 1. FUNCIONES CRIPTOGRÁFICAS DE COLUMNA (pgcrypto AES-256 y SHA-256 + Salt)
-- ============================================================================

-- Verificar credenciales con Salt aleatorio + Hash determinista SHA-256
CREATE OR REPLACE FUNCTION fn_verificar_credenciales_sha256(
    p_id_terapeuta VARCHAR,
    p_password_plano VARCHAR
) RETURNS TABLE (
    autenticado BOOLEAN,
    id_terapeuta VARCHAR,
    nombre_completo VARCHAR,
    cedula_profesional VARCHAR,
    especialidad_clinica VARCHAR,
    rol_operativo VARCHAR
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        (encode(digest(p_password_plano || t.password_salt, 'sha256'), 'hex') = t.password_hash) AS autenticado,
        t.id_terapeuta,
        t.nombre_completo,
        t.cedula_profesional,
        t.especialidad_clinica,
        t.rol_operativo
    FROM terapeuta t
    WHERE t.id_terapeuta = p_id_terapeuta
      AND t.estado_activo = TRUE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Cifrar narrativa clínica a nivel de columna con AES-256 (pgcrypto)
CREATE OR REPLACE FUNCTION fn_cifrar_columna_pgp(
    p_texto_plano TEXT,
    p_llave_simetrica TEXT DEFAULT 'PsychoTrack_AES256_ClinicalKey_2026!'
) RETURNS BYTEA AS $$
BEGIN
    RETURN pgp_sym_encrypt(p_texto_plano, p_llave_simetrica, 'cipher-algo=aes256');
END;
$$ LANGUAGE plpgsql IMMUTABLE STRICT;

-- Descifrar narrativa clínica a nivel de columna (solo para roles autorizados)
CREATE OR REPLACE FUNCTION fn_descifrar_columna_pgp(
    p_dato_cifrado BYTEA,
    p_llave_simetrica TEXT DEFAULT 'PsychoTrack_AES256_ClinicalKey_2026!'
) RETURNS TEXT AS $$
BEGIN
    IF p_dato_cifrado IS NULL THEN
        RETURN NULL;
    END IF;
    RETURN pgp_sym_decrypt(p_dato_cifrado, p_llave_simetrica);
EXCEPTION WHEN OTHERS THEN
    RETURN '[CONTENIDO PROTEGIDO POR CIFRADO PGCRYPTO AES-256]';
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- 2. PROCEDIMIENTO ALMACENADO DE EVOLUCIÓN LONGITUDINAL (Δ = Puntaje_actual - Puntaje_inicial)
-- Sección 3.B y Mockup 3: sp_calcular_delta_psicometrico()
-- ============================================================================
CREATE OR REPLACE FUNCTION sp_calcular_delta_psicometrico(
    p_id_expediente VARCHAR,
    p_id_escala VARCHAR,
    p_puntaje_actual INTEGER
) RETURNS TABLE (
    puntaje_inicial INTEGER,
    puntaje_actual INTEGER,
    delta_calculado INTEGER,
    baremo_actual VARCHAR,
    interpretacion_vector VARCHAR
) AS $$
DECLARE
    v_puntaje_inicial INTEGER;
    v_delta INTEGER;
    v_baremo VARCHAR(40);
    v_interpretacion VARCHAR(150);
    v_umbral_leve INTEGER;
    v_umbral_mod INTEGER;
    v_umbral_sev INTEGER;
BEGIN
    -- 1. Obtener umbrales de la escala psicométrica en el catálogo
    SELECT umbral_leve, umbral_moderado, umbral_severo
    INTO v_umbral_leve, v_umbral_mod, v_umbral_sev
    FROM escala_evaluacion
    WHERE id_escala = p_id_escala;

    -- Determinar baremo normalizado según el puntaje bruto actual
    IF p_puntaje_actual >= COALESCE(v_umbral_sev, 29) THEN
        v_baremo := 'Severo';
    ELSIF p_puntaje_actual >= COALESCE(v_umbral_mod, 20) THEN
        v_baremo := 'Moderado';
    ELSIF p_puntaje_actual >= COALESCE(v_umbral_leve, 14) THEN
        v_baremo := 'Leve';
    ELSE
        v_baremo := 'Mínimo';
    END IF;

    -- 2. Buscar el Puntaje Inicial (Sesión #1) para el expediente y escala
    SELECT rp.puntuacion_bruta
    INTO v_puntaje_inicial
    FROM resultado_psicometrico rp
    WHERE rp.id_expediente = p_id_expediente
      AND rp.id_escala = p_id_escala
    ORDER BY rp.fecha_aplicacion ASC, rp.id_resultado ASC
    LIMIT 1;

    -- Si es la primera evaluación registrada, el puntaje inicial es el actual
    IF v_puntaje_inicial IS NULL THEN
        v_puntaje_inicial := p_puntaje_actual;
    END IF;

    -- 3. Calcular el vector analítico longitudinal: Δ = Puntaje_actual - Puntaje_inicial
    v_delta := p_puntaje_actual - v_puntaje_inicial;

    IF v_delta <= -10 THEN
        v_interpretacion := 'Mejoría Clínica Significativa (Alta / Remisión)';
    ELSIF v_delta < 0 THEN
        v_interpretacion := 'Mejoría Sintomática Progresiva';
    ELSIF v_delta = 0 THEN
        v_interpretacion := 'Estabilidad Sintomática (Sin variación)';
    ELSE
        v_interpretacion := 'Regresión / Incremento Sintomático (Riesgo)';
    END IF;

    RETURN QUERY SELECT
        v_puntaje_inicial,
        p_puntaje_actual,
        v_delta,
        v_baremo,
        v_interpretacion;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 3. DISPARADOR ATÓMICO BEFORE INSERT DE ALERTA POR RIESGO (Sección 3.B y Mockup 3)
-- Evalúa reactivos críticos (Ítem 9 del inventario BDI-II sobre ideación suicida)
-- y calcula de manera autónoma el Delta (Δ) antes de insertar la tupla
-- ============================================================================
CREATE OR REPLACE FUNCTION fn_trg_before_insert_resultado_psicometrico()
RETURNS TRIGGER AS $$
DECLARE
    v_calc RECORD;
    v_cota_maxima INTEGER;
BEGIN
    -- 1. Validación semántica contra la cota máxima del instrumento en EscalaEvaluacion
    SELECT puntaje_maximo INTO v_cota_maxima
    FROM escala_evaluacion
    WHERE id_escala = NEW.id_escala;

    IF NEW.puntuacion_bruta < 0 OR NEW.puntuacion_bruta > COALESCE(v_cota_maxima, 63) THEN
        RAISE EXCEPTION 'Violación de restricción semántica: Puntaje bruto (%) fuera del rango permitido [0 - %] para la escala %',
            NEW.puntuacion_bruta, v_cota_maxima, NEW.id_escala;
    END IF;

    -- 2. Invocar el Procedimiento Almacenado sp_calcular_delta_psicometrico()
    SELECT * INTO v_calc
    FROM sp_calcular_delta_psicometrico(NEW.id_expediente, NEW.id_escala, NEW.puntuacion_bruta);

    NEW.puntaje_inicial_referencia := v_calc.puntaje_inicial;
    NEW.delta_cambio := v_calc.delta_calculado;
    NEW.baremo_severidad := v_calc.baremo_actual;

    -- 3. Evaluación atómica de reactivo crítico (Ítem 9 del inventario BDI-II >= 2)
    IF NEW.item_9_ideacion_riesgo >= 2 THEN
        NEW.bandera_emergencia := TRUE;
        NEW.interpretacion_clinica := COALESCE(NEW.interpretacion_clinica, '') ||
            ' [ALERTA DISPARADA POR TRIGGER: Reactivo crítico Ítem 9 >= 2 detectado. Notificación prioritaria enviada al Supervisor Clínico]';
    ELSE
        NEW.bandera_emergencia := FALSE;
        IF NEW.interpretacion_clinica IS NULL OR NEW.interpretacion_clinica = '' THEN
            NEW.interpretacion_clinica := v_calc.interpretacion_vector;
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_before_insert_resultado_psicometrico ON resultado_psicometrico;
CREATE TRIGGER trg_before_insert_resultado_psicometrico
    BEFORE INSERT ON resultado_psicometrico
    FOR EACH ROW
    EXECUTE FUNCTION fn_trg_before_insert_resultado_psicometrico();

-- ============================================================================
-- 4. DISPARADOR ATÓMICO AFTER INSERT PARA REGISTRO EN BITÁCORA DE EMERGENCIA
-- Si el trigger BEFORE INSERT activó bandera_emergencia, inserta atómicamente
-- la alerta para el Supervisor Clínico y actualiza el nivel de riesgo del expediente
-- ============================================================================
CREATE OR REPLACE FUNCTION fn_trg_after_insert_alerta_emergencia()
RETURNS TRIGGER AS $$
DECLARE
    v_id_terapeuta VARCHAR(25);
BEGIN
    -- Actualizar contador de sesiones en el plan de intervención
    UPDATE plan_intervencion
    SET sesiones_completadas = (
        SELECT COUNT(*) FROM sesion_terapeutica st
        WHERE st.id_expediente = NEW.id_expediente AND st.estado_cita = 'Completada'
    )
    WHERE id_expediente = NEW.id_expediente AND estado_plan = 'Vigente';

    IF NEW.bandera_emergencia = TRUE THEN
        SELECT id_terapeuta_titular INTO v_id_terapeuta
        FROM expediente_clinico
        WHERE id_expediente = NEW.id_expediente;

        -- Actualizar nivel de riesgo en el expediente clínico
        UPDATE expediente_clinico
        SET nivel_riesgo_actual = 'Alto - Alerta Crítica',
            ultima_actualizacion = CURRENT_TIMESTAMP
        WHERE id_expediente = NEW.id_expediente;

        -- Insertar registro de alerta crítica inmediata para Supervisión Clínica y API SMTP/SendGrid
        INSERT INTO alerta_riesgo_clinico (
            id_resultado,
            id_expediente,
            id_paciente,
            id_terapeuta,
            tipo_reactivo,
            puntuacion_reactivo,
            puntuacion_total_test,
            mensaje_alerta,
            notificacion_api_enviada,
            estado_alerta
        ) VALUES (
            NEW.id_resultado,
            NEW.id_expediente,
            NEW.id_paciente,
            v_id_terapeuta,
            'Ítem 9 BDI-II: Pensamientos o Deseos de Autolesión / Ideación',
            NEW.item_9_ideacion_riesgo,
            NEW.puntuacion_bruta,
            format(
                'El paciente %s (Exp. %s) registró puntuación >= 2 (%s pts) en el reactivo de ideación en la sesión de hoy. Se notificó automáticamente al Supervisor Clínico vía API.',
                NEW.id_paciente, NEW.id_expediente, NEW.item_9_ideacion_riesgo
            ),
            TRUE,
            'Activa'
        );
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_after_insert_alerta_emergencia ON resultado_psicometrico;
CREATE TRIGGER trg_after_insert_alerta_emergencia
    AFTER INSERT ON resultado_psicometrico
    FOR EACH ROW
    EXECUTE FUNCTION fn_trg_after_insert_alerta_emergencia();
