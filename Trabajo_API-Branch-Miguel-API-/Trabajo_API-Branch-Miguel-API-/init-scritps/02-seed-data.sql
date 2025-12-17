-- ============================================
-- Script de datos de ejemplo (SEED DATA)
-- ============================================

-- Este script se ejecuta DESPUÉS de que la aplicación
-- cree las tablas, así que solo insertamos datos si no existen

DO $$
BEGIN
    -- Verificar si ya hay datos
    IF NOT EXISTS (SELECT 1 FROM "user" WHERE username = 'testuser') THEN
        
        RAISE NOTICE '📦 Insertando datos de ejemplo...';
        
        -- Insertar usuario de prueba (password: TestPass123!)
        -- Hash generado con Argon2: $argon2id$v=19$m=65536,t=2,p=4$...
        INSERT INTO "user" (username, email, hashed_password, role, is_active, created_at)
        VALUES 
        ('testuser', 'test@example.com', '$argon2id$v=19$m=65536,t=2,p=4$randomsalthere', 'user', true, NOW());
        
        RAISE NOTICE '✅ Usuario de prueba creado: testuser / TestPass123!';
        
        -- Nota: El admin se crea automáticamente en el entrypoint del backend
        
    ELSE
        RAISE NOTICE 'ℹ️  Datos de ejemplo ya existen, saltando...';
    END IF;
    
END $$;