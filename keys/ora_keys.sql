-- Tabela de chaves de criptografia de chaves (KEK), sempre armazenadas
-- criptografadas ("wrapped") pela chave mestra, que NUNCA fica no banco.
-- Script idempotente: ignora ORA-00955 (tabela já existe).
BEGIN
  EXECUTE IMMEDIATE '
    CREATE TABLE ora_keys (
      key_name    VARCHAR2(100) NOT NULL,
      key_version NUMBER(9)     NOT NULL,
      wrapped_key RAW(512)      NOT NULL,
      status      VARCHAR2(10)  DEFAULT ''ACTIVE'' NOT NULL,
      created_at  TIMESTAMP     DEFAULT SYSTIMESTAMP NOT NULL,
      retired_at  TIMESTAMP,
      CONSTRAINT pk_ora_keys PRIMARY KEY (key_name, key_version),
      CONSTRAINT ck_ora_keys_status CHECK (status IN (''ACTIVE'', ''RETIRED''))
    )';
  -- no máximo uma versão ACTIVE por nome de chave
  EXECUTE IMMEDIATE '
    CREATE UNIQUE INDEX ux_ora_keys_active ON ora_keys
      (CASE WHEN status = ''ACTIVE'' THEN key_name END)';
EXCEPTION
  WHEN OTHERS THEN
    IF SQLCODE NOT IN (-955, -1408) THEN
      RAISE;
    END IF;
END;
/
