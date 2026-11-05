-- Instalação completa. Execute a partir da raiz do repositório:
--   sqlplus usuario/senha@banco @install.sql
--
-- Pré-requisito (como SYS, uma vez):
--   GRANT EXECUTE ON SYS.DBMS_CRYPTO TO <usuario>;
SET DEFINE OFF
SET SERVEROUTPUT ON
WHENEVER SQLERROR EXIT FAILURE ROLLBACK

PROMPT == Cifras clássicas
@classic/pkg_ora_classic.pks
@classic/pkg_ora_classic.pkb
@classic/legacy_functions.sql

PROMPT == AES-256 + PBKDF2 + HMAC
@crypto/pkg_ora_crypto.pks
@crypto/pkg_ora_crypto.pkb

PROMPT == Hash e senhas
@hash/pkg_ora_hash.pks
@hash/pkg_ora_hash.pkb

PROMPT == Gestão de chaves
@keys/ora_keys.sql
@keys/pkg_ora_keys.pks
@keys/pkg_ora_keys.pkb

PROMPT == Verificando objetos inválidos
DECLARE
  v_bad NUMBER;
BEGIN
  SELECT COUNT(*) INTO v_bad FROM user_objects WHERE status = 'INVALID';
  IF v_bad > 0 THEN
    RAISE_APPLICATION_ERROR(-20900, v_bad || ' objeto(s) inválido(s); veja USER_ERRORS.');
  END IF;
END;
/
PROMPT Instalação concluída.
