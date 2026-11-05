-- Executar a partir da raiz do repositório, depois de @install.sql:
--   sqlplus usuario/senha@banco @tests/run_all.sql
SET SERVEROUTPUT ON
WHENEVER SQLERROR EXIT FAILURE ROLLBACK
@tests/test_classic.sql
@tests/test_crypto.sql
@tests/test_hash.sql
@tests/test_keys.sql
PROMPT Todos os testes passaram.
EXIT
