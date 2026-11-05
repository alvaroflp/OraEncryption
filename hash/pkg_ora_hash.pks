-- Hashes, HMAC e armazenamento seguro de senhas.
CREATE OR REPLACE PACKAGE pkg_ora_hash AS

  -- Resumos em hexadecimal (maiúsculo). Entrada tratada como UTF-8.
  FUNCTION sha256(p_text IN VARCHAR2) RETURN VARCHAR2;
  FUNCTION sha512(p_text IN VARCHAR2) RETURN VARCHAR2;
  FUNCTION hmac_sha256(p_text IN VARCHAR2, p_key IN VARCHAR2) RETURN VARCHAR2;

  -- Hash de senha: 'pbkdf2-sha256$<iterações>$<salt hex>$<hash hex>'
  -- NÃO use sha256/sha512 puros para senhas.
  FUNCTION hash_password(p_password   IN VARCHAR2,
                         p_iterations IN PLS_INTEGER DEFAULT pkg_ora_crypto.c_default_iterations)
    RETURN VARCHAR2;

  -- Comparação em tempo constante
  FUNCTION verify_password(p_password IN VARCHAR2, p_stored IN VARCHAR2)
    RETURN BOOLEAN;

  -- Versão utilizável em SQL: 1 = confere, 0 = não confere
  FUNCTION is_password_valid(p_password IN VARCHAR2, p_stored IN VARCHAR2)
    RETURN NUMBER;

END pkg_ora_hash;
/
