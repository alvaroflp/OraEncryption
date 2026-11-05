CREATE OR REPLACE PACKAGE BODY pkg_ora_hash AS

  c_charset CONSTANT VARCHAR2(10) := 'AL32UTF8';
  c_prefix  CONSTANT VARCHAR2(20) := 'pbkdf2-sha256';

  FUNCTION to_raw(p_text IN VARCHAR2) RETURN RAW IS
  BEGIN
    RETURN UTL_I18N.STRING_TO_RAW(p_text, c_charset);
  END to_raw;

  FUNCTION sha256(p_text IN VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
    IF p_text IS NULL THEN
      RETURN NULL;
    END IF;
    RETURN RAWTOHEX(DBMS_CRYPTO.HASH(to_raw(p_text), DBMS_CRYPTO.HASH_SH256));
  END sha256;

  FUNCTION sha512(p_text IN VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
    IF p_text IS NULL THEN
      RETURN NULL;
    END IF;
    RETURN RAWTOHEX(DBMS_CRYPTO.HASH(to_raw(p_text), DBMS_CRYPTO.HASH_SH512));
  END sha512;

  FUNCTION hmac_sha256(p_text IN VARCHAR2, p_key IN VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
    IF p_text IS NULL THEN
      RETURN NULL;
    END IF;
    IF p_key IS NULL THEN
      RAISE_APPLICATION_ERROR(-20012, 'Chave não pode ser vazia.');
    END IF;
    RETURN RAWTOHEX(DBMS_CRYPTO.MAC(to_raw(p_text),
                                    DBMS_CRYPTO.HMAC_SH256,
                                    to_raw(p_key)));
  END hmac_sha256;

  FUNCTION hash_password(p_password   IN VARCHAR2,
                         p_iterations IN PLS_INTEGER DEFAULT pkg_ora_crypto.c_default_iterations)
    RETURN VARCHAR2 IS
    v_salt RAW(16) := DBMS_CRYPTO.RANDOMBYTES(16);
  BEGIN
    RETURN c_prefix || '$' || p_iterations || '$' || RAWTOHEX(v_salt) || '$' || RAWTOHEX(pkg_ora_crypto.pbkdf2_sha256(p_password,
                                                                                                                      v_salt,
                                                                                                                      p_iterations));
  END hash_password;

  FUNCTION verify_password(p_password IN VARCHAR2, p_stored IN VARCHAR2)
    RETURN BOOLEAN IS
    v_iter PLS_INTEGER;
    v_salt RAW(64);
    v_hash RAW(64);
  BEGIN
    IF p_password IS NULL OR p_stored IS NULL OR
       NOT REGEXP_LIKE(p_stored,
                       '^' || c_prefix || '\$[0-9]{1,8}\$([0-9A-Fa-f]{2}){8,64}\$[0-9A-Fa-f]{64}$') THEN
      RETURN FALSE;
    END IF;
    v_iter := TO_NUMBER(REGEXP_SUBSTR(p_stored, '[^$]+', 1, 2));
    IF v_iter < 1 OR v_iter > pkg_ora_crypto.c_max_iterations THEN
      RETURN FALSE;
    END IF;
    v_salt := HEXTORAW(REGEXP_SUBSTR(p_stored, '[^$]+', 1, 3));
    v_hash := HEXTORAW(REGEXP_SUBSTR(p_stored, '[^$]+', 1, 4));
    RETURN pkg_ora_crypto.constant_time_equals(pkg_ora_crypto.pbkdf2_sha256(p_password,
                                                                            v_salt,
                                                                            v_iter),
                                               v_hash);
  EXCEPTION
    WHEN VALUE_ERROR OR INVALID_NUMBER THEN
      RETURN FALSE; -- registro armazenado malformado (ex.: salt curto/ímpar)
  END verify_password;

  FUNCTION is_password_valid(p_password IN VARCHAR2, p_stored IN VARCHAR2)
    RETURN NUMBER IS
  BEGIN
    RETURN CASE WHEN verify_password(p_password, p_stored) THEN 1 ELSE 0 END;
  END is_password_valid;

END pkg_ora_hash;
/
