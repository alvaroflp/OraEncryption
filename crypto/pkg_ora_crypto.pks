-- AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC) sobre DBMS_CRYPTO.
-- Compatível com Oracle 12c ou superior (não depende de AES-GCM).
--
-- Formato do texto cifrado (BLOB):
--   modo chave : 0x01 | IV(16) | AES-256-CBC(dados) | HMAC(32)
--   modo senha : 0x02 | iterações(4) | salt(16) | <blob do modo chave>
-- Os dois são sempre autenticados: adulteração ou chave/senha errada gera
-- ORA-20010 antes de qualquer tentativa de descriptografar.
CREATE OR REPLACE PACKAGE pkg_ora_crypto AS

  c_default_iterations CONSTANT PLS_INTEGER := 100000;
  c_max_iterations     CONSTANT PLS_INTEGER := 10000000;

  -- Chave aleatória de 32 bytes (CSPRNG do banco)
  FUNCTION random_key RETURN RAW;

  -- PBKDF2-HMAC-SHA256, saída de 32 bytes
  FUNCTION pbkdf2_sha256(p_password   IN VARCHAR2,
                         p_salt       IN RAW,
                         p_iterations IN PLS_INTEGER DEFAULT c_default_iterations)
    RETURN RAW;

  -- Com chave binária de 32 bytes (use random_key ou uma chave gerenciada)
  FUNCTION encrypt_blob(p_data IN BLOB, p_key IN RAW) RETURN BLOB;
  FUNCTION decrypt_blob(p_data IN BLOB, p_key IN RAW) RETURN BLOB;

  -- Com senha (salt aleatório + PBKDF2)
  FUNCTION encrypt_blob_pw(p_data       IN BLOB,
                           p_password   IN VARCHAR2,
                           p_iterations IN PLS_INTEGER DEFAULT c_default_iterations)
    RETURN BLOB;
  FUNCTION decrypt_blob_pw(p_data IN BLOB, p_password IN VARCHAR2) RETURN BLOB;

  -- Texto -> Base64 (usa senha). Limite prático: ~20.000 caracteres.
  FUNCTION encrypt_aes(p_text       IN VARCHAR2,
                       p_password   IN VARCHAR2,
                       p_iterations IN PLS_INTEGER DEFAULT c_default_iterations)
    RETURN VARCHAR2;
  FUNCTION decrypt_aes(p_token IN VARCHAR2, p_password IN VARCHAR2)
    RETURN VARCHAR2;

  -- Utilitários
  FUNCTION raw_to_blob(p_raw IN RAW) RETURN BLOB;
  FUNCTION text_to_blob(p_text IN VARCHAR2) RETURN BLOB;
  FUNCTION blob_to_text(p_blob IN BLOB) RETURN VARCHAR2;
  FUNCTION blob_to_base64(p_blob IN BLOB) RETURN CLOB;
  FUNCTION base64_to_blob(p_b64 IN CLOB) RETURN BLOB;
  FUNCTION constant_time_equals(p_a IN RAW, p_b IN RAW) RETURN BOOLEAN;

END pkg_ora_crypto;
/
