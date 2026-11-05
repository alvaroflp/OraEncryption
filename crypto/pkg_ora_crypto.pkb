CREATE OR REPLACE PACKAGE BODY pkg_ora_crypto AS

  c_cipher CONSTANT PLS_INTEGER := DBMS_CRYPTO.ENCRYPT_AES256 +
                                   DBMS_CRYPTO.CHAIN_CBC +
                                   DBMS_CRYPTO.PAD_PKCS5;
  c_charset       CONSTANT VARCHAR2(10) := 'AL32UTF8';
  c_ver_key       CONSTANT RAW(1) := HEXTORAW('01');
  c_ver_pw        CONSTANT RAW(1) := HEXTORAW('02');
  c_iv_len        CONSTANT PLS_INTEGER := 16;
  c_mac_len       CONSTANT PLS_INTEGER := 32;
  c_salt_len      CONSTANT PLS_INTEGER := 16;
  c_pw_header_len CONSTANT PLS_INTEGER := 1 + 4 + 16;
  -- versão + IV + pelo menos 1 bloco AES + MAC
  c_min_key_blob  CONSTANT PLS_INTEGER := 1 + 16 + 16 + 32;

  ---------------------------------------------------------------------------
  -- Internos
  ---------------------------------------------------------------------------
  FUNCTION hmac(p_data IN RAW, p_key IN RAW) RETURN RAW IS
  BEGIN
    RETURN DBMS_CRYPTO.MAC(p_data, DBMS_CRYPTO.HMAC_SH256, p_key);
  END hmac;

  PROCEDURE check_iterations(p_iterations IN PLS_INTEGER) IS
  BEGIN
    IF p_iterations IS NULL OR p_iterations < 1 OR
       p_iterations > c_max_iterations THEN
      RAISE_APPLICATION_ERROR(-20012,
                              'Número de iterações inválido (1..' ||
                              c_max_iterations || ').');
    END IF;
  END check_iterations;

  -- Separa a chave de 32 bytes em chaves independentes de cifra e de MAC
  PROCEDURE derive_keys(p_key IN RAW, p_enc OUT RAW, p_mac OUT RAW) IS
  BEGIN
    IF p_key IS NULL OR UTL_RAW.LENGTH(p_key) <> 32 THEN
      RAISE_APPLICATION_ERROR(-20012, 'A chave deve ter exatamente 32 bytes.');
    END IF;
    p_enc := hmac(UTL_RAW.CAST_TO_RAW('ora-encryption-key'), p_key);
    p_mac := hmac(UTL_RAW.CAST_TO_RAW('ora-mac-key'), p_key);
  END derive_keys;

  ---------------------------------------------------------------------------
  -- Utilitários públicos
  ---------------------------------------------------------------------------
  FUNCTION random_key RETURN RAW IS
  BEGIN
    RETURN DBMS_CRYPTO.RANDOMBYTES(32);
  END random_key;

  FUNCTION constant_time_equals(p_a IN RAW, p_b IN RAW) RETURN BOOLEAN IS
    v_diff PLS_INTEGER := 0;
  BEGIN
    IF p_a IS NULL OR p_b IS NULL OR UTL_RAW.LENGTH(p_a) <> UTL_RAW.LENGTH(p_b) THEN
      RETURN FALSE;
    END IF;
    FOR i IN 1 .. UTL_RAW.LENGTH(p_a) LOOP
      v_diff := v_diff +
                ABS(UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(p_a, i, 1)) -
                    UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(p_b, i, 1)));
    END LOOP;
    RETURN v_diff = 0;
  END constant_time_equals;

  FUNCTION raw_to_blob(p_raw IN RAW) RETURN BLOB IS
    v_blob BLOB;
  BEGIN
    DBMS_LOB.CREATETEMPORARY(v_blob, TRUE);
    IF p_raw IS NOT NULL THEN
      DBMS_LOB.WRITEAPPEND(v_blob, UTL_RAW.LENGTH(p_raw), p_raw);
    END IF;
    RETURN v_blob;
  END raw_to_blob;

  FUNCTION text_to_blob(p_text IN VARCHAR2) RETURN BLOB IS
  BEGIN
    RETURN raw_to_blob(UTL_I18N.STRING_TO_RAW(p_text, c_charset));
  END text_to_blob;

  FUNCTION blob_to_text(p_blob IN BLOB) RETURN VARCHAR2 IS
  BEGIN
    IF DBMS_LOB.GETLENGTH(p_blob) > 32767 THEN
      RAISE_APPLICATION_ERROR(-20013, 'Conteúdo grande demais para VARCHAR2.');
    END IF;
    RETURN UTL_I18N.RAW_TO_CHAR(DBMS_LOB.SUBSTR(p_blob, 32767, 1), c_charset);
  END blob_to_text;

  FUNCTION blob_to_base64(p_blob IN BLOB) RETURN CLOB IS
    c_chunk CONSTANT PLS_INTEGER := 12000; -- múltiplo de 3: sem padding no meio
    v_len NUMBER := DBMS_LOB.GETLENGTH(p_blob);
    v_pos NUMBER := 1;
    v_amt PLS_INTEGER;
    v_str VARCHAR2(32767);
    v_res CLOB;
  BEGIN
    DBMS_LOB.CREATETEMPORARY(v_res, TRUE);
    WHILE v_pos <= v_len LOOP
      v_amt := LEAST(c_chunk, v_len - v_pos + 1);
      v_str := REPLACE(REPLACE(UTL_RAW.CAST_TO_VARCHAR2(UTL_ENCODE.BASE64_ENCODE(DBMS_LOB.SUBSTR(p_blob,
                                                                                                 v_amt,
                                                                                                 v_pos))),
                               CHR(13)),
                       CHR(10));
      DBMS_LOB.WRITEAPPEND(v_res, LENGTH(v_str), v_str);
      v_pos := v_pos + v_amt;
    END LOOP;
    RETURN v_res;
  END blob_to_base64;

  FUNCTION base64_to_blob(p_b64 IN CLOB) RETURN BLOB IS
    c_chunk CONSTANT PLS_INTEGER := 16000;
    v_len NUMBER := DBMS_LOB.GETLENGTH(p_b64);
    v_pos NUMBER := 1;
    v_buf VARCHAR2(32767);
    v_use PLS_INTEGER;
    v_res BLOB;
  BEGIN
    DBMS_LOB.CREATETEMPORARY(v_res, TRUE);
    WHILE v_pos <= v_len LOOP
      -- remove espaços/quebras de linha e decodifica em múltiplos de 4 chars
      v_buf := v_buf ||
               REPLACE(REPLACE(REPLACE(DBMS_LOB.SUBSTR(p_b64, c_chunk, v_pos),
                                       CHR(13)),
                               CHR(10)),
                       ' ');
      v_pos := v_pos + c_chunk;
      v_use := TRUNC(LENGTH(v_buf) / 4) * 4;
      IF v_pos > v_len THEN
        v_use := LENGTH(v_buf); -- último pedaço
      END IF;
      IF v_use > 0 THEN
        DBMS_LOB.APPEND(v_res,
                        raw_to_blob(UTL_ENCODE.BASE64_DECODE(UTL_RAW.CAST_TO_RAW(SUBSTR(v_buf,
                                                                                         1,
                                                                                         v_use)))));
        v_buf := SUBSTR(v_buf, v_use + 1);
      END IF;
    END LOOP;
    RETURN v_res;
  END base64_to_blob;

  ---------------------------------------------------------------------------
  -- PBKDF2-HMAC-SHA256 (RFC 8018), um bloco = 32 bytes de saída
  ---------------------------------------------------------------------------
  FUNCTION pbkdf2_sha256(p_password   IN VARCHAR2,
                         p_salt       IN RAW,
                         p_iterations IN PLS_INTEGER DEFAULT c_default_iterations)
    RETURN RAW IS
    v_pw RAW(32767);
    v_u  RAW(32);
    v_t  RAW(32);
  BEGIN
    IF p_password IS NULL THEN
      RAISE_APPLICATION_ERROR(-20012, 'Senha não pode ser vazia.');
    END IF;
    IF p_salt IS NULL OR UTL_RAW.LENGTH(p_salt) < 8 THEN
      RAISE_APPLICATION_ERROR(-20012, 'Salt deve ter ao menos 8 bytes.');
    END IF;
    check_iterations(p_iterations);
    v_pw := UTL_I18N.STRING_TO_RAW(p_password, c_charset);
    v_u  := hmac(UTL_RAW.CONCAT(p_salt, HEXTORAW('00000001')), v_pw);
    v_t  := v_u;
    FOR i IN 2 .. p_iterations LOOP
      v_u := hmac(v_u, v_pw);
      v_t := UTL_RAW.BIT_XOR(v_t, v_u);
    END LOOP;
    RETURN v_t;
  END pbkdf2_sha256;

  ---------------------------------------------------------------------------
  -- Modo chave
  ---------------------------------------------------------------------------
  FUNCTION encrypt_blob(p_data IN BLOB, p_key IN RAW) RETURN BLOB IS
    v_enc_key RAW(32);
    v_mac_key RAW(32);
    v_iv      RAW(16);
    v_ct      BLOB;
    v_out     BLOB;
  BEGIN
    IF p_data IS NULL THEN
      RETURN NULL;
    END IF;
    IF DBMS_LOB.GETLENGTH(p_data) = 0 THEN
      RAISE_APPLICATION_ERROR(-20013, 'Dados vazios não são suportados.');
    END IF;
    derive_keys(p_key, v_enc_key, v_mac_key);
    v_iv := DBMS_CRYPTO.RANDOMBYTES(c_iv_len); -- IV novo a cada chamada

    DBMS_LOB.CREATETEMPORARY(v_ct, TRUE);
    DBMS_CRYPTO.ENCRYPT(v_ct, p_data, c_cipher, v_enc_key, v_iv);

    DBMS_LOB.CREATETEMPORARY(v_out, TRUE);
    DBMS_LOB.WRITEAPPEND(v_out, 1, c_ver_key);
    DBMS_LOB.WRITEAPPEND(v_out, c_iv_len, v_iv);
    DBMS_LOB.APPEND(v_out, v_ct);
    DBMS_LOB.WRITEAPPEND(v_out,
                         c_mac_len,
                         DBMS_CRYPTO.MAC(v_out,
                                         DBMS_CRYPTO.HMAC_SH256,
                                         v_mac_key));
    DBMS_LOB.FREETEMPORARY(v_ct);
    RETURN v_out;
  END encrypt_blob;

  FUNCTION decrypt_blob(p_data IN BLOB, p_key IN RAW) RETURN BLOB IS
    v_enc_key RAW(32);
    v_mac_key RAW(32);
    v_len     NUMBER;
    v_body    BLOB;
    v_ct      BLOB;
    v_out     BLOB;
    v_iv      RAW(16);
    v_mac     RAW(32);
    v_calc    RAW(32);
  BEGIN
    IF p_data IS NULL THEN
      RETURN NULL;
    END IF;
    v_len := DBMS_LOB.GETLENGTH(p_data);
    IF v_len < c_min_key_blob OR DBMS_LOB.SUBSTR(p_data, 1, 1) <> c_ver_key THEN
      RAISE_APPLICATION_ERROR(-20011, 'Formato de texto cifrado inválido.');
    END IF;
    derive_keys(p_key, v_enc_key, v_mac_key);

    -- 1) autenticar
    v_mac := DBMS_LOB.SUBSTR(p_data, c_mac_len, v_len - c_mac_len + 1);
    DBMS_LOB.CREATETEMPORARY(v_body, TRUE);
    DBMS_LOB.COPY(v_body, p_data, v_len - c_mac_len, 1, 1);
    v_calc := DBMS_CRYPTO.MAC(v_body, DBMS_CRYPTO.HMAC_SH256, v_mac_key);
    DBMS_LOB.FREETEMPORARY(v_body);
    IF NOT constant_time_equals(v_mac, v_calc) THEN
      RAISE_APPLICATION_ERROR(-20010,
                              'Falha de autenticação: chave/senha incorreta ou dados adulterados.');
    END IF;

    -- 2) só então descriptografar
    v_iv := DBMS_LOB.SUBSTR(p_data, c_iv_len, 2);
    DBMS_LOB.CREATETEMPORARY(v_ct, TRUE);
    DBMS_LOB.COPY(v_ct, p_data, v_len - c_mac_len - 1 - c_iv_len, 1, 2 + c_iv_len);
    DBMS_LOB.CREATETEMPORARY(v_out, TRUE);
    DBMS_CRYPTO.DECRYPT(v_out, v_ct, c_cipher, v_enc_key, v_iv);
    DBMS_LOB.FREETEMPORARY(v_ct);
    RETURN v_out;
  END decrypt_blob;

  ---------------------------------------------------------------------------
  -- Modo senha
  ---------------------------------------------------------------------------
  FUNCTION encrypt_blob_pw(p_data       IN BLOB,
                           p_password   IN VARCHAR2,
                           p_iterations IN PLS_INTEGER DEFAULT c_default_iterations)
    RETURN BLOB IS
    v_salt  RAW(16);
    v_key   RAW(32);
    v_inner BLOB;
    v_out   BLOB;
  BEGIN
    IF p_data IS NULL THEN
      RETURN NULL;
    END IF;
    check_iterations(p_iterations);
    v_salt  := DBMS_CRYPTO.RANDOMBYTES(c_salt_len);
    v_key   := pbkdf2_sha256(p_password, v_salt, p_iterations);
    v_inner := encrypt_blob(p_data, v_key);

    DBMS_LOB.CREATETEMPORARY(v_out, TRUE);
    DBMS_LOB.WRITEAPPEND(v_out, 1, c_ver_pw);
    DBMS_LOB.WRITEAPPEND(v_out,
                         4,
                         UTL_RAW.CAST_FROM_BINARY_INTEGER(p_iterations,
                                                          UTL_RAW.BIG_ENDIAN));
    DBMS_LOB.WRITEAPPEND(v_out, c_salt_len, v_salt);
    DBMS_LOB.APPEND(v_out, v_inner);
    DBMS_LOB.FREETEMPORARY(v_inner);
    RETURN v_out;
  END encrypt_blob_pw;

  FUNCTION decrypt_blob_pw(p_data IN BLOB, p_password IN VARCHAR2) RETURN BLOB IS
    v_len    NUMBER;
    v_header RAW(21);
    v_iter   PLS_INTEGER;
    v_salt   RAW(16);
    v_key    RAW(32);
    v_inner  BLOB;
  BEGIN
    IF p_data IS NULL THEN
      RETURN NULL;
    END IF;
    v_len := DBMS_LOB.GETLENGTH(p_data);
    IF v_len < c_pw_header_len + c_min_key_blob THEN
      RAISE_APPLICATION_ERROR(-20011, 'Formato de texto cifrado inválido.');
    END IF;
    v_header := DBMS_LOB.SUBSTR(p_data, c_pw_header_len, 1);
    IF UTL_RAW.SUBSTR(v_header, 1, 1) <> c_ver_pw THEN
      RAISE_APPLICATION_ERROR(-20011, 'Formato de texto cifrado inválido.');
    END IF;
    v_iter := UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(v_header, 2, 4),
                                             UTL_RAW.BIG_ENDIAN);
    check_iterations(v_iter); -- evita DoS por cabeçalho forjado
    v_salt := UTL_RAW.SUBSTR(v_header, 6, c_salt_len);
    v_key  := pbkdf2_sha256(p_password, v_salt, v_iter);

    DBMS_LOB.CREATETEMPORARY(v_inner, TRUE);
    DBMS_LOB.COPY(v_inner, p_data, v_len - c_pw_header_len, 1, c_pw_header_len + 1);
    RETURN decrypt_blob(v_inner, v_key);
  END decrypt_blob_pw;

  ---------------------------------------------------------------------------
  -- Texto <-> Base64
  ---------------------------------------------------------------------------
  FUNCTION encrypt_aes(p_text       IN VARCHAR2,
                       p_password   IN VARCHAR2,
                       p_iterations IN PLS_INTEGER DEFAULT c_default_iterations)
    RETURN VARCHAR2 IS
    v_b64 CLOB;
  BEGIN
    IF p_text IS NULL THEN
      RETURN NULL;
    END IF;
    v_b64 := blob_to_base64(encrypt_blob_pw(text_to_blob(p_text),
                                            p_password,
                                            p_iterations));
    IF DBMS_LOB.GETLENGTH(v_b64) > 32767 THEN
      RAISE_APPLICATION_ERROR(-20013,
                              'Resultado grande demais para VARCHAR2; use encrypt_blob_pw.');
    END IF;
    RETURN DBMS_LOB.SUBSTR(v_b64, 32767, 1);
  END encrypt_aes;

  FUNCTION decrypt_aes(p_token IN VARCHAR2, p_password IN VARCHAR2)
    RETURN VARCHAR2 IS
  BEGIN
    IF p_token IS NULL THEN
      RETURN NULL;
    END IF;
    RETURN blob_to_text(decrypt_blob_pw(base64_to_blob(TO_CLOB(p_token)),
                                        p_password));
  END decrypt_aes;

END pkg_ora_crypto;
/
