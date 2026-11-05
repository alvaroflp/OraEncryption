CREATE OR REPLACE PACKAGE BODY pkg_ora_keys AS

  g_master RAW(32);

  FUNCTION master_key RETURN RAW IS
  BEGIN
    IF g_master IS NULL THEN
      RAISE_APPLICATION_ERROR(-20021,
                              'Chave mestra não definida; chame set_master_key.');
    END IF;
    RETURN g_master;
  END master_key;

  PROCEDURE check_master(p_key IN RAW) IS
  BEGIN
    IF p_key IS NULL OR UTL_RAW.LENGTH(p_key) <> 32 THEN
      RAISE_APPLICATION_ERROR(-20025, 'A chave mestra deve ter 32 bytes.');
    END IF;
  END check_master;

  PROCEDURE set_master_key(p_master_key IN RAW) IS
  BEGIN
    check_master(p_master_key);
    g_master := p_master_key;
  END set_master_key;

  PROCEDURE clear_master_key IS
  BEGIN
    g_master := NULL;
  END clear_master_key;

  -- RAW <-> BLOB helpers para (des)embrulhar chaves
  FUNCTION wrap_key(p_key IN RAW, p_master IN RAW) RETURN RAW IS
  BEGIN
    RETURN DBMS_LOB.SUBSTR(pkg_ora_crypto.encrypt_blob(pkg_ora_crypto.raw_to_blob(p_key),
                                                       p_master),
                           32767,
                           1);
  END wrap_key;

  FUNCTION unwrap_key(p_wrapped IN RAW, p_master IN RAW) RETURN RAW IS
  BEGIN
    RETURN DBMS_LOB.SUBSTR(pkg_ora_crypto.decrypt_blob(pkg_ora_crypto.raw_to_blob(p_wrapped),
                                                       p_master),
                           32767,
                           1);
  END unwrap_key;

  PROCEDURE check_name(p_key_name IN VARCHAR2) IS
  BEGIN
    IF p_key_name IS NULL THEN
      RAISE_APPLICATION_ERROR(-20022, 'Nome da chave não pode ser vazio.');
    END IF;
  END check_name;

  FUNCTION active_version(p_key_name IN VARCHAR2) RETURN NUMBER IS
    v_ver NUMBER;
  BEGIN
    SELECT key_version
      INTO v_ver
      FROM ora_keys
     WHERE key_name = p_key_name
       AND status = 'ACTIVE';
    RETURN v_ver;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      RAISE_APPLICATION_ERROR(-20022,
                              'Nenhuma chave ativa com o nome ' || p_key_name || '.');
  END active_version;

  FUNCTION get_kek(p_key_name IN VARCHAR2, p_version IN NUMBER) RETURN RAW IS
    v_wrapped RAW(512);
  BEGIN
    SELECT wrapped_key
      INTO v_wrapped
      FROM ora_keys
     WHERE key_name = p_key_name
       AND key_version = p_version;
    RETURN unwrap_key(v_wrapped, master_key);
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      RAISE_APPLICATION_ERROR(-20022,
                              'Chave ' || p_key_name || ' versão ' || p_version ||
                              ' não encontrada.');
  END get_kek;

  PROCEDURE change_master_key(p_old_master IN RAW, p_new_master IN RAW) IS
  BEGIN
    check_master(p_old_master);
    check_master(p_new_master);
    FOR r IN (SELECT key_name, key_version, wrapped_key
                FROM ora_keys
                 FOR UPDATE) LOOP
      UPDATE ora_keys
         SET wrapped_key = wrap_key(unwrap_key(r.wrapped_key, p_old_master),
                                    p_new_master)
       WHERE key_name = r.key_name
         AND key_version = r.key_version;
    END LOOP;
    g_master := p_new_master;
  END change_master_key;

  FUNCTION create_key(p_key_name IN VARCHAR2) RETURN NUMBER IS
    v_cnt NUMBER;
  BEGIN
    check_name(p_key_name);
    SELECT COUNT(*) INTO v_cnt FROM ora_keys WHERE key_name = p_key_name;
    IF v_cnt > 0 THEN
      RAISE_APPLICATION_ERROR(-20023,
                              'Já existe uma chave chamada ' || p_key_name ||
                              '; use rotate_key.');
    END IF;
    INSERT INTO ora_keys
      (key_name, key_version, wrapped_key, status)
    VALUES
      (p_key_name, 1, wrap_key(pkg_ora_crypto.random_key, master_key), 'ACTIVE');
    RETURN 1;
  END create_key;

  FUNCTION rotate_key(p_key_name IN VARCHAR2) RETURN NUMBER IS
    v_ver NUMBER;
    v_new RAW(512);
  BEGIN
    check_name(p_key_name);
    v_new := wrap_key(pkg_ora_crypto.random_key, master_key); -- falha cedo sem mestra
    BEGIN
      SELECT key_version
        INTO v_ver
        FROM ora_keys
       WHERE key_name = p_key_name
         AND status = 'ACTIVE'
         FOR UPDATE;
    EXCEPTION
      WHEN NO_DATA_FOUND THEN
        RAISE_APPLICATION_ERROR(-20022,
                                'Nenhuma chave ativa com o nome ' || p_key_name || '.');
    END;
    UPDATE ora_keys
       SET status = 'RETIRED', retired_at = SYSTIMESTAMP
     WHERE key_name = p_key_name
       AND key_version = v_ver;
    INSERT INTO ora_keys
      (key_name, key_version, wrapped_key, status)
    VALUES
      (p_key_name, v_ver + 1, v_new, 'ACTIVE');
    RETURN v_ver + 1;
  END rotate_key;

  FUNCTION encrypt_text(p_key_name IN VARCHAR2, p_text IN VARCHAR2)
    RETURN VARCHAR2 IS
    v_ver     NUMBER;
    v_kek     RAW(32);
    v_dek     RAW(32) := pkg_ora_crypto.random_key; -- uma DEK nova por registro
    v_wrapped RAW(512);
    v_payload BLOB;
    v_data    BLOB;
    v_b64     CLOB;
  BEGIN
    IF p_text IS NULL THEN
      RETURN NULL;
    END IF;
    check_name(p_key_name);
    v_ver     := active_version(p_key_name);
    v_kek     := get_kek(p_key_name, v_ver);
    v_wrapped := wrap_key(v_dek, v_kek);
    v_data    := pkg_ora_crypto.encrypt_blob(pkg_ora_crypto.text_to_blob(p_text),
                                             v_dek);

    -- payload = tamanho(4) | DEK embrulhada | dado cifrado
    DBMS_LOB.CREATETEMPORARY(v_payload, TRUE);
    DBMS_LOB.WRITEAPPEND(v_payload,
                         4,
                         UTL_RAW.CAST_FROM_BINARY_INTEGER(UTL_RAW.LENGTH(v_wrapped),
                                                          UTL_RAW.BIG_ENDIAN));
    DBMS_LOB.WRITEAPPEND(v_payload, UTL_RAW.LENGTH(v_wrapped), v_wrapped);
    DBMS_LOB.APPEND(v_payload, v_data);

    v_b64 := pkg_ora_crypto.blob_to_base64(v_payload);
    IF DBMS_LOB.GETLENGTH(v_b64) > 32000 THEN
      RAISE_APPLICATION_ERROR(-20013, 'Resultado grande demais para VARCHAR2.');
    END IF;
    RETURN 'v' || v_ver || '.' || DBMS_LOB.SUBSTR(v_b64, 32000, 1);
  END encrypt_text;

  FUNCTION decrypt_text(p_key_name IN VARCHAR2, p_token IN VARCHAR2)
    RETURN VARCHAR2 IS
    v_ver     NUMBER;
    v_payload BLOB;
    v_len     NUMBER;
    v_wlen    PLS_INTEGER;
    v_wrapped RAW(512);
    v_dek     RAW(32);
    v_data    BLOB;
  BEGIN
    IF p_token IS NULL THEN
      RETURN NULL;
    END IF;
    check_name(p_key_name);
    IF NOT REGEXP_LIKE(p_token, '^v[0-9]{1,9}\.[A-Za-z0-9+/=]+$') THEN
      RAISE_APPLICATION_ERROR(-20024, 'Token inválido.');
    END IF;
    v_ver     := TO_NUMBER(SUBSTR(p_token, 2, INSTR(p_token, '.') - 2));
    v_payload := pkg_ora_crypto.base64_to_blob(TO_CLOB(SUBSTR(p_token,
                                                              INSTR(p_token, '.') + 1)));
    v_len := DBMS_LOB.GETLENGTH(v_payload);
    IF v_len < 5 THEN
      RAISE_APPLICATION_ERROR(-20024, 'Token inválido.');
    END IF;
    v_wlen := UTL_RAW.CAST_TO_BINARY_INTEGER(DBMS_LOB.SUBSTR(v_payload, 4, 1),
                                             UTL_RAW.BIG_ENDIAN);
    IF v_wlen < 1 OR v_wlen > 512 OR 4 + v_wlen >= v_len THEN
      RAISE_APPLICATION_ERROR(-20024, 'Token inválido.');
    END IF;
    v_wrapped := DBMS_LOB.SUBSTR(v_payload, v_wlen, 5);
    v_dek     := unwrap_key(v_wrapped, get_kek(p_key_name, v_ver));

    DBMS_LOB.CREATETEMPORARY(v_data, TRUE);
    DBMS_LOB.COPY(v_data, v_payload, v_len - 4 - v_wlen, 1, 5 + v_wlen);
    RETURN pkg_ora_crypto.blob_to_text(pkg_ora_crypto.decrypt_blob(v_data, v_dek));
  END decrypt_text;

  FUNCTION reencrypt_text(p_key_name IN VARCHAR2, p_token IN VARCHAR2)
    RETURN VARCHAR2 IS
  BEGIN
    RETURN encrypt_text(p_key_name, decrypt_text(p_key_name, p_token));
  END reencrypt_text;

END pkg_ora_keys;
/
