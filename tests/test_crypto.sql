SET SERVEROUTPUT ON
DECLARE
  v_t1   VARCHAR2(32767);
  v_t2   VARCHAR2(32767);
  v_blob BLOB;
  v_key  RAW(32) := pkg_ora_crypto.random_key;
  v_plain VARCHAR2(100) := UNISTR('A\00E7\00E3o: dados secretos \20AC 123');

  PROCEDURE ok(p_name VARCHAR2, p_cond BOOLEAN) IS
  BEGIN
    IF p_cond THEN
      DBMS_OUTPUT.PUT_LINE('OK    crypto: ' || p_name);
    ELSE
      RAISE_APPLICATION_ERROR(-20999, 'FALHOU ' || p_name);
    END IF;
  END;
BEGIN
  -- PBKDF2-HMAC-SHA256, RFC 7914 §11: P="passwd", S="salt", c=1, dkLen=32 (32 primeiros bytes)
  ok('pbkdf2 vetor RFC (c=1)',
     RAWTOHEX(pkg_ora_crypto.pbkdf2_sha256('passwd', UTL_RAW.CAST_TO_RAW('salt'), 1)) =
     '55AC046E56E3089FEC1691C22544B605F94185216DDE0465E68B9D57C20DACBC');

  -- senha
  v_t1 := pkg_ora_crypto.encrypt_aes(v_plain, 'senha-forte', 1000);
  v_t2 := pkg_ora_crypto.encrypt_aes(v_plain, 'senha-forte', 1000);
  ok('roundtrip com senha', pkg_ora_crypto.decrypt_aes(v_t1, 'senha-forte') = v_plain);
  ok('IV/salt aleatórios: mesmo texto, tokens diferentes', v_t1 <> v_t2);
  ok('sem quebras de linha no Base64', INSTR(v_t1, CHR(10)) = 0 AND INSTR(v_t1, CHR(13)) = 0);
  ok('NULL -> NULL', pkg_ora_crypto.encrypt_aes(NULL, 'x') IS NULL);

  BEGIN
    v_t2 := pkg_ora_crypto.decrypt_aes(v_t1, 'senha-errada');
    ok('senha errada deve falhar', FALSE);
  EXCEPTION
    WHEN OTHERS THEN
      ok('senha errada -> ORA-20010', SQLCODE = -20010);
  END;

  -- adulteração: inverte um byte no meio do payload
  v_blob := pkg_ora_crypto.base64_to_blob(TO_CLOB(v_t1));
  DBMS_LOB.WRITE(v_blob, 1, 40, UTL_RAW.BIT_XOR(DBMS_LOB.SUBSTR(v_blob, 1, 40), HEXTORAW('01')));
  BEGIN
    v_t2 := pkg_ora_crypto.decrypt_aes(DBMS_LOB.SUBSTR(pkg_ora_crypto.blob_to_base64(v_blob), 32767, 1), 'senha-forte');
    ok('adulteração deve falhar', FALSE);
  EXCEPTION
    WHEN OTHERS THEN
      ok('adulteração -> ORA-20010', SQLCODE = -20010);
  END;

  -- cabeçalho forjado com iterações absurdas não pode travar o servidor
  v_blob := pkg_ora_crypto.base64_to_blob(TO_CLOB(v_t1));
  DBMS_LOB.WRITE(v_blob, 4, 2, HEXTORAW('7FFFFFFF'));
  BEGIN
    v_t2 := pkg_ora_crypto.decrypt_aes(DBMS_LOB.SUBSTR(pkg_ora_crypto.blob_to_base64(v_blob), 32767, 1), 'senha-forte');
    ok('iterações forjadas devem falhar', FALSE);
  EXCEPTION
    WHEN OTHERS THEN
      ok('iterações forjadas -> ORA-20012', SQLCODE = -20012);
  END;

  -- chave binária
  v_blob := pkg_ora_crypto.encrypt_blob(pkg_ora_crypto.text_to_blob(v_plain), v_key);
  ok('roundtrip com chave binária',
     pkg_ora_crypto.blob_to_text(pkg_ora_crypto.decrypt_blob(v_blob, v_key)) = v_plain);
  BEGIN
    v_t2 := pkg_ora_crypto.blob_to_text(pkg_ora_crypto.decrypt_blob(v_blob, pkg_ora_crypto.random_key));
    ok('chave errada deve falhar', FALSE);
  EXCEPTION
    WHEN OTHERS THEN
      ok('chave errada -> ORA-20010', SQLCODE = -20010);
  END;

  -- BLOB grande (> 32 KB) atravessa Base64 intacto
  DECLARE
    v_big BLOB;
    v_dec BLOB;
  BEGIN
    DBMS_LOB.CREATETEMPORARY(v_big, TRUE);
    FOR i IN 1 .. 40 LOOP
      DBMS_LOB.WRITEAPPEND(v_big, 2000, UTL_RAW.COPIES(HEXTORAW('AB'), 2000));
    END LOOP;
    v_dec := pkg_ora_crypto.decrypt_blob_pw(
               pkg_ora_crypto.base64_to_blob(
                 pkg_ora_crypto.blob_to_base64(pkg_ora_crypto.encrypt_blob_pw(v_big, 'pw', 100))), 'pw');
    ok('roundtrip 80 KB', DBMS_LOB.COMPARE(v_big, v_dec) = 0);
  END;
END;
/
