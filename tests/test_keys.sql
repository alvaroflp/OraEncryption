SET SERVEROUTPUT ON
DECLARE
  v_master  RAW(32) := pkg_ora_crypto.random_key;
  v_master2 RAW(32) := pkg_ora_crypto.random_key;
  v_ver     NUMBER;
  v_old     VARCHAR2(32767);
  v_new     VARCHAR2(32767);
  v_x       VARCHAR2(32767);

  PROCEDURE ok(p_name VARCHAR2, p_cond BOOLEAN) IS
  BEGIN
    IF p_cond THEN
      DBMS_OUTPUT.PUT_LINE('OK    keys: ' || p_name);
    ELSE
      RAISE_APPLICATION_ERROR(-20999, 'FALHOU ' || p_name);
    END IF;
  END;
BEGIN
  pkg_ora_keys.clear_master_key;
  BEGIN
    v_ver := pkg_ora_keys.create_key('TESTE');
    ok('sem chave mestra deve falhar', FALSE);
  EXCEPTION
    WHEN OTHERS THEN
      ok('sem chave mestra -> ORA-20021', SQLCODE = -20021);
  END;

  pkg_ora_keys.set_master_key(v_master);
  v_ver := pkg_ora_keys.create_key('CPF');
  ok('create_key v1', v_ver = 1);

  v_old := pkg_ora_keys.encrypt_text('CPF', '123.456.789-09');
  ok('token carrega versão', v_old LIKE 'v1.%');
  ok('roundtrip envelope', pkg_ora_keys.decrypt_text('CPF', v_old) = '123.456.789-09');
  ok('DEK única por registro', v_old <> pkg_ora_keys.encrypt_text('CPF', '123.456.789-09'));

  v_ver := pkg_ora_keys.rotate_key('CPF');
  ok('rotate_key v2', v_ver = 2);
  v_new := pkg_ora_keys.encrypt_text('CPF', '123.456.789-09');
  ok('novos dados usam v2', v_new LIKE 'v2.%');
  ok('dados antigos ainda legíveis', pkg_ora_keys.decrypt_text('CPF', v_old) = '123.456.789-09');
  ok('reencrypt migra para v2', pkg_ora_keys.reencrypt_text('CPF', v_old) LIKE 'v2.%');

  -- troca de chave mestra: tokens continuam válidos, sem tocar nos dados
  pkg_ora_keys.change_master_key(v_master, v_master2);
  ok('após change_master_key', pkg_ora_keys.decrypt_text('CPF', v_old) = '123.456.789-09');
  pkg_ora_keys.set_master_key(v_master);
  BEGIN
    v_x := pkg_ora_keys.decrypt_text('CPF', v_old);
    ok('mestra antiga deve falhar', FALSE);
  EXCEPTION
    WHEN OTHERS THEN
      ok('mestra antiga -> ORA-20010', SQLCODE = -20010);
  END;

  BEGIN
    v_x := pkg_ora_keys.decrypt_text('CPF', 'lixo');
    ok('token inválido deve falhar', FALSE);
  EXCEPTION
    WHEN OTHERS THEN
      ok('token inválido -> ORA-20024', SQLCODE = -20024);
  END;

  pkg_ora_keys.clear_master_key;
  ROLLBACK; -- não deixa chaves de teste na tabela
END;
/
