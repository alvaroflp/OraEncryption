SET SERVEROUTPUT ON
DECLARE
  v_h VARCHAR2(200);
  PROCEDURE ok(p_name VARCHAR2, p_cond BOOLEAN) IS
  BEGIN
    IF p_cond THEN
      DBMS_OUTPUT.PUT_LINE('OK    hash: ' || p_name);
    ELSE
      RAISE_APPLICATION_ERROR(-20999, 'FALHOU ' || p_name);
    END IF;
  END;
BEGIN
  ok('sha256("abc")',
     pkg_ora_hash.sha256('abc') = 'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD');
  ok('sha512("abc") prefixo',
     pkg_ora_hash.sha512('abc') LIKE 'DDAF35A193617ABACC417349AE204131%');
  -- RFC 4231, caso 2
  ok('hmac-sha256 RFC 4231 #2',
     pkg_ora_hash.hmac_sha256('what do ya want for nothing?', 'Jefe') =
     '5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843');

  v_h := pkg_ora_hash.hash_password('s3nha!', 1000);
  ok('formato do hash', v_h LIKE 'pbkdf2-sha256$1000$%');
  ok('senha correta confere', pkg_ora_hash.verify_password('s3nha!', v_h));
  ok('senha errada não confere', NOT pkg_ora_hash.verify_password('s3nha?', v_h));
  ok('salt aleatório', v_h <> pkg_ora_hash.hash_password('s3nha!', 1000));
  ok('registro malformado -> FALSE', NOT pkg_ora_hash.verify_password('x', 'lixo'));
  ok('uso em SQL', pkg_ora_hash.is_password_valid('s3nha!', v_h) = 1);
END;
/
