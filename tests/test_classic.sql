SET SERVEROUTPUT ON
DECLARE
  PROCEDURE eq(p_name VARCHAR2, p_exp VARCHAR2, p_act VARCHAR2) IS
  BEGIN
    IF (p_exp IS NULL AND p_act IS NULL) OR p_exp = p_act THEN
      DBMS_OUTPUT.PUT_LINE('OK    classic: ' || p_name);
    ELSE
      RAISE_APPLICATION_ERROR(-20999, 'FALHOU ' || p_name || ': esperado=' || p_exp || ' obtido=' || p_act);
    END IF;
  END;
  PROCEDURE expect_error(p_name VARCHAR2, p_code NUMBER, p_sql VARCHAR2) IS
    v VARCHAR2(4000);
  BEGIN
    EXECUTE IMMEDIATE 'BEGIN :r := ' || p_sql || '; END;' USING OUT v;
    RAISE_APPLICATION_ERROR(-20999, 'FALHOU ' || p_name || ': esperava ORA' || p_code);
  EXCEPTION
    WHEN OTHERS THEN
      IF SQLCODE = p_code THEN
        DBMS_OUTPUT.PUT_LINE('OK    classic: ' || p_name);
      ELSE
        RAISE;
      END IF;
  END;
BEGIN
  eq('cesar +3', 'Def abc, XYZ!', pkg_ora_classic.encrypt_cesar('Abc xyz, UVW!', 3));
  eq('cesar roundtrip', 'Olá Mundo', pkg_ora_classic.decrypt_cesar(pkg_ora_classic.encrypt_cesar('Olá Mundo', 7), 7));
  eq('cesar negativo', 'Xyz', pkg_ora_classic.encrypt_cesar('Abc', -3));
  eq('cesar > 26', pkg_ora_classic.encrypt_cesar('Abc', 3), pkg_ora_classic.encrypt_cesar('Abc', 29));
  eq('cesar null', NULL, pkg_ora_classic.encrypt_cesar(NULL, 3));
  eq('vigenere vetor clássico', 'LXFOPVEFRNHR', pkg_ora_classic.encrypt_vigenere('ATTACKATDAWN', 'LEMON'));
  eq('vigenere chave minúscula', 'LXFOPVEFRNHR', pkg_ora_classic.encrypt_vigenere('ATTACKATDAWN', 'lemon'));
  eq('vigenere roundtrip', 'Ataque ao amanhecer, 5h!',
     pkg_ora_classic.decrypt_vigenere(pkg_ora_classic.encrypt_vigenere('Ataque ao amanhecer, 5h!', 'Chave'), 'Chave'));
  eq('vigenere pontuação não consome chave', 'LX FO', pkg_ora_classic.encrypt_vigenere('AT TA', 'LEMON'));
  expect_error('vigenere chave vazia', -20002, 'pkg_ora_classic.encrypt_vigenere(''abc'', NULL)');
  expect_error('vigenere chave inválida', -20002, 'pkg_ora_classic.encrypt_vigenere(''abc'', ''k3y'')');
  expect_error('cesar deslocamento fracionário', -20001, 'pkg_ora_classic.encrypt_cesar(''abc'', 1.5)');
END;
/
