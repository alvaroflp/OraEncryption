CREATE OR REPLACE PACKAGE BODY pkg_ora_classic AS

  -- Desloca uma letra ASCII dentro do alfabeto; demais caracteres passam direto.
  FUNCTION shift_char(p_ch IN VARCHAR2, p_shift IN PLS_INTEGER)
    RETURN VARCHAR2 IS
    v_code PLS_INTEGER := ASCII(p_ch);
    v_base PLS_INTEGER;
  BEGIN
    IF v_code BETWEEN 65 AND 90 THEN
      v_base := 65;
    ELSIF v_code BETWEEN 97 AND 122 THEN
      v_base := 97;
    ELSE
      RETURN p_ch;
    END IF;
    -- p_shift está em 0..25, portanto o resultado nunca é negativo
    RETURN CHR(MOD(v_code - v_base + p_shift, 26) + v_base);
  END shift_char;

  FUNCTION cesar(p_texto IN VARCHAR2, p_deslocamento IN NUMBER, p_dir IN PLS_INTEGER)
    RETURN VARCHAR2 IS
    v_shift  PLS_INTEGER;
    v_result VARCHAR2(32767);
  BEGIN
    IF p_texto IS NULL THEN
      RETURN NULL;
    END IF;
    IF p_deslocamento IS NULL OR p_deslocamento <> TRUNC(p_deslocamento) THEN
      RAISE_APPLICATION_ERROR(-20001, 'Deslocamento deve ser um número inteiro.');
    END IF;
    v_shift := MOD(MOD(p_dir * p_deslocamento, 26) + 26, 26);
    FOR i IN 1 .. LENGTH(p_texto) LOOP
      v_result := v_result || shift_char(SUBSTR(p_texto, i, 1), v_shift);
    END LOOP;
    RETURN v_result;
  END cesar;

  FUNCTION vigenere(p_texto IN VARCHAR2, p_chave IN VARCHAR2, p_dir IN PLS_INTEGER)
    RETURN VARCHAR2 IS
    v_key    VARCHAR2(4000);
    v_klen   PLS_INTEGER;
    v_ki     PLS_INTEGER := 0;
    v_ch     VARCHAR2(1 CHAR);
    v_code   PLS_INTEGER;
    v_shift  PLS_INTEGER;
    v_result VARCHAR2(32767);
  BEGIN
    IF p_texto IS NULL THEN
      RETURN NULL;
    END IF;
    IF p_chave IS NULL OR NOT REGEXP_LIKE(p_chave, '^[A-Za-z]+$') THEN
      RAISE_APPLICATION_ERROR(-20002,
                              'A chave deve conter apenas letras A-Z e não pode ser vazia.');
    END IF;
    v_key  := UPPER(p_chave);
    v_klen := LENGTH(v_key);
    FOR i IN 1 .. LENGTH(p_texto) LOOP
      v_ch   := SUBSTR(p_texto, i, 1);
      v_code := ASCII(v_ch);
      IF v_code BETWEEN 65 AND 90 OR v_code BETWEEN 97 AND 122 THEN
        v_shift  := MOD(MOD(p_dir * (ASCII(SUBSTR(v_key, MOD(v_ki, v_klen) + 1, 1)) - 65), 26) + 26, 26);
        v_ki     := v_ki + 1;
        v_result := v_result || shift_char(v_ch, v_shift);
      ELSE
        v_result := v_result || v_ch;
      END IF;
    END LOOP;
    RETURN v_result;
  END vigenere;

  FUNCTION encrypt_cesar(p_texto IN VARCHAR2, p_deslocamento IN NUMBER)
    RETURN VARCHAR2 IS
  BEGIN
    RETURN cesar(p_texto, p_deslocamento, 1);
  END encrypt_cesar;

  FUNCTION decrypt_cesar(p_texto_cifrado IN VARCHAR2, p_deslocamento IN NUMBER)
    RETURN VARCHAR2 IS
  BEGIN
    RETURN cesar(p_texto_cifrado, p_deslocamento, -1);
  END decrypt_cesar;

  FUNCTION encrypt_vigenere(p_texto IN VARCHAR2, p_chave IN VARCHAR2)
    RETURN VARCHAR2 IS
  BEGIN
    RETURN vigenere(p_texto, p_chave, 1);
  END encrypt_vigenere;

  FUNCTION decrypt_vigenere(p_texto_cifrado IN VARCHAR2, p_chave IN VARCHAR2)
    RETURN VARCHAR2 IS
  BEGIN
    RETURN vigenere(p_texto_cifrado, p_chave, -1);
  END decrypt_vigenere;

END pkg_ora_classic;
/
