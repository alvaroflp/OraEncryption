CREATE OR REPLACE FUNCTION ENCRYPT_VIGENERE(P_TEXTO VARCHAR2, P_CHAVE VARCHAR2)
  RETURN VARCHAR2 IS
  V_TEXTO_CIFRADO VARCHAR2(4000);
  V_TAM_TEXTO     NUMBER;
  V_TAM_CHAVE     NUMBER;
  V_DESLOCAMENTO  NUMBER;
BEGIN
  V_TAM_TEXTO := LENGTH(P_TEXTO);
  V_TAM_CHAVE := LENGTH(P_CHAVE);
  
  FOR I IN 1 .. V_TAM_TEXTO LOOP
    IF ASCII(SUBSTR(P_TEXTO, I, 1)) BETWEEN 65 AND 90 THEN
      V_DESLOCAMENTO := ASCII(SUBSTR(P_CHAVE, MOD(I - 1, V_TAM_CHAVE) + 1, 1)) - 65;
      V_TEXTO_CIFRADO := V_TEXTO_CIFRADO ||
                         CHR(MOD(ASCII(SUBSTR(P_TEXTO, I, 1)) - 65 +
                                 V_DESLOCAMENTO,
                                 26) + 65);
    ELSIF ASCII(SUBSTR(P_TEXTO, I, 1)) BETWEEN 97 AND 122 THEN
      V_DESLOCAMENTO := ASCII(SUBSTR(P_CHAVE, MOD(I - 1, V_TAM_CHAVE) + 1, 1)) - 97;
      V_TEXTO_CIFRADO := V_TEXTO_CIFRADO ||
                         CHR(MOD(ASCII(SUBSTR(P_TEXTO, I, 1)) - 97 +
                                 V_DESLOCAMENTO,
                                 26) + 97);
    ELSE
      V_TEXTO_CIFRADO := V_TEXTO_CIFRADO || SUBSTR(P_TEXTO, I, 1);
    END IF;
  END LOOP;
  
  RETURN V_TEXTO_CIFRADO;
END ENCRYPT_VIGENERE;
