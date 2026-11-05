-- Cifras clássicas (DIDÁTICAS). Não use para proteger dados reais.
CREATE OR REPLACE PACKAGE pkg_ora_classic AS

  -- Cifra de César. Aceita deslocamento negativo ou maior que 26.
  FUNCTION encrypt_cesar(p_texto IN VARCHAR2, p_deslocamento IN NUMBER)
    RETURN VARCHAR2;
  FUNCTION decrypt_cesar(p_texto_cifrado IN VARCHAR2, p_deslocamento IN NUMBER)
    RETURN VARCHAR2;

  -- Cifra de Vigenère. A chave deve conter apenas letras A-Z (sem distinção
  -- de maiúsculas/minúsculas). A chave só avança em letras do texto.
  FUNCTION encrypt_vigenere(p_texto IN VARCHAR2, p_chave IN VARCHAR2)
    RETURN VARCHAR2;
  FUNCTION decrypt_vigenere(p_texto_cifrado IN VARCHAR2, p_chave IN VARCHAR2)
    RETURN VARCHAR2;

END pkg_ora_classic;
/
