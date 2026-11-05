-- Funções standalone mantidas por compatibilidade com a primeira versão do
-- repositório. Delegam para PKG_ORA_CLASSIC.
CREATE OR REPLACE FUNCTION encrypt_cesar(p_texto VARCHAR2, p_deslocamento NUMBER)
  RETURN VARCHAR2 IS
BEGIN
  RETURN pkg_ora_classic.encrypt_cesar(p_texto, p_deslocamento);
END encrypt_cesar;
/

CREATE OR REPLACE FUNCTION decrypt_cesar(p_texto_cifrado VARCHAR2, p_deslocamento NUMBER)
  RETURN VARCHAR2 IS
BEGIN
  RETURN pkg_ora_classic.decrypt_cesar(p_texto_cifrado, p_deslocamento);
END decrypt_cesar;
/

CREATE OR REPLACE FUNCTION encrypt_vigenere(p_texto VARCHAR2, p_chave VARCHAR2)
  RETURN VARCHAR2 IS
BEGIN
  RETURN pkg_ora_classic.encrypt_vigenere(p_texto, p_chave);
END encrypt_vigenere;
/

CREATE OR REPLACE FUNCTION decrypt_vigenere(p_texto_cifrado VARCHAR2, p_chave VARCHAR2)
  RETURN VARCHAR2 IS
BEGIN
  RETURN pkg_ora_classic.decrypt_vigenere(p_texto_cifrado, p_chave);
END decrypt_vigenere;
/
