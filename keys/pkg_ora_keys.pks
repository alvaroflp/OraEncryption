-- Gestão de chaves com criptografia em envelope e rotação.
--
--   chave mestra (fora do banco)  --protege-->  KEK (tabela ORA_KEYS, versionada)
--   KEK                           --protege-->  DEK (uma chave aleatória por registro)
--   DEK                           --protege-->  dado
--
-- A chave mestra é fornecida pela aplicação a cada sessão (set_master_key),
-- vinda de Oracle Wallet, OCI Vault, HSM etc. Nenhuma procedure aqui faz COMMIT.
CREATE OR REPLACE PACKAGE pkg_ora_keys AS

  -- Chave mestra (32 bytes) mantida só no estado de sessão do pacote
  PROCEDURE set_master_key(p_master_key IN RAW);
  PROCEDURE clear_master_key;

  -- Rewrap de todas as KEKs com uma nova chave mestra (não toca nos dados)
  PROCEDURE change_master_key(p_old_master IN RAW, p_new_master IN RAW);

  -- Cria a versão 1 de uma chave; ORA-20023 se já existir
  FUNCTION create_key(p_key_name IN VARCHAR2) RETURN NUMBER;

  -- Aposenta a versão ativa e cria a seguinte. Retorna a nova versão.
  FUNCTION rotate_key(p_key_name IN VARCHAR2) RETURN NUMBER;

  -- Token: 'v<versão>.<base64>'. O token carrega a versão usada, por isso
  -- dados antigos continuam legíveis após a rotação.
  FUNCTION encrypt_text(p_key_name IN VARCHAR2, p_text IN VARCHAR2)
    RETURN VARCHAR2;
  FUNCTION decrypt_text(p_key_name IN VARCHAR2, p_token IN VARCHAR2)
    RETURN VARCHAR2;

  -- Descriptografa com a versão do token e criptografa com a versão ativa
  FUNCTION reencrypt_text(p_key_name IN VARCHAR2, p_token IN VARCHAR2)
    RETURN VARCHAR2;

END pkg_ora_keys;
/
