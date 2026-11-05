# OraEncryption

Biblioteca PL/SQL de criptografia para Oracle Database (**12c ou superior**, testada para a faixa 12c–21c), com dois níveis:

| Módulo | Pacote | Para que serve | Seguro para dados reais? |
|---|---|---|---|
| `classic/` | `PKG_ORA_CLASSIC` | César e Vigenère (didático) | **Não** |
| `crypto/` | `PKG_ORA_CRYPTO` | AES-256-CBC + HMAC-SHA256, PBKDF2 | Sim |
| `hash/` | `PKG_ORA_HASH` | SHA-256/512, HMAC, hash de senhas | Sim |
| `keys/` | `PKG_ORA_KEYS` | Chaves versionadas, envelope, rotação | Sim |

> ⚠️ César e Vigenère são quebráveis em segundos. Servem para estudo; para proteger dados use os demais módulos.

## Instalação

Como `SYS`, uma vez: `GRANT EXECUTE ON SYS.DBMS_CRYPTO TO <usuario>;`

Na raiz do repositório:

```bash
sqlplus usuario/senha@banco @install.sql
sqlplus usuario/senha@banco @tests/run_all.sql   # opcional
```

## Cifras clássicas

```sql
SELECT pkg_ora_classic.encrypt_cesar('Texto', 3) FROM dual;
SELECT pkg_ora_classic.decrypt_vigenere('LXFOPVEFRNHR', 'lemon') FROM dual;
```

As funções standalone originais (`ENCRYPT_CESAR`, `DECRYPT_CESAR`, `ENCRYPT_VIGENERE`, `DECRYPT_VIGENERE`) continuam existindo e delegam ao pacote.

**Mudanças de comportamento em relação à v1:** o deslocamento negativo/maior que 26 funciona; a chave do Vigenère é case-insensitive, só avança em letras (padrão clássico) e é validada (apenas A–Z). Textos cifrados com a versão antiga que continham espaços/pontuação **não** decifram igual.

## Criptografia com senha (AES-256)

```sql
DECLARE
  v_token VARCHAR2(32767);
BEGIN
  v_token := pkg_ora_crypto.encrypt_aes('dado sensível', 'minha-senha-forte');
  DBMS_OUTPUT.PUT_LINE(pkg_ora_crypto.decrypt_aes(v_token, 'minha-senha-forte'));
END;
/
```

- AES-256-CBC com IV aleatório por chamada + HMAC-SHA256 (*encrypt-then-MAC*): adulteração ou senha errada geram `ORA-20010` antes de decifrar.
- Senha → chave via PBKDF2-HMAC-SHA256 (padrão 100.000 iterações, salt de 16 bytes; o número de iterações vai no token). Implementado em PL/SQL puro para funcionar no 12c; é mais lento que código nativo, então ajuste `p_iterations` conforme seu hardware.
- Para dados grandes ou binários: `encrypt_blob_pw` / `decrypt_blob_pw` (BLOB). Com chave binária de 32 bytes: `encrypt_blob` / `decrypt_blob` + `random_key`.
- O Oracle 12c–21c não oferece AES-GCM no `DBMS_CRYPTO`; por isso a autenticação é feita com HMAC.

## Hash e senhas

```sql
SELECT pkg_ora_hash.sha256('abc') FROM dual;

-- armazenar e verificar senha de usuário
UPDATE usuarios SET senha_hash = pkg_ora_hash.hash_password(:senha) WHERE id = :id;
SELECT id FROM usuarios WHERE pkg_ora_hash.is_password_valid(:senha, senha_hash) = 1;
```

Nunca guarde senhas com `sha256` puro. `hash_password` usa PBKDF2 com salt aleatório e a verificação é em tempo constante.

## Gestão de chaves e rotação

Criptografia em envelope: **chave mestra** (fora do banco) → **KEK** versionada (tabela `ORA_KEYS`, sempre cifrada) → **DEK** aleatória por registro → dado.

```sql
BEGIN
  -- a chave mestra vem de Wallet / OCI Vault / HSM, nunca fica no banco
  pkg_ora_keys.set_master_key(:master_key_raw32);

  v_ver   := pkg_ora_keys.create_key('CPF');            -- v1
  v_token := pkg_ora_keys.encrypt_text('CPF', '123.456.789-09');   -- 'v1.<base64>'

  v_ver   := pkg_ora_keys.rotate_key('CPF');            -- v2; v1 vira RETIRED
  v_token := pkg_ora_keys.reencrypt_text('CPF', v_token); -- migra o dado para v2
  COMMIT;                                               -- as procedures não fazem commit
END;
/
```

`change_master_key(old, new)` reembrulha todas as KEKs sem tocar nos dados. Restrinja o acesso à tabela `ORA_KEYS` e ao pacote ao mínimo necessário e ative auditoria (Unified Auditing) sobre eles.

## Limites conhecidos / roadmap

- Cifragem assimétrica (RSA-OAEP, assinaturas) **não** está implementada: o `DBMS_CRYPTO` não oferece RSA e exigiria Java Stored Procedures (JCE) ou integração externa.
- Não é testado em 12c localmente; o CI roda em Oracle XE 21. Rode `tests/run_all.sql` na sua versão antes de usar.
- Textos acima de ~20.000 caracteres: use as variantes BLOB.

Veja também [SECURITY.md](SECURITY.md).
