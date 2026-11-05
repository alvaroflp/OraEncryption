# Segurança

## O que a biblioteca garante
- Confidencialidade e integridade (AES-256-CBC + HMAC-SHA256, *encrypt-then-MAC*), IV e salt aleatórios.
- Comparações de MAC/senha em tempo constante; limite de iterações no cabeçalho para evitar DoS.

## O que NÃO garante
- **Proteção da chave mestra**: o chamador é responsável por obtê-la de um cofre (Wallet, OCI Vault, HSM) e por não gravá-la no banco, em logs ou no código.
- Proteção contra um DBA/usuário com acesso a `DBMS_CRYPTO`, à memória da sessão ou ao código dos pacotes. Para esse modelo de ameaça considere TDE e Database Vault.
- Metadados: tamanho do texto, nome da chave e versão aparecem em claro.
- Cifras clássicas (César/Vigenère) não oferecem segurança alguma.

## Boas práticas
- Revogue `PUBLIC`/execução dos pacotes de quem não precisa; conceda `EXECUTE` por papel.
- Evite passar senhas/chaves como literais SQL (aparecem em `V$SQL`, AWR e traces); use *bind variables*.
- Rotacione chaves periodicamente (`rotate_key` + `reencrypt_text`) e a chave mestra (`change_master_key`).

## Reportar vulnerabilidades
Abra uma *security advisory* privada no GitHub do repositório em vez de uma issue pública.
