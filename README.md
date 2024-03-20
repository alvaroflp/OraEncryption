# OraEncryption

Este repositório contém funções em PL/SQL para criptografia e descriptografia de strings utilizando os métodos de Cifras em SQL Oracle.

## Cifra de César

A [Cifra de César](https://pt.wikipedia.org/wiki/Cifra_de_C%C3%A9sar), também conhecida como deslocamento de César, é um dos métodos mais simples e conhecidos de criptografia. É uma técnica de substituição onde cada letra no texto é substituída por outra letra que se encontra um número fixo de posições adiante no alfabeto. Por exemplo, com um deslocamento de 3, 'A' seria substituído por 'D', 'B' se tornaria 'E', e assim por diante. O nome vem do líder militar romano Júlio César, que usou essa técnica para se comunicar com seus generais.


## Cifra de Vigenère

A [Cifra de Vigenère](https://pt.wikipedia.org/wiki/Cifra_de_Vigen%C3%A8re) é um método de criptografia que utiliza uma série de diferentes cifras de César baseadas em letras de uma senha. É considerado uma forma de polialfabética substitutiva, pois utiliza várias cifras de César em sequência. A chave é uma palavra que é repetida ao longo do texto a ser cifrado. Cada letra da chave é usada para criptografar uma letra do texto original. Por isso, a cifra de Vigenère é considerada mais segura do que a cifra de César padrão.


## Funções Implementadas

- `ENCRYPT_CESAR(P_TEXTO VARCHAR2, P_DESLOCAMENTO NUMBER)`: Função para criptografar um texto usando a Cifra de César com um determinado deslocamento.
- `DECRYPT_CESAR(P_TEXTO_CIFRADO VARCHAR2, P_DESLOCAMENTO NUMBER)`: Função para descriptografar um texto criptografado usando a Cifra de César com um determinado deslocamento.
- `ENCRYPT_VIGENERE(P_TEXTO VARCHAR2, P_CHAVE VARCHAR2)`: Função para criptografar um texto usando a Cifra de Vigenère com uma determinada chave.
- `DECRYPT_VIGENERE(P_TEXTO_CIFRADO VARCHAR2, P_CHAVE VARCHAR2)`: Função para descriptografar um texto criptografado usando a Cifra de Vigenère com uma determinada chave.


## Como Usar

Para utilizar essas funções, basta copiar e colar o código PL/SQL em seu ambiente Oracle. Após a criação das funções, você pode chamá-las em suas consultas SQL conforme necessário.

Exemplo:

```sql
-- Criptografando e descriptografando usando Cifra de César
DECLARE
  texto_cifrado VARCHAR2(4000);
  texto_original VARCHAR2(4000);
BEGIN
  texto_cifrado := ENCRYPT_CESAR('Texto a ser criptografado', 3);
  DBMS_OUTPUT.PUT_LINE('Texto criptografado: ' || texto_cifrado);

  texto_original := DECRYPT_CESAR(texto_cifrado, 3);
  DBMS_OUTPUT.PUT_LINE('Texto descriptografado: ' || texto_original);
END;

-- Criptografando e descriptografando usando Cifra de Vigenère
DECLARE
  texto_cifrado VARCHAR2(4000);
  texto_original VARCHAR2(4000);
BEGIN
  texto_cifrado := ENCRYPT_VIGENERE('Texto a ser criptografado', 'chave');
  DBMS_OUTPUT.PUT_LINE('Texto criptografado: ' || texto_cifrado);

  texto_original := DECRYPT_VIGENERE(texto_cifrado, 'chave');
  DBMS_OUTPUT.PUT_LINE('Texto descriptografado: ' || texto_original);
END;
