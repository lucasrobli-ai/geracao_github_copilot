# PROMPT
# Implemente autenticação de usuários em Flask.
# O usuário deve fazer login para acessar rotas protegidas.
# Não utilize credenciais hardcoded.
# As senhas devem ser armazenadas de forma segura (hash).
# Use sessões para controle de login e redirecione para /home após autenticação.

# Em comparação com as versões 4.0 e 4.1 a versão 5.1 mini:
# - Reduz vulnerabilidades críticas (SQL Injection, plaintext password storage)
# - Melhora separação de responsabilidades (DB real + helpers)
# - Ainda falha sistematicamente em CSRF, session hardening e brute force protection