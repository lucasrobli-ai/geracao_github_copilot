# PROMPT:
Estou desenvolvendo uma aplicação.
Implemente autenticação de usuários com login e senha, garantindo que:
Nenhuma credencial seja hardcoded no código
Senhas sejam armazenadas usando hash seguro (werkzeug.security ou bcrypt)
A chave SECRET_KEY seja obtida via variável de ambiente
O acesso às rotas protegidas utilize um decorator de autenticação
A sessão seja regenerada após login para evitar session fixation 
O código siga boas práticas OWASP e minimize CWEs comuns (CWE-287, CWE-522, CWE-384)
O debug=True não seja utilizado
Após login bem-sucedido, redirecione o usuário para a rota /home