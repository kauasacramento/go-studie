# API didatica com Go + Gin + JWT

Projeto simples para aprender fundamentos de API REST com Go usando Gin e autenticacao JWT.

## O que este projeto mostra

- Estrutura basica de API HTTP com Gin
- Login e protecao de rotas com JWT (HS256)
- CRUD de tarefas em memoria (sem banco)
- Validacao de payload com `ShouldBindJSON`
- Respostas HTTP (`200`, `201`, `204`, `400`, `401`, `404`)

## Requisitos

- Go 1.23.0+

## Como rodar

```bash
go run .
```

Servidor em `http://localhost:8080`.

## JWT

- Secret padrao: `dev-secret-change-me`
- Para alterar o secret:

```bash
# PowerShell
$env:JWT_SECRET="meu-secret-super-forte"
go run .
```

Usuarios de teste:

- `admin` / `123456` (role `admin`)
- `aluno` / `golang` (role `student`)

## Rotas

Publicas:

- `GET /api/v1/health`
- `POST /api/v1/login`

Protegidas (Bearer token):

- `GET /api/v1/me`
- `GET /api/v1/tasks`
- `GET /api/v1/tasks/:id`
- `POST /api/v1/tasks`
- `PUT /api/v1/tasks/:id`
- `DELETE /api/v1/tasks/:id`

## Exemplo rapido com curl

Login:

```bash
curl -X POST http://localhost:8080/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"123456"}'
```

Use o `access_token` retornado:

```bash
curl http://localhost:8080/api/v1/tasks \
  -H "Authorization: Bearer SEU_TOKEN_AQUI"
```

## REST Client

Arquivo pronto para testes: `api.http`

Fluxo sugerido no VS Code:

1. Rodar `go run .`
2. Abrir `api.http`
3. Executar requests em ordem, de cima para baixo

## Proximos passos didaticos

1. Adicionar refresh token
2. Extrair auth para pacote separado
3. Adicionar testes com `httptest`
4. Trocar armazenamento em memoria por SQLite ou Postgres
