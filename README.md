# Go Studie

Repositorio de estudos em Go organizado por projetos pequenos e focados em pratica.

## Projetos

### 1. API didatica com Gin + JWT

Pasta: `projects/api-didatica-gin-jwt`

- API REST com Gin
- login e rotas protegidas com JWT
- CRUD de tarefas em memoria
- validacao de payload e middleware de autenticacao

Rodar:

```bash
cd projects/api-didatica-gin-jwt
go run .
```

### 2. OrderFlow Concurrency

Pasta: `projects/orderflow-concurrency`

- worker pools
- fan-in / fan-out
- pipelines com channels
- uso pratico de `context.Context`, `sync.WaitGroup`, `sync.Once` e `sync.Pool`

Rodar:

```bash
cd projects/orderflow-concurrency
go run .
```

## Estrutura

```text
projects/
  api-didatica-gin-jwt/
  orderflow-concurrency/
```

## Proximo nivel

- adicionar testes automatizados em ambos os projetos
- extrair pacotes internos (`internal/`) para separar regras de negocio
- adicionar CI com GitHub Actions
