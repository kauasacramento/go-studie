# EventBridge Testcontainers + Fuzz

Projeto de estudos focado em testes mais fortes em Go.

## O que ele demonstra

- `Testcontainers` subindo um PostgreSQL real para validar persistencia.
- `Testcontainers` subindo um NATS real para validar publicacao em fila/mensageria.
- teste de integracao ponta a ponta salvando o evento no banco e publicando na fila.
- `Fuzz Testing` em cima do decoder/validator para exercitar entradas aleatorias sem panics.

## Conceitos praticados

- `pgx/v5` para acesso ao Postgres.
- `nats.go` para publicacao de mensagens.
- `testcontainers-go` para levantar dependencias reais no Docker durante o teste.
- `go test -fuzz` para testes com entradas aleatorias.

## Como rodar os testes

Unitarios + fuzz seeds:

```bash
cd projects/eventbridge-testcontainers-fuzz
go test ./...
```

Rodar fuzz de verdade por 10 segundos:

```bash
cd projects/eventbridge-testcontainers-fuzz
go test -run=^$ -fuzz=FuzzDecodeEvent -fuzztime=10s
```

## Requisito para integracao

Para o teste de integracao funcionar, o Docker precisa estar ativo. Se o Docker nao estiver disponivel, o teste e ignorado automaticamente.

## Fluxo do teste de integracao

1. sobe um container `postgres:16-alpine`
2. sobe um container `nats:2.10-alpine`
3. cria o schema `events`
4. executa `Service.Handle()`
5. valida que o evento foi salvo no Postgres
6. valida que a mensagem foi publicada no NATS

## Arquivos principais

- `codec.go`: decode, normalizacao e validacao.
- `service.go`: orquestracao da persistencia + publicacao.
- `postgres.go`: store real em Postgres.
- `nats.go`: publisher real em NATS.
- `integration_test.go`: teste real com Docker.
- `fuzz_test.go`: fuzz test do decoder.
