# OrderFlow

Projeto simples para praticar concorrencia em Go com um caso mais realista: uma pipeline de analise de risco de pedidos.

## O que esse projeto demonstra

- `worker pools`: multiplos workers nas etapas de enrichment, score e persistencia.
- `fan-out`: a mesma entrada eh distribuida para varios workers consumindo do mesmo channel.
- `fan-in`: os resultados de varios workers sao reunidos em um unico channel com `sync.WaitGroup`.
- `pipelines`: `generate -> enrich -> score -> persist`.
- `context.Context`: timeout global, cancelamento em cascata e propagacao de valores como `batch_id`, `trace_id` e `requested_by`.
- `sync.Once`: carga unica de perfis e do modelo de risco.
- `sync.Pool`: reutilizacao de `bytes.Buffer` na etapa de persistencia/relatorio.

## Como rodar

```bash
cd projects/orderflow-concurrency
go run .
```

## Estrutura mental da pipeline

1. `generateJobs` cria os pedidos e injeta metadados no `context`.
2. `fanOutEnrich` faz lookup do perfil do cliente.
3. `fanOutScore` calcula risco de fraude.
4. `fanOutPersist` monta o registro final reutilizando buffers.
5. `fanIn` junta os resultados e fecha o channel quando todos os workers terminam.

## Ideias para evoluir no GitHub

- trocar `sampleOrders()` por leitura de arquivo CSV ou fila.
- expor metricas HTTP com `expvar` ou Prometheus.
- adicionar testes por etapa da pipeline.
- separar em pacotes: `pipeline`, `risk`, `storage`, `cmd/orderflow`.
- adicionar retries com backoff e um channel dedicado para erros.

## Por que isso fica bom no portfolio

Nao eh so um `go func()`. O projeto mostra coordenacao entre goroutines, cancelamento correto, sincronizacao com `WaitGroup`, inicializacao segura com `Once` e otimizacao simples com `Pool`.
