package main

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"
)

type contextKey string

const (
	batchIDKey     contextKey = "batch_id"
	requestedByKey contextKey = "requested_by"
	traceIDKey     contextKey = "trace_id"
	orderIDKey     contextKey = "order_id"
	highRiskCutoff            = 85
)

type Order struct {
	ID         int
	CustomerID string
	Amount     float64
	Items      int
	Country    string
}

type Job struct {
	Ctx   context.Context
	Order Order
}

type EnrichedOrder struct {
	Ctx               context.Context
	Order             Order
	Segment           string
	RecentChargebacks int
}

type ScoredOrder struct {
	Ctx               context.Context
	Order             Order
	Segment           string
	RecentChargebacks int
	Risk              int
	Reason            string
}

type StoredOrder struct {
	Ctx    context.Context
	Order  Order
	Risk   int
	Record string
}

type CustomerProfile struct {
	Segment           string
	RecentChargebacks int
}

type RiskModel struct {
	segmentWeight map[string]int
}

type ContextData struct {
	BatchID     string
	RequestedBy string
	TraceID     string
	OrderID     int
}

var (
	profiles     map[string]CustomerProfile
	profilesOnce sync.Once

	riskModel     RiskModel
	riskModelOnce sync.Once

	reportBufferPool = sync.Pool{
		New: func() any {
			return new(bytes.Buffer)
		},
	}
)

func main() {
	root := context.Background()
	root = context.WithValue(root, batchIDKey, "batch-2026-04-02")
	root = context.WithValue(root, requestedByKey, "pdi-go")

	ctx, cancel := context.WithTimeout(root, 1500*time.Millisecond)
	defer cancel()

	orders := sampleOrders()
	jobs := generateJobs(ctx, orders)

	enriched := fanIn(ctx, fanOutEnrich(ctx, jobs, 3)...)
	scored := fanIn(ctx, fanOutScore(ctx, enriched, 4)...)
	stored := fanIn(ctx, fanOutPersist(ctx, scored, 2)...)

	var results []StoredOrder
	for result := range stored {
		results = append(results, result)
		fmt.Println(result.Record)

		if result.Risk >= highRiskCutoff {
			fmt.Printf("cancelando lote: pedido %d ultrapassou risco %d\n", result.Order.ID, result.Risk)
			cancel()
		}
	}

	printSummary(results, ctx)

	if err := ctx.Err(); err != nil {
		fmt.Printf("pipeline finalizada com contexto encerrado: %v\n", err)
	}
	fmt.Println("projeto pronto para subir no GitHub como demo de concorrencia em Go")
}

func sampleOrders() []Order {
	return []Order{
		{ID: 101, CustomerID: "c-1", Amount: 120, Items: 2, Country: "BR"},
		{ID: 102, CustomerID: "c-2", Amount: 980, Items: 1, Country: "US"},
		{ID: 103, CustomerID: "c-3", Amount: 220, Items: 5, Country: "BR"},
		{ID: 104, CustomerID: "c-4", Amount: 1500, Items: 1, Country: "NG"},
		{ID: 105, CustomerID: "c-5", Amount: 410, Items: 3, Country: "AR"},
		{ID: 106, CustomerID: "c-6", Amount: 80, Items: 1, Country: "BR"},
		{ID: 107, CustomerID: "c-7", Amount: 1300, Items: 2, Country: "US"},
		{ID: 108, CustomerID: "c-8", Amount: 260, Items: 4, Country: "MX"},
	}
}

func generateJobs(ctx context.Context, orders []Order) <-chan Job {
	out := make(chan Job)

	go func() {
		defer close(out)

		for _, order := range orders {
			jobCtx := context.WithValue(ctx, traceIDKey, fmt.Sprintf("trace-%03d", order.ID))
			jobCtx = context.WithValue(jobCtx, orderIDKey, order.ID)

			job := Job{Ctx: jobCtx, Order: order}

			select {
			case <-ctx.Done():
				return
			case out <- job:
			}
		}
	}()

	return out
}

func fanOutEnrich(ctx context.Context, in <-chan Job, workers int) []<-chan EnrichedOrder {
	outs := make([]<-chan EnrichedOrder, 0, workers)
	for workerID := 1; workerID <= workers; workerID++ {
		out := make(chan EnrichedOrder)
		go enrichWorker(ctx, workerID, in, out)
		outs = append(outs, out)
	}
	return outs
}

func enrichWorker(ctx context.Context, _ int, in <-chan Job, out chan<- EnrichedOrder) {
	defer close(out)
	profilesOnce.Do(loadProfiles)

	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-in:
			if !ok {
				return
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(120 * time.Millisecond):
			}

			profile := profiles[job.Order.CustomerID]
			enriched := EnrichedOrder{
				Ctx:               job.Ctx,
				Order:             job.Order,
				Segment:           profile.Segment,
				RecentChargebacks: profile.RecentChargebacks,
			}

			select {
			case <-ctx.Done():
				return
			case out <- enriched:
			}
		}
	}
}

func fanOutScore(ctx context.Context, in <-chan EnrichedOrder, workers int) []<-chan ScoredOrder {
	outs := make([]<-chan ScoredOrder, 0, workers)
	for workerID := 1; workerID <= workers; workerID++ {
		out := make(chan ScoredOrder)
		go scoreWorker(ctx, workerID, in, out)
		outs = append(outs, out)
	}
	return outs
}

func scoreWorker(ctx context.Context, _ int, in <-chan EnrichedOrder, out chan<- ScoredOrder) {
	defer close(out)
	riskModelOnce.Do(loadRiskModel)

	for {
		select {
		case <-ctx.Done():
			return
		case order, ok := <-in:
			if !ok {
				return
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(90 * time.Millisecond):
			}

			risk, reason := calculateRisk(order)
			scored := ScoredOrder{
				Ctx:               order.Ctx,
				Order:             order.Order,
				Segment:           order.Segment,
				RecentChargebacks: order.RecentChargebacks,
				Risk:              risk,
				Reason:            reason,
			}

			select {
			case <-ctx.Done():
				return
			case out <- scored:
			}
		}
	}
}

func fanOutPersist(ctx context.Context, in <-chan ScoredOrder, workers int) []<-chan StoredOrder {
	outs := make([]<-chan StoredOrder, 0, workers)
	for workerID := 1; workerID <= workers; workerID++ {
		out := make(chan StoredOrder)
		go persistWorker(ctx, workerID, in, out)
		outs = append(outs, out)
	}
	return outs
}

func persistWorker(ctx context.Context, workerID int, in <-chan ScoredOrder, out chan<- StoredOrder) {
	defer close(out)

	for {
		select {
		case <-ctx.Done():
			return
		case order, ok := <-in:
			if !ok {
				return
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(70 * time.Millisecond):
			}

			metadata := contextData(order.Ctx)
			buffer := reportBufferPool.Get().(*bytes.Buffer)
			buffer.Reset()

			fmt.Fprintf(
				buffer,
				"[worker=%d batch=%s trace=%s requested_by=%s] order=%d customer=%s segment=%s risk=%d reason=%s",
				workerID,
				metadata.BatchID,
				metadata.TraceID,
				metadata.RequestedBy,
				order.Order.ID,
				order.Order.CustomerID,
				order.Segment,
				order.Risk,
				order.Reason,
			)

			record := string(append([]byte(nil), buffer.Bytes()...))
			reportBufferPool.Put(buffer)

			stored := StoredOrder{
				Ctx:    order.Ctx,
				Order:  order.Order,
				Risk:   order.Risk,
				Record: record,
			}

			select {
			case <-ctx.Done():
				return
			case out <- stored:
			}
		}
	}
}

func fanIn[T any](ctx context.Context, inputs ...<-chan T) <-chan T {
	out := make(chan T)
	var wg sync.WaitGroup

	wg.Add(len(inputs))
	for _, input := range inputs {
		go func(stream <-chan T) {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return
				case item, ok := <-stream:
					if !ok {
						return
					}

					select {
					case <-ctx.Done():
						return
					case out <- item:
					}
				}
			}
		}(input)
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

func loadProfiles() {
	profiles = map[string]CustomerProfile{
		"c-1": {Segment: "regular", RecentChargebacks: 0},
		"c-2": {Segment: "vip", RecentChargebacks: 0},
		"c-3": {Segment: "regular", RecentChargebacks: 1},
		"c-4": {Segment: "new", RecentChargebacks: 3},
		"c-5": {Segment: "regular", RecentChargebacks: 0},
		"c-6": {Segment: "new", RecentChargebacks: 0},
		"c-7": {Segment: "vip", RecentChargebacks: 2},
		"c-8": {Segment: "regular", RecentChargebacks: 1},
	}
}

func loadRiskModel() {
	riskModel = RiskModel{
		segmentWeight: map[string]int{
			"vip":     -5,
			"regular": 10,
			"new":     25,
		},
	}
}

func calculateRisk(order EnrichedOrder) (int, string) {
	risk := 10
	reason := "perfil estavel"

	risk += riskModel.segmentWeight[order.Segment]
	if order.Order.Amount > 1000 {
		risk += 35
		reason = "ticket muito alto"
	}
	if order.RecentChargebacks > 0 {
		risk += order.RecentChargebacks * 12
		reason = "historico de chargeback"
	}
	if order.Order.Country == "NG" {
		risk += 20
		reason = "pais com validacao adicional"
	}
	if order.Order.Items >= 4 {
		risk += 8
	}
	if risk < 0 {
		risk = 0
	}
	if risk > 100 {
		risk = 100
	}

	return risk, reason
}

func contextData(ctx context.Context) ContextData {
	data := ContextData{}
	if value, ok := ctx.Value(batchIDKey).(string); ok {
		data.BatchID = value
	}
	if value, ok := ctx.Value(requestedByKey).(string); ok {
		data.RequestedBy = value
	}
	if value, ok := ctx.Value(traceIDKey).(string); ok {
		data.TraceID = value
	}
	if value, ok := ctx.Value(orderIDKey).(int); ok {
		data.OrderID = value
	}
	return data
}

func printSummary(results []StoredOrder, ctx context.Context) {
	total := 0
	highRisk := 0
	for _, result := range results {
		total++
		if result.Risk >= highRiskCutoff {
			highRisk++
		}
	}

	metadata := contextData(ctx)
	fmt.Printf(
		"resumo batch=%s processed=%d high_risk=%d requested_by=%s\n",
		metadata.BatchID,
		total,
		highRisk,
		metadata.RequestedBy,
	)
}
