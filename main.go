package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const tokenTTL = time.Hour

type Task struct {
	ID    int64  `json:"id"`
	Title string `json:"title"`
	Done  bool   `json:"done"`
}

type createTaskInput struct {
	Title string `json:"title" binding:"required,min=3"`
	Done  *bool  `json:"done"`
}

type updateTaskInput struct {
	Title *string `json:"title"`
	Done  *bool   `json:"done"`
}

type loginInput struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type userCredentials struct {
	Password string
	Role     string
}

type jwtClaims struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	Iat  int64  `json:"iat"`
	Exp  int64  `json:"exp"`
}

type taskStore struct {
	mu     sync.RWMutex
	nextID int64
	tasks  map[int64]Task
}

var users = map[string]userCredentials{
	"admin": {
		Password: "123456",
		Role:     "admin",
	},
	"aluno": {
		Password: "golang",
		Role:     "student",
	},
}

func newTaskStore() *taskStore {
	return &taskStore{
		nextID: 1,
		tasks:  make(map[int64]Task),
	}
}

func (s *taskStore) list() []Task {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]Task, 0, len(s.tasks))
	for _, task := range s.tasks {
		items = append(items, task)
	}

	return items
}

func (s *taskStore) get(id int64) (Task, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	task, ok := s.tasks[id]
	return task, ok
}

func (s *taskStore) create(input createTaskInput) Task {
	s.mu.Lock()
	defer s.mu.Unlock()

	done := false
	if input.Done != nil {
		done = *input.Done
	}

	task := Task{
		ID:    s.nextID,
		Title: strings.TrimSpace(input.Title),
		Done:  done,
	}
	s.tasks[task.ID] = task
	s.nextID++

	return task
}

func (s *taskStore) update(id int64, input updateTaskInput) (Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	task, ok := s.tasks[id]
	if !ok {
		return Task{}, errors.New("task nao encontrada")
	}

	if input.Title == nil && input.Done == nil {
		return Task{}, errors.New("envie ao menos um campo para atualizar")
	}

	if input.Title != nil {
		title := strings.TrimSpace(*input.Title)
		if len(title) < 3 {
			return Task{}, errors.New("title precisa ter no minimo 3 caracteres")
		}
		task.Title = title
	}

	if input.Done != nil {
		task.Done = *input.Done
	}

	s.tasks[id] = task
	return task, nil
}

func (s *taskStore) delete(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tasks[id]; !ok {
		return false
	}

	delete(s.tasks, id)
	return true
}

func signingKey() []byte {
	secret := strings.TrimSpace(os.Getenv("JWT_SECRET"))
	if secret == "" {
		secret = "dev-secret-change-me"
	}
	return []byte(secret)
}

func generateJWT(username, role string, now time.Time, ttl time.Duration) (string, error) {
	headerJSON, err := json.Marshal(map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	})
	if err != nil {
		return "", err
	}

	claims := jwtClaims{
		Sub:  username,
		Role: role,
		Iat:  now.Unix(),
		Exp:  now.Add(ttl).Unix(),
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	unsignedToken := encodedHeader + "." + encodedPayload

	mac := hmac.New(sha256.New, signingKey())
	mac.Write([]byte(unsignedToken))
	signature := mac.Sum(nil)
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	return unsignedToken + "." + encodedSignature, nil
}

func validateJWT(token string, now time.Time) (jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return jwtClaims{}, errors.New("token invalido")
	}

	unsignedToken := parts[0] + "." + parts[1]
	providedSignature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return jwtClaims{}, errors.New("assinatura invalida")
	}

	mac := hmac.New(sha256.New, signingKey())
	mac.Write([]byte(unsignedToken))
	expectedSignature := mac.Sum(nil)
	if !hmac.Equal(providedSignature, expectedSignature) {
		return jwtClaims{}, errors.New("assinatura invalida")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return jwtClaims{}, errors.New("payload invalido")
	}

	var claims jwtClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return jwtClaims{}, errors.New("claims invalidos")
	}

	if claims.Sub == "" {
		return jwtClaims{}, errors.New("claim sub ausente")
	}
	if claims.Exp <= now.Unix() {
		return jwtClaims{}, errors.New("token expirado")
	}

	return claims, nil
}

func extractBearerToken(authHeader string) (string, error) {
	parts := strings.Fields(authHeader)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("header Authorization invalido")
	}
	return parts[1], nil
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := extractBearerToken(c.GetHeader("Authorization"))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		claims, err := validateJWT(token, time.Now())
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		c.Set("auth_user", claims.Sub)
		c.Set("auth_role", claims.Role)
		c.Next()
	}
}

func parseID(c *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id invalido"})
		return 0, false
	}

	return id, true
}

func main() {
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())
	if err := router.SetTrustedProxies([]string{"127.0.0.1", "::1"}); err != nil {
		panic(err)
	}
	store := newTaskStore()

	api := router.Group("/api/v1")
	{
		api.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

		api.POST("/login", func(c *gin.Context) {
			var input loginInput
			if err := c.ShouldBindJSON(&input); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			username := strings.TrimSpace(input.Username)
			credentials, ok := users[username]
			if !ok || credentials.Password != input.Password {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "credenciais invalidas"})
				return
			}

			token, err := generateJWT(username, credentials.Role, time.Now(), tokenTTL)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "falha ao gerar token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"data": gin.H{
					"access_token": token,
					"token_type":   "Bearer",
					"expires_in":   int64(tokenTTL.Seconds()),
				},
			})
		})

		auth := api.Group("")
		auth.Use(authMiddleware())
		{
			auth.GET("/me", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"data": gin.H{
						"username": c.GetString("auth_user"),
						"role":     c.GetString("auth_role"),
					},
				})
			})

			auth.GET("/tasks", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"data": store.list()})
			})

			auth.GET("/tasks/:id", func(c *gin.Context) {
				id, ok := parseID(c)
				if !ok {
					return
				}

				task, found := store.get(id)
				if !found {
					c.JSON(http.StatusNotFound, gin.H{"error": "task nao encontrada"})
					return
				}

				c.JSON(http.StatusOK, gin.H{"data": task})
			})

			auth.POST("/tasks", func(c *gin.Context) {
				var input createTaskInput
				if err := c.ShouldBindJSON(&input); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}

				task := store.create(input)
				c.JSON(http.StatusCreated, gin.H{"data": task})
			})

			auth.PUT("/tasks/:id", func(c *gin.Context) {
				id, ok := parseID(c)
				if !ok {
					return
				}

				var input updateTaskInput
				if err := c.ShouldBindJSON(&input); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}

				task, err := store.update(id, input)
				if err != nil {
					if err.Error() == "task nao encontrada" {
						c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
						return
					}
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}

				c.JSON(http.StatusOK, gin.H{"data": task})
			})

			auth.DELETE("/tasks/:id", func(c *gin.Context) {
				id, ok := parseID(c)
				if !ok {
					return
				}

				if !store.delete(id) {
					c.JSON(http.StatusNotFound, gin.H{"error": "task nao encontrada"})
					return
				}

				c.Status(http.StatusNoContent)
			})
		}
	}

	if err := router.Run(":8080"); err != nil {
		panic(err)
	}
}
