# Go Code Design Guide

This guide documents the coding standards, folder structure, and best practices for Go services in this project.

## File Size Guidelines

Keep files small and focused:

| File Type | Recommended Max Lines |
|-----------|----------------------|
| Handlers | 200 lines |
| Services | 300 lines |
| Repositories | 250 lines |
| Entities/Models | 150 lines |
| Middleware | 100 lines |

**When to split a file:**
- File exceeds the recommended limit
- File contains multiple unrelated concerns
- You need to scroll extensively to understand the file

**How to split:**
- Group related functions into separate files within the same package
- Example: `user-handler.go` can become `user-get-handler.go`, `user-create-handler.go`
- Keep one struct/interface per file when possible

---

## Design Pattern: Package by Feature

We use the **Package by Feature** pattern (also known as "Vertical Slice Architecture") to organize code. Related files are grouped by domain/feature rather than by technical layer.

### Package by Feature vs Package by Layer

**Package by Layer** (NOT recommended):
```
/handlers/
    user-handler.go
    order-handler.go
    product-handler.go
/services/
    user-service.go
    order-service.go
    product-service.go
/repositories/
    user-repository.go
    order-repository.go
    product-repository.go
```

**Package by Feature** (recommended):
```
/domains/
    /user/
        entities/
        repositories/
        services/
    /order/
        entities/
        repositories/
        services/
    /product/
        entities/
        repositories/
        services/
```

**Benefits:**
- Related code is close together
- Easier to understand a feature by looking at one directory
- Changes to a feature are localized
- Better encapsulation and modularity

---

## Project Structure

```
/cmd/
    /api/
        main.go                 # Application entry point
/internal/
    /config/
        config.go               # Configuration loading
    /database/
        client.go               # Database connection
    /domains/
        /user/                  # Feature: User management
            /entities/
                user.go
            /repositories/
                user-repository.go
                user-repository-interface.go
            /services/
                user-service.go
            /valueobjects/
                user-role.go
        /order/                 # Feature: Order management
            /entities/
            /repositories/
            /services/
    /api/
        /handlers/
            user-handler.go
            order-handler.go
        /router/
            router.go
        /requests/
            user-request.go
        /responses/
            user-response.go
        /middleware/
            auth.go
            logger.go
            error-handler.go
    /shared/
        /valueobjects/
            pagination.go
/pkg/
    /logger/
        logger.go               # Shared logging utilities
```

---

## Domain Layer

The domain layer contains business logic and data access, organized by feature.

### Folder Structure

```
/internal/domains/{feature}/
├── entities/           # Domain models/entities
├── repositories/       # Data access layer
├── services/           # Business logic
├── valueobjects/       # Value objects, enums, constants
└── factory.go          # Factory functions (optional)
```

### Entities

Domain models representing business objects.

```go
// internal/domains/user/entities/user.go
package entities

import "time"

type User struct {
    ID             string
    Email          string
    Name           string
    OrganizationID string
    Role           string
    CreatedAt      time.Time
    UpdatedAt      time.Time
}

func NewUser(email, name, organizationID string) *User {
    now := time.Now()
    return &User{
        Email:          email,
        Name:           name,
        OrganizationID: organizationID,
        Role:           "member",
        CreatedAt:      now,
        UpdatedAt:      now,
    }
}
```

### Repositories

Data access layer with interface + implementation pattern.

```go
// internal/domains/user/repositories/user-repository-interface.go
package repositories

import (
    "context"
    "myapp/internal/domains/user/entities"
)

type UserRepository interface {
    GetByID(ctx context.Context, id string) (*entities.User, error)
    GetByEmail(ctx context.Context, email string) (*entities.User, error)
    GetByOrganization(ctx context.Context, orgID string) ([]*entities.User, error)
    Create(ctx context.Context, user *entities.User) error
    Update(ctx context.Context, user *entities.User) error
    Delete(ctx context.Context, id string) error
}
```

```go
// internal/domains/user/repositories/user-repository.go
package repositories

import (
    "context"
    "myapp/internal/domains/user/entities"
    "go.mongodb.org/mongo-driver/mongo"
)

type userRepositoryImpl struct {
    collection *mongo.Collection
}

// Compile-time interface check
var _ UserRepository = (*userRepositoryImpl)(nil)

func NewUserRepository(db *mongo.Database) UserRepository {
    return &userRepositoryImpl{
        collection: db.Collection("users"),
    }
}

func (r *userRepositoryImpl) GetByID(ctx context.Context, id string) (*entities.User, error) {
    var user entities.User
    err := r.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&user)
    if err != nil {
        return nil, err
    }
    return &user, nil
}

func (r *userRepositoryImpl) Create(ctx context.Context, user *entities.User) error {
    _, err := r.collection.InsertOne(ctx, user)
    return err
}

// ... other methods
```

### Services

Business logic layer.

```go
// internal/domains/user/services/user-service.go
package services

import (
    "context"
    "errors"
    "myapp/internal/domains/user/entities"
    "myapp/internal/domains/user/repositories"
)

type UserService struct {
    repo repositories.UserRepository
}

func NewUserService(repo repositories.UserRepository) *UserService {
    return &UserService{repo: repo}
}

func (s *UserService) GetUser(ctx context.Context, id string) (*entities.User, error) {
    return s.repo.GetByID(ctx, id)
}

func (s *UserService) CreateUser(ctx context.Context, email, name, orgID string) (*entities.User, error) {
    existing, _ := s.repo.GetByEmail(ctx, email)
    if existing != nil {
        return nil, errors.New("user already exists")
    }

    user := entities.NewUser(email, name, orgID)
    if err := s.repo.Create(ctx, user); err != nil {
        return nil, err
    }
    return user, nil
}
```

### Value Objects

Immutable objects, enums, and domain constants.

```go
// internal/domains/user/valueobjects/user-role.go
package valueobjects

type UserRole string

const (
    RoleAdmin  UserRole = "admin"
    RoleMember UserRole = "member"
    RoleViewer UserRole = "viewer"
)

func (r UserRole) IsValid() bool {
    switch r {
    case RoleAdmin, RoleMember, RoleViewer:
        return true
    }
    return false
}

func (r UserRole) CanEdit() bool {
    return r == RoleAdmin || r == RoleMember
}
```

---

## REST Layer

The REST layer handles HTTP concerns, organized separately from domain logic.

### Folder Structure

```
/internal/api/
├── handlers/           # HTTP request handlers
├── router/             # Route definitions
├── requests/           # Request models
├── responses/          # Response models
└── middleware/         # Cross-cutting concerns
```

### Handlers

HTTP handlers that delegate to services.

```go
// internal/api/handlers/user-handler.go
package handlers

import (
    "net/http"
    "myapp/internal/api/requests"
    "myapp/internal/api/responses"
    "myapp/internal/domains/user/services"
    "github.com/gin-gonic/gin"
)

type UserHandler struct {
    userService *services.UserService
}

func NewUserHandler(userService *services.UserService) *UserHandler {
    return &UserHandler{userService: userService}
}

func (h *UserHandler) GetUser(c *gin.Context) {
    id := c.Param("id")

    user, err := h.userService.GetUser(c.Request.Context(), id)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
        return
    }

    response := responses.UserResponse{
        ID:    user.ID,
        Email: user.Email,
        Name:  user.Name,
    }
    c.JSON(http.StatusOK, response)
}

func (h *UserHandler) CreateUser(c *gin.Context) {
    var req requests.CreateUserRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    user, err := h.userService.CreateUser(c.Request.Context(), req.Email, req.Name, req.OrganizationID)
    if err != nil {
        c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusCreated, responses.UserResponse{
        ID:    user.ID,
        Email: user.Email,
        Name:  user.Name,
    })
}
```

### Request Models

```go
// internal/api/requests/user-request.go
package requests

type CreateUserRequest struct {
    Email          string `json:"email" binding:"required,email"`
    Name           string `json:"name" binding:"required"`
    OrganizationID string `json:"organizationId" binding:"required"`
}

type UpdateUserRequest struct {
    Name string `json:"name" binding:"required"`
    Role string `json:"role" binding:"omitempty,oneof=admin member viewer"`
}
```

### Response Models

```go
// internal/api/responses/user-response.go
package responses

type UserResponse struct {
    ID    string `json:"id"`
    Email string `json:"email"`
    Name  string `json:"name"`
    Role  string `json:"role,omitempty"`
}

type UsersListResponse struct {
    Users      []UserResponse `json:"users"`
    TotalCount int            `json:"totalCount"`
    Page       int            `json:"page"`
    PageSize   int            `json:"pageSize"`
}
```

### Router

Route definitions and handler registration.

```go
// internal/api/router/router.go
package router

import (
    "myapp/internal/api/handlers"
    "myapp/internal/api/middleware"
    "github.com/gin-gonic/gin"
)

func SetupRouter(
    userHandler *handlers.UserHandler,
    orderHandler *handlers.OrderHandler,
) *gin.Engine {
    r := gin.New()

    // Global middleware
    r.Use(middleware.Logger())
    r.Use(middleware.ErrorHandler())
    r.Use(gin.Recovery())

    // Health check
    r.GET("/health", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok"})
    })

    // API routes
    api := r.Group("/api/v1")
    api.Use(middleware.Auth())
    {
        // User routes
        users := api.Group("/users")
        {
            users.GET("/:id", userHandler.GetUser)
            users.POST("", userHandler.CreateUser)
            users.PUT("/:id", userHandler.UpdateUser)
            users.DELETE("/:id", userHandler.DeleteUser)
        }

        // Order routes
        orders := api.Group("/orders")
        {
            orders.GET("/:id", orderHandler.GetOrder)
            orders.POST("", orderHandler.CreateOrder)
        }
    }

    return r
}
```

### Middleware

```go
// internal/api/middleware/auth.go
package middleware

import (
    "net/http"
    "strings"
    "github.com/gin-gonic/gin"
)

const (
    ClaimsKey       = "claims"
    OrganizationKey = "organizationId"
)

func Auth() gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
            return
        }

        token := strings.TrimPrefix(authHeader, "Bearer ")
        claims, err := validateToken(token)
        if err != nil {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
            return
        }

        c.Set(ClaimsKey, claims)
        c.Set(OrganizationKey, claims.OrganizationID)
        c.Next()
    }
}
```

```go
// internal/api/middleware/error-handler.go
package middleware

import (
    "net/http"
    "github.com/gin-gonic/gin"
    "go.uber.org/zap"
)

type HTTPError struct {
    StatusCode int
    Message    string
}

func (e *HTTPError) Error() string {
    return e.Message
}

func NewHTTPError(statusCode int, message string) *HTTPError {
    return &HTTPError{StatusCode: statusCode, Message: message}
}

func ErrorHandler(logger *zap.Logger) gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Next()

        if len(c.Errors) > 0 {
            err := c.Errors.Last().Err
            if httpErr, ok := err.(*HTTPError); ok {
                c.JSON(httpErr.StatusCode, gin.H{"error": httpErr.Message})
                return
            }

            logger.Error("unhandled error", zap.Error(err))
            c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
        }
    }
}
```

---

## Naming Conventions

### Files

Use **kebab-case** for file names:
```
user-handler.go
user-repository.go
user-service.go
order-request.go
```

### Packages

Use **lowercase** without underscores:
```go
package handlers
package repositories
package valueobjects
```

### Functions and Methods

Use **PascalCase** for exported, **camelCase** for unexported:
```go
func GetUser(id string) *User          // Exported
func (s *Service) CreateOrder() error  // Exported method
func validateInput(input string) bool  // Unexported
```

### Constants

Use **PascalCase** for exported constants:
```go
const (
    DefaultPageSize = 20
    MaxPageSize     = 100
    ClaimsKey       = "claims"
)
```

### Interfaces

Name interfaces by what they do, not what they are:
```go
type Reader interface { ... }      // Good
type UserRepository interface { }  // Good for repositories
type IUser interface { }           // Avoid "I" prefix
```

---

## Best Practices

### Use Interfaces for Dependencies

Define interfaces in the package that uses them (not where implemented):

```go
// Service defines its own dependency interface
type UserService struct {
    repo UserRepository  // Interface, not concrete type
}

type UserRepository interface {
    GetByID(ctx context.Context, id string) (*User, error)
}
```

### Always Use Context

Pass context as the first parameter for cancellation and timeouts:

```go
func (s *Service) GetUser(ctx context.Context, id string) (*User, error) {
    return s.repo.GetByID(ctx, id)
}
```

### Structured Logging with Zap

Use structured logging for better observability:

```go
import "go.uber.org/zap"

logger.Info("user created",
    zap.String("userId", user.ID),
    zap.String("email", user.Email),
)

logger.Error("failed to create user",
    zap.Error(err),
    zap.String("email", email),
)
```

### Error Handling

Return errors, don't panic. Wrap errors with context:

```go
import "fmt"

func (s *Service) GetUser(ctx context.Context, id string) (*User, error) {
    user, err := s.repo.GetByID(ctx, id)
    if err != nil {
        return nil, fmt.Errorf("failed to get user %s: %w", id, err)
    }
    return user, nil
}
```

### Configuration

Use a config struct loaded from environment:

```go
// internal/config/config.go
package config

import "os"

type Config struct {
    Port        string
    MongoURI    string
    RedisHost   string
    LogLevel    string
}

func Load() *Config {
    return &Config{
        Port:        getEnv("PORT", "8080"),
        MongoURI:    getEnv("MONGO_URI", "mongodb://localhost:27017"),
        RedisHost:   getEnv("REDIS_HOST", "localhost:6379"),
        LogLevel:    getEnv("LOG_LEVEL", "info"),
    }
}

func getEnv(key, fallback string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return fallback
}
```

### Dependency Injection

Wire dependencies in main.go:

```go
// cmd/api/main.go
func main() {
    cfg := config.Load()
    logger := setupLogger(cfg.LogLevel)
    db := database.Connect(cfg.MongoURI)

    // Repositories
    userRepo := repositories.NewUserRepository(db)
    orderRepo := repositories.NewOrderRepository(db)

    // Services
    userService := services.NewUserService(userRepo)
    orderService := services.NewOrderService(orderRepo)

    // Handlers
    userHandler := handlers.NewUserHandler(userService)
    orderHandler := handlers.NewOrderHandler(orderService)

    // Router
    router := router.SetupRouter(userHandler, orderHandler)
    router.Run(":" + cfg.Port)
}
```

### Compile-Time Interface Checks

Verify implementations at compile time:

```go
var _ UserRepository = (*userRepositoryImpl)(nil)
```

---

## Summary

| Layer | Location | Contains |
|-------|----------|----------|
| Domain Entities | `/internal/domains/{feature}/entities/` | Business models |
| Repositories | `/internal/domains/{feature}/repositories/` | Data access interfaces + implementations |
| Services | `/internal/domains/{feature}/services/` | Business logic |ÂÂ
| Value Objects | `/internal/domains/{feature}/valueobjects/` | Enums, constants, immutable types |
| Handlers | `/internal/api/handlers/` | HTTP request handlers |
| Requests | `/internal/api/requests/` | Request models |
| Responses | `/internal/api/responses/` | Response models |
| Middleware | `/internal/api/middleware/` | Auth, logging, error handling |
| Router | `/internal/api/router/` | Route definitions |
| Config | `/internal/config/` | Configuration loading |
| Shared | `/internal/shared/` | Cross-feature utilities |
