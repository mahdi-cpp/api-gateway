package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var jwtSecretKey = []byte("your_very_secret_key")

// AuthMiddleware verifies JWT tokens from the Authorization header
func AuthMiddleware() gin.HandlerFunc {

	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required."})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header format is 'Bearer <token>'."})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// Parse and validate the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecretKey, nil
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token."})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if userID, ok := claims["user_id"].(string); ok {
				c.Set("user_id", userID)
				c.Next()
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID in token is invalid."})
				c.Abort()
			}
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims."})
			c.Abort()
		}
	}
}

// ReverseProxy creates a reverse proxy for a target URL
func ReverseProxy(target *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Modify the request to indicate it's being proxied
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Header.Set("X-Proxy", "API-Gateway")
		req.Header.Set("X-Proxy-Time", time.Now().Format(time.RFC3339))
	}

	return proxy
}

func main() {
	r := gin.Default()

	// Define backend service URLs
	photosServiceURL, _ := url.Parse("http://localhost:50100")
	settingsServiceURL, _ := url.Parse("http://localhost:50101")

	// Create reverse proxies
	photosProxy := ReverseProxy(photosServiceURL)
	settingsProxy := ReverseProxy(settingsServiceURL)

	// Login route to generate JWT tokens
	r.POST("/login", func(c *gin.Context) {
		var loginData struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := c.BindJSON(&loginData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request."})
			return
		}

		// Mock authentication - replace with real validation
		if loginData.Username != "admin" || loginData.Password != "password" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials."})
			return
		}

		// Create token with claims
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": "12345", // Example user ID
			"exp":     time.Now().Add(time.Hour * 24).Unix(),
		})

		// Sign and get the complete encoded token
		tokenString, err := token.SignedString(jwtSecretKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token."})
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	})

	// Photos service routes (protected)
	photos := r.Group("/photos")
	photos.Use(AuthMiddleware())
	{
		photos.Any("/*path", func(c *gin.Context) {
			// Add user ID to headers for the backend service
			userID, _ := c.Get("user_id")
			c.Request.Header.Set("X-User-ID", userID.(string))

			// Remove the prefix before forwarding
			c.Request.URL.Path = strings.TrimPrefix(c.Request.URL.Path, "/photos")
			if c.Request.URL.Path == "" {
				c.Request.URL.Path = "/"
			}

			photosProxy.ServeHTTP(c.Writer, c.Request)
		})
	}

	// Settings service routes (protected)
	settings := r.Group("/settings")
	settings.Use(AuthMiddleware())
	{
		settings.Any("/*path", func(c *gin.Context) {
			// Add user ID to headers for the backend service
			userID, _ := c.Get("user_id")
			c.Request.Header.Set("X-User-ID", userID.(string))

			// Remove the prefix before forwarding
			c.Request.URL.Path = strings.TrimPrefix(c.Request.URL.Path, "/settings")
			if c.Request.URL.Path == "" {
				c.Request.URL.Path = "/"
			}

			settingsProxy.ServeHTTP(c.Writer, c.Request)
		})
	}

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "OK", "service": "API Gateway"})
	})

	// Protected route example
	r.GET("/protected", AuthMiddleware(), func(c *gin.Context) {
		userID, _ := c.Get("user_id")
		c.JSON(http.StatusOK, gin.H{"message": "Access granted", "user_id": userID})
	})

	fmt.Println("API Gateway running on :8080")
	err := r.Run(":8080")
	if err != nil {
		return
	}
}
