package main

import (
	"api-gateway/internal/jwt-middleware"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func main() {

	ginInit()

	jwt_middleware.CreateRefreshToken()

	// Define backend service URLs
	settingsServiceURL, _ := url.Parse("http://localhost:50150")
	photosServiceURL, _ := url.Parse("http://localhost:50151")

	// Create reverse proxies
	photosProxy := ReverseProxy(photosServiceURL)
	settingsProxy := ReverseProxy(settingsServiceURL)

	// Login route to generate JWT tokens
	router.POST("/login", func(c *gin.Context) {
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
		tokenString, err := token.SignedString(jwt_middleware.JwtSecretKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token."})
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	})

	// Photos service routes (unprotected)
	photos := router.Group("/photos")
	{
		photos.Any("/*path", func(c *gin.Context) {

			// Add user ID to headers for the backend service
			userID := c.GetHeader("user_id")
			fmt.Println(userID)

			// Remove the prefix before forwarding
			c.Request.URL.Path = strings.TrimPrefix(c.Request.URL.Path, "/photos")
			if c.Request.URL.Path == "" {
				c.Request.URL.Path = "/"
				fmt.Println(c.Request.URL.Path)
			}
			c.Request.Header.Set("X-User-ID", userID)

			photosProxy.ServeHTTP(c.Writer, c.Request)
		})
	}

	// Settings service routes (protected)
	settings := router.Group("/settings")
	settings.Use(jwt_middleware.AuthMiddleware())
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
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "OK", "service": "API Gateway"})
	})

	// Protected route example
	router.GET("/protected", jwt_middleware.AuthMiddleware(), func(c *gin.Context) {
		userID, _ := c.Get("user_id")
		c.JSON(http.StatusOK, gin.H{"message": "Access granted", "user_id": userID})
	})

	fmt.Println("API Gateway running on :50000")
	startServer(router)
}
