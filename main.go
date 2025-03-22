package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/rs/cors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

const (
	DB_USER    = "admin"
	DB_PASS    = "kundhavi"
	DB_NAME    = "users"
	DB_HOST    = "localhost"
	DB_PORT    = 5432
	JWT_SECRET = "my_secret_key" // Change this in production!
)

var db *sql.DB

// User struct
type User struct {
	ID              int    `json:"id"`
	Username        string `json:"username"`
	Password        string `json:"password,omitempty"`
	ConfirmPassword string `json:"confirmPassword,omitempty"`
	Email           string `json:"email,omitempty"`
}

// JWT Claims
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Initialize Database
func initDB() {
	psqlConn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		DB_HOST, DB_PORT, DB_USER, DB_PASS, DB_NAME)

	var err error
	db, err = sql.Open("postgres", psqlConn)
	if err != nil {
		log.Fatal("Database connection error:", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal("Database is unreachable:", err)
	}

	// Create users table
	createTableQuery := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username VARCHAR(50) UNIQUE NOT NULL,
		password TEXT NOT NULL,
		email VARCHAR(100) UNIQUE NOT NULL
	);
	`
	_, err = db.Exec(createTableQuery)
	if err != nil {
		log.Fatal("Error creating users table:", err)
	}

	fmt.Println("Database initialized successfully!")
}

// Register a new user
//func RegisterHandler(w http.ResponseWriter, r *http.Request) {
//	var user User
//	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
//		http.Error(w, "Invalid request payload", http.StatusBadRequest)
//		return
//	}
//
//	// Check if passwords match
//	if user.Password != user.ConfirmPassword {
//		http.Error(w, "Passwords do not match", http.StatusBadRequest)
//		return
//	}
//
//	// Check if user exists
//	var existingUser string
//	err := db.QueryRow("SELECT username FROM users WHERE username=$1 OR email=$2", user.Username, user.Email).Scan(&existingUser)
//	if err == nil {
//		http.Error(w, "User already exists", http.StatusBadRequest)
//		return
//	}
//
//	// Hash password
//	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
//	if err != nil {
//		http.Error(w, "Error hashing password", http.StatusInternalServerError)
//		return
//	}
//
//	// Insert new user
//	_, err = db.Exec("INSERT INTO users (username, password, email) VALUES ($1, $2, $3)",
//		user.Username, string(hashedPassword), user.Email)
//	if err != nil {
//		http.Error(w, "Database error", http.StatusInternalServerError)
//		return
//	}
//
//	w.WriteHeader(http.StatusCreated)
//	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
//}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// ✅ Add CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// ✅ Handle OPTIONS preflight request
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Check if passwords match
	if user.Password != user.ConfirmPassword {
		http.Error(w, "Passwords do not match", http.StatusBadRequest)
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}
	_, err = db.Exec("INSERT INTO users (username, password, email) VALUES ($1, $2, $3)",
		user.Username, string(hashedPassword), user.Email)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Simulate user creation (replace with database logic)
	response := map[string]string{
		"message": "User registered successfully",
		"email":   user.Email,
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// Login and generate JWT
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	var hashedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username=$1", user.Username).Scan(&hashedPassword)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Check password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password))
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Generate JWT token
	token, err := generateJWT(user.Username)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// Middleware to validate JWT
func JWTMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		fmt.Println("Received Token:", tokenString) // Debugging print

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(JWT_SECRET), nil
		})

		if err != nil || !token.Valid {
			fmt.Println("Token parsing error:", err) // Debugging print
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		fmt.Println("Extracted Username from Token:", claims.Username) // Debugging print

		// Set username in the request header
		r.Header.Set("Username", claims.Username)
		next(w, r)
	}
}

// Get user profile
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("Username")
	var user User
	err := db.QueryRow("SELECT username, email FROM users WHERE username=$1", username).Scan(&user.Username, &user.Email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(user)
}

// Update user password
func UpdatePasswordHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("Username")
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("UPDATE users SET password=$1 WHERE username=$2", hashedPassword, username)
	if err != nil {
		http.Error(w, "Error updating password", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Password updated successfully"})
}

// Update user email
func UpdateEmailHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("Username")
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("UPDATE users SET email=$1 WHERE username=$2", user.Email, username)
	if err != nil {
		http.Error(w, "Error updating email", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Email updated successfully"})
}

// Generate JWT token
func generateJWT(username string) (string, error) {
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(JWT_SECRET))
}

// Main function
func main() {
	initDB()
	router := mux.NewRouter()

	router.HandleFunc("/register", RegisterHandler).Methods("POST")
	handler := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:4200"}, // Angular frontend
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	}).Handler(router)
	router.HandleFunc("/login", LoginHandler).Methods("POST")
	router.HandleFunc("/profile", JWTMiddleware(ProfileHandler)).Methods("GET")
	router.HandleFunc("/update-password", JWTMiddleware(UpdatePasswordHandler)).Methods("POST")
	router.HandleFunc("/update-email", JWTMiddleware(UpdateEmailHandler)).Methods("POST")

	fmt.Println("Server running on port 8081...")
	log.Fatal(http.ListenAndServe(":8081", handler))
}
