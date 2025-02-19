package main

import (
	"database/sql"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var jwtKey = []byte("wakeuptoreality")

const otpExpiration = 30 * time.Second
const otpRequestLimit = 3
const blockDuration = 15 * time.Minute

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type OTP struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	OTP       string    `json:"otp"`
	CreatedAt time.Time `json:"created_at"`
}

type Claims struct {
	UserID int `json:"id"`
	jwt.StandardClaims
}

func main() {
	var err error
	db, err = sql.Open("mysql", "lord:lord@tcp(localhost:3306)/testdb2?parseTime=true")
	if err != nil {
		log.Fatal(err)
	}

	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://127.0.0.1:5500"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	r.POST("/signup", signupHandler)
	r.POST("/login", loginHandler)
	r.POST("/request-otp", requestOTPHandler)
	r.POST("/verify-otp", verifyOTPHandler)
	r.GET("/protected", authMiddleware, protectedHandler)

	r.Run(":8080")
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func signupHandler(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Input"})
		return
	}

	hashedPassword, err := HashPassword(user.Password)
	_, err = db.Exec("INSERT INTO user (username, password) VALUES (?, ?)", user.Username, hashedPassword)
	if err != nil {
		log.Println("Error inserting user:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving user data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User saved successfully"})
}

func loginHandler(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Input"})
		return
	}

	var storedPassword string
	var userID int
	err := db.QueryRow("SELECT id, password FROM user WHERE username=?", user.Username).Scan(&userID, &storedPassword)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if !CheckPasswordHash(user.Password, storedPassword) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Password"})
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func generateOTP() string {
	rand.Seed(time.Now().UnixNano())
	return strconv.Itoa(rand.Intn(10000))
}

func requestOTPHandler(c *gin.Context) {
	var otpReq struct {
		UserID int `json:"user_id"`
	}
	if err := c.ShouldBindJSON(&otpReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Input"})
		return
	}

	var lastCreatedAt time.Time
	var attemptCount int
	err := db.QueryRow("SELECT COUNT(*) FROM otps WHERE userID=? AND created_at > ?", otpReq.UserID, time.Now().Add(-blockDuration)).Scan(&attemptCount)
	if err == nil && attemptCount >= otpRequestLimit {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Too many OTP requests. Try again after 15 minutes."})
		return
	}

	err = db.QueryRow("SELECT created_at FROM otps WHERE userID=? ORDER BY id DESC LIMIT 1", otpReq.UserID).Scan(&lastCreatedAt)
	if err == nil && time.Since(lastCreatedAt) < otpExpiration {
		c.JSON(http.StatusBadRequest, gin.H{"error": "OTP request too soon. Try again later."})
		return
	}

	otp := generateOTP()
	_, err = db.Exec("INSERT INTO otps (userID, otp, created_at) VALUES (?, ?, ?)", otpReq.UserID, otp, time.Now())
	if err != nil {
		log.Println("Error inserting OTP:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving OTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OTP sent successfully"})
}

func verifyOTPHandler(c *gin.Context) {
	var otpReq OTP
	if err := c.ShouldBindJSON(&otpReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Input"})
		return
	}

	var storedOTP string
	var createdAt time.Time
	err := db.QueryRow("SELECT otp, created_at FROM otps WHERE userID=? ORDER BY id DESC LIMIT 1", otpReq.UserID).Scan(&storedOTP, &createdAt)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid OTP"})
		return
	}

	if time.Since(createdAt) > 30*time.Second {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "OTP expired"})
		return
	}

	if storedOTP == otpReq.OTP {
		c.JSON(http.StatusOK, gin.H{"message": "OTP verified successfully"})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid OTP"})
	}
}

func authMiddleware(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		c.Abort()
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		c.Abort()
		return
	}

	c.Set("userID", claims.UserID)
	c.Next()
}

func protectedHandler(c *gin.Context) {
	userID, _ := c.Get("userID")
	c.JSON(http.StatusOK, gin.H{"message": "Hello, user " + strconv.Itoa(userID.(int))})
}
