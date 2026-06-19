// main.go — сервер Secret ED с заморочками
package main

import (
	"compress/gzip"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var db *gorm.DB
var jwtKey = []byte("secret-ed-2026-very-secure-key")

// ========== МОДЕЛИ ==========
type User struct {
	ID        uint   `gorm:"primaryKey"`
	Username  string `gorm:"unique"`
	Password  string // bcrypt hash
	CreatedAt time.Time
}

type Room struct {
	ID        string `gorm:"primaryKey"`
	Name      string
	Password  string // bcrypt hash
	CreatorID uint
	CreatedAt time.Time
}

type Message struct {
	ID        uint      `gorm:"primaryKey"`
	RoomID    string    `gorm:"index"`
	SenderID  uint      `gorm:"index"`
	Encrypted string    `gorm:"type:text"`
	CreatedAt time.Time
}

// ========== ОЧЕРЕДЬ ОФЛАЙН-СООБЩЕНИЙ ==========
type OfflineQueue struct {
	mu sync.Mutex
	// userID → []Message
	queue map[uint][]Message
}

var offline = OfflineQueue{
	queue: make(map[uint][]Message),
}

// ========== WEBSOCKET ==========
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}
var clients = make(map[uint]*websocket.Conn)
var clientsMu sync.Mutex

// ========== MAIN ==========
func main() {
	// 1. База данных
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "host=localhost user=postgres password=postgres dbname=secreted port=5432 sslmode=disable"
	}

	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		log.Fatal("❌ Ошибка подключения к БД:", err)
	}
	db.AutoMigrate(&User{}, &Room{}, &Message{})
	log.Println("✅ База данных подключена")

	// 2. Обработчики
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/rooms", authMiddleware(roomsHandler))
	http.HandleFunc("/ws", authMiddleware(wsHandler))

	// 3. Rate Limiting (простой)
	go func() {
		log.Println("🧹 Cleaner: удаление старых сообщений каждые 24 часа")
		for {
			time.Sleep(24 * time.Hour)
			db.Where("created_at < ?", time.Now().AddDate(0, 0, -30)).Delete(&Message{})
		}
	}()

	// 4. Graceful Shutdown
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	srv := &http.Server{Addr: ":" + port, Handler: http.DefaultServeMux}
	go func() {
		log.Println("🚀 Сервер запущен на порту", port)
		log.Fatal(srv.ListenAndServe())
	}()

	// 5. Обработка Ctrl+C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	log.Println("🛑 Получен сигнал остановки, завершаем работу...")
	srv.Close()
	log.Println("✅ Сервер остановлен корректно")
}

// ========== ОБРАБОТЧИКИ ==========
func pingHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("pong"))
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", 400)
		return
	}

	var existing User
	if db.Where("username = ?", req.Username).First(&existing).Error == nil {
		http.Error(w, "User already exists", 400)
		return
	}

	hashed, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	user := User{Username: req.Username, Password: string(hashed)}
	db.Create(&user)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Hour * 24 * 7).Unix(),
	})
	tokenString, _ := token.SignedString(jwtKey)
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	var user User
	if err := db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		http.Error(w, "Invalid credentials", 401)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid credentials", 401)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Hour * 24 * 7).Unix(),
	})
	tokenString, _ := token.SignedString(jwtKey)
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func roomsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		var rooms []Room
		db.Find(&rooms)
		json.NewEncoder(w).Encode(rooms)
		return
	}
	if r.Method == "POST" {
		var req struct {
			Name     string `json:"name"`
			Password string `json:"password"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		hashed, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		room := Room{
			ID:        generateRoomID(),
			Name:      req.Name,
			Password:  string(hashed),
			CreatorID: 1, // TODO: из JWT
		}
		db.Create(&room)
		json.NewEncoder(w).Encode(map[string]string{"room_id": room.ID})
		return
	}
	http.Error(w, "Method not allowed", 405)
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade error:", err)
		return
	}
	defer conn.Close()

	// Получаем user_id из контекста (JWT)
	userID := uint(1) // временно
	clientsMu.Lock()
	clients[userID] = conn
	clientsMu.Unlock()

	// Отправляем офлайн-сообщения
	offline.mu.Lock()
	for _, msg := range offline.queue[userID] {
		conn.WriteJSON(msg)
	}
	delete(offline.queue, userID)
	offline.mu.Unlock()

	for {
		var msg Message
		err := conn.ReadJSON(&msg)
		if err != nil {
			break
		}
		msg.SenderID = userID
		msg.CreatedAt = time.Now()

		// Сохраняем в БД
		db.Create(&msg)

		// Отправляем получателю (если онлайн)
		clientsMu.Lock()
		if targetConn, ok := clients[msg.SenderID]; ok {
			targetConn.WriteJSON(msg)
		} else {
			offline.mu.Lock()
			offline.queue[msg.SenderID] = append(offline.queue[msg.SenderID], msg)
			offline.mu.Unlock()
		}
		clientsMu.Unlock()
	}

	clientsMu.Lock()
	delete(clients, userID)
	clientsMu.Unlock()
}

// ========== УТИЛИТЫ ==========
func authMiddleware(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", 401)
			return
		}
		next(w, r)
	}
}

func generateRoomID() string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 16)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
		time.Sleep(1 * time.Nanosecond)
	}
	return string(b)
}

func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			gz := gzip.NewWriter(w)
			defer gz.Close()
			w.Header().Set("Content-Encoding", "gzip")
			next.ServeHTTP(gz, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}