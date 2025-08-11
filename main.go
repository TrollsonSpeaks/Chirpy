package main

import _ "github.com/lib/pq"

import (
	"os"
	"log"
	"database/sql"
	"github.com/joho/godotenv"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"fmt"
	"strings"
	"chirpy/internal/database"
	"time"
	"github.com/google/uuid"
	"errors"
	"chirpy/internal/auth"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	jwtSecret      string
	polkaKey       string
}

type User struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
}

type Chirp struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Body         string    `json:"body"`
	UserID       uuid.UUID `json:"user_id"`
}

type createUserRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
}

func (cfg *apiConfig) handlePolkaWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil {
		http.Error(w, "Missing or invalid API key", http.StatusUnauthorized)
		return
	}

	if apiKey != cfg.polkaKey {
		http.Error(w, "Invalid API key", http.StatusUnauthorized)
		return
	}

	type webhookRequest struct {
		Event   string `json:"event"`
		Data    struct {
			UserID uuid.UUID `json:"user_id"`
		} `json:"data"`
	}

	var req webhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	err = cfg.db.UpgradeUserToChirpyRed(r.Context(), req.Data.UserID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	hashed, err := auth.HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	user, err := cfg.db.CreateUser(r.Context(), database.CreateUserParams{
		Email:             req.Email,
		HashedPassword:    hashed,
	})
	if err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(struct {
		ID          uuid.UUID `json:"id"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		Email       string    `json:"email"`
	}{
		ID:         user.ID,
		CreatedAt:  user.CreatedAt,
		UpdatedAt:  user.UpdatedAt,
		Email:      user.Email,
	})
}

type loginRequest struct {
	Email             string `json:"email"`
	Password          string `json:"password"`
	//	ExpiresInSeconds  *int   `json:"expires_in_seconds,omitempty"`
}

func (cfg *apiConfig) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	user, err := cfg.db.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		http.Error(w, "Incorrect email or password", http.StatusUnauthorized)
		return
	}

	if err := auth.CheckPasswordHash(req.Password, user.HashedPassword); err != nil {
		http.Error(w, "Incorrect email or password", http.StatusUnauthorized)
		return
	}

	accessToken, err := auth.MakeJWT(user.ID, cfg.jwtSecret, time.Hour)
	if err != nil {
		http.Error(w, "Failed to create access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		http.Error(w, "Failed to create refresh token", http.StatusInternalServerError)
		return
	}

	expiresAt := time.Now().Add(60 * 24 * time.Hour)
	_, err = cfg.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:         refreshToken,
		UserID:        user.ID,
		ExpiresAt:     expiresAt,
	})
	if err != nil {
		http.Error(w, "Failed to store refresh token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		ID            uuid.UUID `json:"id"`
		CreatedAt     time.Time  `json:"created_at"`
		UpdatedAt     time.Time `json:"updated_at"`
		Email         string    `json:"email"`
		IsChirpyRed   bool      `json:"is_chirpy_red"`
		Token         string    `json:"token"`
		RefreshToken  string    `json:"refresh_token"`
	}{
		ID:           user.ID,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Email:        user.Email,
		IsChirpyRed:  user.IsChirpyRed,
		Token:        accessToken,
		RefreshToken: refreshToken,
	})
}

	/*

	const defaultExpirationSeconds = 3600
	const maxExpirationSeconds = 3600

	expirationSeconds := defaultExpirationSeconds

	if req.ExpiresInSeconds!= nil {
		clientExpiration := *req.ExpiresInSeconds
		if clientExpiration > 0 && clientExpiration <= maxExpirationSeconds {
			expirationSeconds = clientExpiration
		}
	}

	token, err := auth.MakeJWT(user.ID, cfg.jwtSecret, time.Duration(expirationSeconds)*time.Second)
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		ID          uuid.UUID `json:"id"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		Email       string    `json:"email"`
		Token       string    `json:"token"`
	}{
		ID:         user.ID,
		CreatedAt:  user.CreatedAt,
		UpdatedAt:  user.UpdatedAt,
		Email:      user.Email,
		Token:      token,
	})
} */

func (cfg *apiConfig) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, "Missing or invalid authorization header", http.StatusUnauthorized)
		return
	}

	err = cfg.db.RevokeRefreshToken(r.Context(), refreshToken)
	if err != nil {
		http.Error(w, "Failed to revoke token", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) deleteChirpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, "Missing or invalid authorization header", http.StatusUnauthorized)
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	chirpIDStr := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		http.Error(w, "Invalid chirp ID", http.StatusBadRequest)
		return
	}

	chirp, err := cfg.db.GetChirpByID(r.Context(), chirpID)
	if err != nil {
		http.Error(w, "Chirp not found", http.StatusNotFound)
		return
	}

	if chirp.UserID.UUID != userID {
		http.Error(w, "You can only delete your own chirps", http.StatusForbidden)
		return
	}

	err = cfg.db.DeleteChirp(r.Context(), database.DeleteChirpParams{
		ID:        chirpID,
		UserID:    uuid.NullUUID{UUID: userID, Valid: true},
	})
	if err != nil {
		http.Error(w, "Failed to delete chirp", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, "Missing or invalid authorization header", http.StatusUnauthorized)
		return
	}

	user, err := cfg.db.GetUserFromRefreshToken(r.Context(), refreshToken)
	if err != nil {
		http.Error(w, "Invalid or expired refreshed token", http.StatusUnauthorized)
		return
	}

	accessToken, err := auth.MakeJWT(user.ID, cfg.jwtSecret, time.Hour)
	if err != nil {
		http.Error(w, "Failed to create access token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Token string `json:"token"`
	}{
		Token: accessToken,
	})
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) adminMetricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	hitCount := int(cfg.fileserverHits.Load())
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`
		<html>
			<body>
				<h1>Welcome, Chirpy Admin</h1>
				<p>Chirpy has been visited %d times!</p>
			</body>
		</html>
		`, hitCount)))
}

func (cfg *apiConfig) adminResetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if cfg.platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Forbidden outside of dev environment"))
		return
	}

	err := cfg.db.DeleteAllUsers(r.Context())
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to delete users")
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("All users deleted"))
}

func (cfg *apiConfig) createUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	type requestBody struct {
		Email          string `json:"email"`
		Password       string `json:"password"`
	}

	var req requestBody
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || req.Email == "" {
		respondWithError(w, http.StatusBadRequest, "Invalid email input")
		return
	}

	hashed, err := auth.HashPassword(req.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not hash password")
		return
	}

	dbUser, err := cfg.db.CreateUser(r.Context(), database.CreateUserParams{
		Email:          req.Email,
		HashedPassword: hashed,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not create user")
		return
	}

	user := User{
		ID:          dbUser.ID,
		CreatedAt:   dbUser.CreatedAt,
		UpdatedAt:   dbUser.UpdatedAt,
		Email:       dbUser.Email,
		IsChirpyRed: dbUser.IsChirpyRed,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(user)
}

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { 
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid authorization header")
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	type requestBody struct {
		Body   string      `json:"body"`
	}

	var req requestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if len(req.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	cleanedBody := filterProfanity(req.Body)

	dbChirp, err := cfg.db.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:     cleanedBody,
		UserID:   uuid.NullUUID{UUID: userID, Valid: true},
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create chirp")
		return
	}

	chirp := Chirp{
		ID:         dbChirp.ID,
		CreatedAt:  dbChirp.CreatedAt,
		UpdatedAt:  dbChirp.UpdatedAt,
		Body:       dbChirp.Body,
		UserID:     dbChirp.UserID.UUID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(chirp)
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{
		"error": msg,
	})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}

func filterProfanity(body string) string {
	profaneWords := []string{"kerfuffle", "sharbert", "fornax"}

	words := strings.Split(body, " ")

	for i, word := range words {
		for _, bad := range profaneWords {
			if strings.ToLower(word) == bad {
				words[i] = "****"
				break
			}
		}
	}

	return strings.Join(words, " ")
}

func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	authorIDStr := r.URL.Query().Get("author_id")

	var chirps []database.Chirp
	var err error

	if authorIDStr != "" {
		authorID, err := uuid.Parse(authorIDStr)
		if err != nil {
			http.Error(w, "Invalid author_id format", http.StatusBadRequest)
			return
		}

		chirps, err = cfg.db.GetChirpsByAuthor(r.Context(), uuid.NullUUID{
			UUID:    authorID,
			Valid:   true,
		})
	} else {
		chirps, err = cfg.db.GetChirps(r.Context())
	}

	if err != nil {
		http.Error(w, "Failed to retrieve chirps", http.StatusInternalServerError)
		return
	}

	responseChirps := make([]Chirp, len(chirps))
	for i, chirp := range chirps {
		responseChirps[i] = Chirp{
			ID:         chirp.ID,
			CreatedAt:  chirp.CreatedAt,
			UpdatedAt:  chirp.UpdatedAt,
			Body:       chirp.Body,
			UserID:     chirp.UserID.UUID,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(responseChirps)
}

/*	dbChirps, err := cfg.db.GetChirps(r.Context())
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to fetch chirps")
		return
	}

	chirps := []Chirp{}
	for _, c := range dbChirps {
		chirps = append(chirps, Chirp{
			ID:         c.ID,
			CreatedAt:  c.CreatedAt,
			UpdatedAt:  c.UpdatedAt,
			Body:       c.Body,
			UserID:     c.UserID.UUID,
		})
	}

	respondWithJSON(w, http.StatusOK, chirps)
}	*/

func (cfg *apiConfig) chirpsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		cfg.createChirpHandler(w, r)
	case http.MethodGet:
		cfg.getChirpsHandler(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)	
	}
}

func (cfg *apiConfig) getChirpByIDHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	idStr := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(idStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid chirp id")
		return
	}

	dbChirp, err := cfg.db.GetChirp(r.Context(), chirpID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		respondWithError(w, http.StatusInternalServerError, "failed to fetch chirp")
		return
	}

	chirp := Chirp{
		ID:          dbChirp.ID,
		CreatedAt:   dbChirp.CreatedAt,
		UpdatedAt:   dbChirp.UpdatedAt,
		Body:        dbChirp.Body,
		UserID:      dbChirp.UserID.UUID,
	}

	respondWithJSON(w, http.StatusOK, chirp)
}

func (cfg *apiConfig) updateUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, "Missing or invalid authorization header", http.StatusUnauthorized)
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	type updateUserRequest struct {
		Email        string `json:"email"`
		Password     string `json:"password"`
	}

	var req updateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to has password", http.StatusInternalServerError)
		return
	}

	updatedUser, err := cfg.db.UpdateUser(r.Context(), database.UpdateUserParams{
		ID:             userID,
		Email:          req.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
	return
	}

	w.Header().Set("content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(struct {
		ID          uuid.UUID `json:"id"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		Email       string    `json:"email"`
		IsChirpyRed bool      `json:"is_chirpy_red"`
	}{
		ID:          updatedUser.ID,
		CreatedAt:   updatedUser.CreatedAt,
		UpdatedAt:   updatedUser.UpdatedAt,
		Email:       updatedUser.Email,
		IsChirpyRed: updatedUser.IsChirpyRed,
	})
}

func (cfg *apiConfig) usersHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		cfg.createUserHandler(w, r)
	case http.MethodPut:
		cfg.updateUserHandler(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	dbURL := os.Getenv("DB_URL")

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Cannot connect to database:", err)
	}

	dbQueries := database.New(db)

	platform := os.Getenv("PLATFORM")

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is not set")
	}

	polkaKey := os.Getenv("POLKA_KEY")
	if polkaKey == "" {
		log.Fatal("POLKA_KEY environment variable is not set")
	}
	
	apiCfg := apiConfig{
		db:         dbQueries,	
		platform:   platform,
		jwtSecret:  jwtSecret,
		polkaKey:   polkaKey,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/api/healthz", readinessHandler)
	mux.HandleFunc("/api/chirps", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			apiCfg.getChirpsHandler(w, r)
		case http.MethodPost:
			apiCfg.createChirpHandler(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	
	mux.HandleFunc("/api/users", apiCfg.usersHandler)
	mux.HandleFunc("/api/refresh", apiCfg.handleRefresh)
	mux.HandleFunc("/api/revoke", apiCfg.handleRevoke)
	mux.HandleFunc("/api/login", apiCfg.handleLogin)
	mux.HandleFunc("/api/polka/webhooks", apiCfg.handlePolkaWebhook)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpByIDHandler)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirpHandler)

	fileServer := http.FileServer(http.Dir("."))
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", fileServer)))
	
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("./assets"))))	

	mux.HandleFunc("/admin/metrics", apiCfg.adminMetricsHandler)
	mux.HandleFunc("/admin/reset", apiCfg.adminResetHandler)

	server := &http.Server{
		Addr:     ":8080",
		Handler:  mux,
	}

	server.ListenAndServe()
}
