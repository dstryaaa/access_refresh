package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	_ "go.mongodb.org/mongo-driver/x/mongo/driver/topology"

	_ "crypto/tls"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// User struct represents a user in our authentication system
type User struct {
	ID string `json:"id"`
}

// AccessTokenResponse struct represents the response for access token generation
type AccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// RefreshTokenRequest struct represents the request for token refresh
type RefreshTokenRequest struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

const (
	connectionString = "MongoDB connection string"
	dbName           = "Database name"
	collection       = "Collection name"
)

// JWT secret key
const jwtSecret = "mysecret"

// GenerateAccessToken creates a new JWT with a 1 hour expiration time
func GenerateAccessToken(userID string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS512)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = userID
	claims["exp"] = time.Now().Add(time.Hour * 1).Unix()
	return token.SignedString([]byte(jwtSecret))
}

func GenerateRefreshToken() (string, error) {
	uuid, err := NewUUID()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(uuid.String())), nil
}

// NewUUID generates a new UUIDv4
func NewUUID() (uuid.UUID, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return uuid.UUID{}, err
	}
	return id, nil
}

func RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var request RefreshTokenRequest
	err := decoder.Decode(&request)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	refreshTokenRaw := []byte(request.RefreshToken)

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(request.AccessToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid Access or Refresh token", http.StatusUnauthorized)
		return
	}
	userID := claims["sub"].(string)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(connectionString))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)
	coll := client.Database(dbName).Collection(collection)
	var result bson.M
	err = coll.FindOne(ctx, bson.M{"user_id": userID}).Decode(&result)
	if err != nil {
		http.Error(w, "Invalid Access or Refresh token", http.StatusUnauthorized)
		return
	}

	fmt.Println(request.RefreshToken)
	fmt.Println(result["refresh_token"].(string))
	hashString := result["refresh_token"].(string)
	hashBytes, _ := base64.StdEncoding.DecodeString(hashString)

	if !VerifyHash(hashBytes, refreshTokenRaw) {
		http.Error(w, "Invalid Access or Refresh token", http.StatusUnauthorized)
		return
	}

	accessToken, err := GenerateAccessToken(userID)
	if err != nil {
		http.Error(w, "Cannot generate Access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := GenerateRefreshToken()
	if err != nil {
		http.Error(w, "Cannot generate Refresh token", http.StatusInternalServerError)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Cannot generate Refresh token hash"+refreshToken, http.StatusInternalServerError)
		return
	}
	hashEncoded := base64.StdEncoding.EncodeToString(hash)

	// Updating the refresh token
	update := bson.M{"$set": bson.M{"refresh_token": hashEncoded}}
	_, err = coll.UpdateOne(ctx, bson.M{"user_id": userID}, update)
	if err != nil {
		log.Fatal(err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AccessTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

// VerifyHash compares a password hash with a raw value
func VerifyHash(hash []byte, raw []byte) bool {
	err := bcrypt.CompareHashAndPassword(hash, raw)
	return err == nil
}

// AccessTokenHandler generates a new Access and Refresh token pair for a given UserID
func AccessTokenHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.FormValue("user_id")
	if userID == "" {
		http.Error(w, "Missing user ID", http.StatusBadRequest)
		return
	}

	// Generate Access token
	accessToken, err := GenerateAccessToken(userID)
	if err != nil {
		http.Error(w, "Cannot generate Access token", http.StatusInternalServerError)
		return
	}

	// Generate Refresh token
	refreshToken, err := GenerateRefreshToken()
	if err != nil {
		http.Error(w, "Cannot generate Refresh token", http.StatusInternalServerError)
		return
	}

	// Save Refresh token hash in MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(connectionString))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)
	coll := client.Database(dbName).Collection(collection)
	fmt.Println(refreshToken)
	hash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Cannot generate Refresh token hash"+refreshToken, http.StatusInternalServerError)
		return
	}
	hashEncoded := base64.StdEncoding.EncodeToString(hash)
	fmt.Println(hashEncoded)
	_, err = coll.InsertOne(ctx, bson.M{"user_id": userID, "refresh_token": hashEncoded})
	if err != nil {
		http.Error(w, "Cannot save Refresh token hash in database", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AccessTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

func main() {
	http.HandleFunc("/access_token", AccessTokenHandler)
	http.HandleFunc("/refresh_token", RefreshTokenHandler)
	fmt.Println("Listening on port 8080...")
	http.ListenAndServe(":8080", nil)
}
