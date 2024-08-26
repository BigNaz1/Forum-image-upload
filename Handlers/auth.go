package RebootForums

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

var (
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/auth/google/callback",
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}

	githubOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/auth/github/callback",
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		Scopes:       []string{"user:email"},
		Endpoint:     github.Endpoint,
	}

	oauthStateString = uuid.New().String()
)

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		RenderTemplate(w, "register.html", nil)
		return
	}

	if r.Method == "POST" {
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		if username == "" || email == "" || password == "" {
			RenderTemplate(w, "register.html", map[string]interface{}{"Message": "All fields are required"})
			return
		}

		var exists bool
		err := DB.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ? OR email = ?)", username, email).Scan(&exists)
		if err != nil {
			log.Printf("Database error during registration: %v", err)
			RenderTemplate(w, "register.html", map[string]interface{}{"Message": "Database error"})
			return
		}
		if exists {
			RenderTemplate(w, "register.html", map[string]interface{}{"Message": "Username or email already exists"})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Error hashing password: %v", err)
			RenderTemplate(w, "register.html", map[string]interface{}{"Message": "Error creating user"})
			return
		}

		_, err = DB.Exec("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", username, email, string(hashedPassword))
		if err != nil {
			log.Printf("Error creating user: %v", err)
			RenderTemplate(w, "register.html", map[string]interface{}{"Message": "Error creating user"})
			return
		}

		// Retrieve the user ID of the newly registered user
		var userID int
		err = DB.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
		if err != nil {
			log.Printf("Error retrieving user ID: %v", err)
			RenderTemplate(w, "register.html", map[string]interface{}{"Message": "Error retrieving user"})
			return
		}

		// Generate a session token
		sessionToken, err := generateSessionToken()
		if err != nil {
			log.Printf("Error generating session token: %v", err)
			RenderTemplate(w, "register.html", map[string]interface{}{"Message": "Error creating session"})
			return
		}

		expiryTime := time.Now().Add(24 * time.Hour)
		err = UpsertSession(&userID, sessionToken, expiryTime, false)
		if err != nil {
			log.Printf("Error creating session: %v", err)
			RenderTemplate(w, "register.html", map[string]interface{}{"Message": "Error creating session"})
			return
		}

		// Set the session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			Expires:  expiryTime,
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil, // Set Secure flag if using HTTPS
		})

		// Redirect to the homepage or a different page as needed
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		message := ""
		error := false
		if r.URL.Query().Get("registered") == "true" {
			message = "Registration successful. Please log in."
		}
		RenderTemplate(w, "login.html", map[string]interface{}{"Message": message, "Error": error})
		return
	}

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "" || password == "" {
			RenderTemplate(w, "login.html", map[string]interface{}{
				"Message": "Username and password are required",
				"Error":   true,
			})
			return
		}

		var user User
		var hashedPassword string
		err := DB.QueryRow("SELECT id, username, password FROM users WHERE username = ?", username).Scan(&user.ID, &user.Username, &hashedPassword)
		if err != nil {
			if err == sql.ErrNoRows {
				RenderTemplate(w, "login.html", map[string]interface{}{
					"Message": "Invalid username or password",
					"Error":   true,
				})
			} else {
				log.Printf("Database error during login: %v", err)
				RenderTemplate(w, "login.html", map[string]interface{}{
					"Message": "An error occurred. Please try again later.",
					"Error":   true,
				})
			}
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
			RenderTemplate(w, "login.html", map[string]interface{}{
				"Message": "Invalid username or password",
				"Error":   true,
			})
			return
		}

		// Delete any existing sessions for this user
		_, err = DB.Exec("DELETE FROM sessions WHERE user_id = ?", user.ID)
		if err != nil {
			log.Printf("Error deleting existing sessions: %v", err)
			RenderTemplate(w, "login.html", map[string]interface{}{
				"Message": "An error occurred. Please try again later.",
				"Error":   true,
			})
			return
		}

		sessionToken, err := generateSessionToken()
		if err != nil {
			log.Printf("Error generating session token: %v", err)
			RenderTemplate(w, "login.html", map[string]interface{}{
				"Message": "An error occurred. Please try again later.",
				"Error":   true,
			})
			return
		}

		expiryTime := time.Now().Add(24 * time.Hour)
		err = UpsertSession(&user.ID, sessionToken, expiryTime, false)
		if err != nil {
			log.Printf("Error creating session: %v", err)
			RenderTemplate(w, "login.html", map[string]interface{}{
				"Message": "An error occurred. Please try again later.",
				"Error":   true,
			})
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			Expires:  expiryTime,
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil, // Set Secure flag if using HTTPS
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func generateSessionToken() (string, error) {
	token := uuid.New().String()
	return token, nil
}

func GetUserByUsername(username string) (*User, error) {
	var user User
	err := DB.QueryRow("SELECT id, username, email, password FROM users WHERE username = ?", username).Scan(&user.ID, &user.Username, &user.Email, &user.Password)
	if err != nil {
		log.Printf("Error getting user by username: %v", err)
		return nil, err
	}
	return &user, nil
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session_token")
	if err != nil {
		// If there's no session cookie, just redirect to home page
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Delete the session from the database
	err = DeleteSession(c.Value)
	if err != nil {
		log.Printf("Error deleting session: %v", err)
		// Continue with logout even if there's an error
	}

	// Clear the cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Now().Add(-1 * time.Hour), // Set expiry in the past
		MaxAge:   -1,
	})

	// Redirect to home page
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func GoogleLoginHandler(w http.ResponseWriter, r *http.Request) {
	url := googleOauthConfig.AuthCodeURL(oauthStateString)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func GoogleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("state") != oauthStateString {
		log.Printf("Invalid oauth state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	token, err := googleOauthConfig.Exchange(context.Background(), r.FormValue("code"))
	if err != nil {
		log.Printf("Code exchange failed: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		log.Printf("Failed getting user info: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	defer response.Body.Close()

	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Printf("Failed reading response body: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	var userInfo struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(contents, &userInfo); err != nil {
		log.Printf("Failed to parse user info: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	user, err := GetOrCreateUser(userInfo.Email, userInfo.Name, "google")
	if err != nil {
		log.Printf("Failed to get or create user: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	createSessionAndRedirect(w, r, user)
}

func GithubLoginHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("GitHub login handler called")
	url := githubOauthConfig.AuthCodeURL(oauthStateString)
	log.Printf("Redirecting to GitHub OAuth URL: %s", url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func GithubCallbackHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("GitHub callback handler called")

	if r.FormValue("state") != oauthStateString {
		log.Printf("Invalid oauth state, expected %s, got %s", oauthStateString, r.FormValue("state"))
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	token, err := githubOauthConfig.Exchange(context.Background(), r.FormValue("code"))
	if err != nil {
		log.Printf("Code exchange failed: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	client := githubOauthConfig.Client(context.Background(), token)
	response, err := client.Get("https://api.github.com/user")
	if err != nil {
		log.Printf("Failed getting user info: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	defer response.Body.Close()

	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Printf("Failed reading response body: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	log.Printf("GitHub API response: %s", string(contents))

	var userInfo struct {
		Email string `json:"email"`
		Name  string `json:"name"`
		Login string `json:"login"`
	}
	if err := json.Unmarshal(contents, &userInfo); err != nil {
		log.Printf("Failed to parse user info: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// If email is not public, fetch it separately
	if userInfo.Email == "" {
		log.Println("Email not found in initial response, fetching emails separately")
		emailResponse, err := client.Get("https://api.github.com/user/emails")
		if err != nil {
			log.Printf("Failed getting user emails: %s", err.Error())
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		defer emailResponse.Body.Close()

		var emails []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if err := json.NewDecoder(emailResponse.Body).Decode(&emails); err != nil {
			log.Printf("Failed to parse user emails: %s", err.Error())
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		for _, email := range emails {
			if email.Primary && email.Verified {
				userInfo.Email = email.Email
				log.Printf("Found primary verified email: %s", userInfo.Email)
				break
			}
		}
	}

	if userInfo.Email == "" {
		log.Printf("No valid email found for GitHub user")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	log.Printf("Creating user with email: %s and login: %s", userInfo.Email, userInfo.Login)
	user, err := GetOrCreateUser(userInfo.Email, userInfo.Login, "github")
	if err != nil {
		log.Printf("Failed to get or create user: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	createSessionAndRedirect(w, r, user)
}

func GetOrCreateUser(email, name, provider string) (*User, error) {
	var user User
	err := DB.QueryRow("SELECT id, username, email FROM users WHERE email = ?", email).Scan(&user.ID, &user.Username, &user.Email)
	if err == sql.ErrNoRows {
		// User doesn't exist, create a new one
		username := generateUsername(email, name, provider)
		result, err := DB.Exec("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", username, email, "")
		if err != nil {
			return nil, fmt.Errorf("failed to create user: %v", err)
		}
		userID, err := result.LastInsertId()
		if err != nil {
			return nil, fmt.Errorf("failed to get last insert ID: %v", err)
		}
		user = User{
			ID:       int(userID),
			Username: username,
			Email:    email,
		}
	} else if err != nil {
		return nil, fmt.Errorf("failed to query user: %v", err)
	}

	return &user, nil
}

func generateUsername(email, name, provider string) string {
	var username string
	if provider == "github" {
		username = "GIT_" + name
	} else if provider == "google" {
		parts := strings.Split(email, "@")
		username = "GO_" + strings.Split(parts[0], ".")[0]
	}

	// Ensure the username is unique
	baseUsername := username
	suffix := 1
	for {
		var exists bool
		err := DB.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", username).Scan(&exists)
		if err != nil {
			log.Printf("Error checking username existence: %v", err)
			return fmt.Sprintf("%s_%s", baseUsername, uuid.New().String())
		}
		if !exists {
			return username
		}
		suffix++
		username = fmt.Sprintf("%s%d", baseUsername, suffix)
	}
}

func createSessionAndRedirect(w http.ResponseWriter, r *http.Request, user *User) {
	sessionToken, err := generateSessionToken()
	if err != nil {
		log.Printf("Error generating session token: %v", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	expiryTime := time.Now().Add(24 * time.Hour)
	err = UpsertSession(&user.ID, sessionToken, expiryTime, false)
	if err != nil {
		log.Printf("Error creating session: %v", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  expiryTime,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
