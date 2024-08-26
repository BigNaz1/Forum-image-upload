package RebootForums

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// GetRecentPosts fetches recent posts from the database
func GetRecentPosts(limit int) ([]Post, error) {
	query := `
        SELECT p.id, p.title, p.content, u.username, p.created_at, p.image_filename
        FROM posts p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC
        LIMIT ?
    `
	rows, err := DB.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var p Post
		var imageFilename sql.NullString
		err := rows.Scan(&p.ID, &p.Title, &p.Content, &p.Author, &p.CreatedAt, &imageFilename)
		if err != nil {
			return nil, err
		}
		if imageFilename.Valid {
			p.ImageFilename = imageFilename.String
		}
		posts = append(posts, p)
	}
	return posts, nil
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		Error404Handler(w, r)
		return
	}

	user, err := GetUserFromSession(r)
	loggedIn := err == nil && user != nil
	var username string
	var isGuest bool
	var sessionDuration time.Duration

	if loggedIn {
		username = user.Username
		isGuest = false
	} else {
		isGuest = true
	}

	cookie, _ := r.Cookie("session_token")
	if cookie != nil {
		sessionDuration, _ = GetSessionDuration(cookie.Value)
	}

	categoryParam := r.URL.Query().Get("category")
	filter := r.URL.Query().Get("filter")

	var posts []Post
	var fetchErr error
	var selectedCategoryID int

	if categoryParam != "" {
		selectedCategoryID, err = strconv.Atoi(categoryParam)
		if err != nil {
			Error400Handler(w, r)
			return
		}
		posts, fetchErr = GetPostsByCategory(selectedCategoryID)
	} else if filter == "created" && loggedIn {
		posts, fetchErr = GetPostsByUser(user.ID)
	} else if filter == "liked" && loggedIn {
		posts, fetchErr = GetLikedPostsByUser(user.ID)
	} else {
		posts, fetchErr = GetRecentPosts(10)
	}

	if fetchErr != nil {
		log.Printf("Failed to fetch posts: %v", fetchErr)
		Error500Handler(w, r)
		return
	}

	categories, err := GetAllCategories()
	if err != nil {
		log.Printf("Failed to fetch categories: %v", err)
		Error500Handler(w, r)
		return
	}

	data := struct {
		Posts            []Post
		Categories       []Category
		LoggedIn         bool
		Username         string
		IsGuest          bool
		SessionDuration  string
		Filter           string
		SelectedCategory int
	}{
		Posts:            posts,
		Categories:       categories,
		LoggedIn:         loggedIn,
		Username:         username,
		IsGuest:          isGuest,
		SessionDuration:  sessionDuration.Round(time.Second).String(),
		Filter:           filter,
		SelectedCategory: selectedCategoryID,
	}

	templatesDir := GetTemplatesDir()
	if templatesDir == "" {
		log.Printf("Templates directory is not set")
		Error500Handler(w, r)
		return
	}

	templatePath := filepath.Join(templatesDir, "home.html")
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		log.Printf("Template file does not exist: %s", templatePath)
		Error500Handler(w, r)
		return
	}

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		log.Printf("Failed to parse template: %v", err)
		Error500Handler(w, r)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Failed to execute template: %v", err)
		Error500Handler(w, r)
		return
	}

	log.Printf("Successfully rendered home page")
}
