package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	RebootForums "RebootForums/Handlers"

	_ "github.com/mattn/go-sqlite3"
)

func makeHandler(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(w, r)
	}
}

func main() {
	// Initialize database
	err := RebootForums.InitDB("./forum.db")
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer RebootForums.DB.Close()

	// Create tables
	err = RebootForums.CreateTables()
	if err != nil {
		log.Fatal("Failed to create tables:", err)
	}

	// Add this line to ensure the updated_at column exists
	err = RebootForums.AddUpdatedAtColumn()
	if err != nil {
		log.Fatal("Failed to add updated_at column:", err)
	}

	// Add this line to ensure the image_filename column exists
	err = RebootForums.AddImageFilenameToPostsTable()
	if err != nil {
		log.Fatal("Failed to add image_filename column:", err)
	}

	// Get the absolute path to the templates directory
	templatesDir, err := filepath.Abs("./templates")
	if err != nil {
		log.Fatal("Failed to get absolute path for templates directory:", err)
	}
	log.Printf("Templates directory: %s", templatesDir)

	// Set the templates directory in the RebootForums package
	RebootForums.SetTemplatesDir(templatesDir)

	// Update the routes
	mux := http.NewServeMux()

	// Set up routes
	mux.HandleFunc("/", RebootForums.HomeHandler)
	mux.HandleFunc("/register", makeHandler(RebootForums.RegisterHandler))
	mux.HandleFunc("/login", makeHandler(RebootForums.LoginHandler))
	mux.HandleFunc("/logout", makeHandler(RebootForums.LogoutHandler))
	// Post-related routes
	mux.HandleFunc("/create-post", makeHandler(RebootForums.CreatePostFormHandler))
	mux.HandleFunc("/post/", makeHandler(RebootForums.ViewPostHandler))
	mux.HandleFunc("/delete-post/", makeHandler(RebootForums.DeletePostHandler))
	mux.HandleFunc("/like-post", makeHandler(RebootForums.LikePostHandler))
	mux.HandleFunc("/like-comment", makeHandler(RebootForums.LikeCommentHandler))
	mux.HandleFunc("/add-comment", makeHandler(RebootForums.AddCommentHandler))
	// Google and Github login Routes
	mux.HandleFunc("/auth/google/login", RebootForums.GoogleLoginHandler)
	mux.HandleFunc("/auth/google/callback", RebootForums.GoogleCallbackHandler)
	mux.HandleFunc("/auth/github/login", RebootForums.GithubLoginHandler)
	mux.HandleFunc("/auth/github/callback", RebootForums.GithubCallbackHandler)
	// Explicit error routes
	mux.HandleFunc("/400", RebootForums.Error400Handler)
	mux.HandleFunc("/404", RebootForums.Error404Handler)
	mux.HandleFunc("/500", RebootForums.Error500Handler)

	// Serve static files
	fs := http.FileServer(http.Dir("./static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// Create uploads directory if it doesn't exist
	uploadsDir := "./uploads"
	err = os.MkdirAll(uploadsDir, os.ModePerm)
	if err != nil {
		log.Fatal("Failed to create uploads directory:", err)
	}

	// Serve uploaded files
	uploadFS := http.FileServer(http.Dir(uploadsDir))
	mux.Handle("/uploads/", http.StripPrefix("/uploads/", uploadFS))

	// Start the server
	fmt.Println("Server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
