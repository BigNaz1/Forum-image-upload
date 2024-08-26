package RebootForums

import (
	"fmt"
	"image"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"

	"github.com/google/uuid"
)

const (
	MaxImageSize    = 20 * 1024 * 1024 // 20 MB
	UploadDirectory = "./uploads"
)

// ImageHandler handles the image upload process
func ImageHandler(file multipart.File, handler *multipart.FileHeader) (string, error) {
	// Check file size
	if handler.Size > MaxImageSize {
		return "", fmt.Errorf("image is too large (max %d MB)", MaxImageSize/(1024*1024))
	}

	// Validate file type
	buff := make([]byte, 512)
	_, err := file.Read(buff)
	if err != nil {
		return "", err
	}

	filetype := http.DetectContentType(buff)
	if filetype != "image/jpeg" && filetype != "image/png" && filetype != "image/gif" {
		return "", fmt.Errorf("invalid file type: only JPEG, PNG and GIF are allowed")
	}

	// Reset the read pointer
	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return "", err
	}

	// Decode the image to validate it
	_, _, err = image.Decode(file)
	if err != nil {
		return "", fmt.Errorf("invalid image file: %v", err)
	}

	// Reset the read pointer again
	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return "", err
	}

	// Generate a unique filename
	ext := strings.ToLower(filepath.Ext(handler.Filename))
	newFilename := uuid.New().String() + ext

	// Ensure upload directory exists
	err = os.MkdirAll(UploadDirectory, os.ModePerm)
	if err != nil {
		return "", err
	}

	// Create the file
	dst, err := os.Create(filepath.Join(UploadDirectory, newFilename))
	if err != nil {
		return "", err
	}
	defer dst.Close()

	// Copy the uploaded file to the created file on the filesystem
	_, err = io.Copy(dst, file)
	if err != nil {
		return "", err
	}

	return newFilename, nil
}

// GetImageURL returns the URL for the given image filename
func GetImageURL(filename string) string {
	return fmt.Sprintf("/uploads/%s", filename)
}

// DeleteImage deletes the image file with the given filename
func DeleteImage(filename string) error {
	err := os.Remove(filepath.Join(UploadDirectory, filename))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
