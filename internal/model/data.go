package model

import (
	"time"
)

type FileContentWithPath struct {
	// The name of the file.
	Name string

	// The binary content of the file.
	Data []byte

	// Path is the file's path on the file system without name.
	Path string

	// PrefixDate is the date prefix associated with the file.
	// This will default to the current time in UTC if not explicitly set.
	PrefixDate time.Time

	PrefixFromName bool

	RequestType string
}

func NewFileContentWithPath(name string, data []byte, path string) *FileContentWithPath {
	return &FileContentWithPath{
		Name:        name,
		Data:        data,
		Path:        path,
		PrefixDate:  time.Now().UTC(),
		RequestType: "",
	}
}

func (file FileContentWithPath) GetPrefixedFileName() string {

	if file.PrefixFromName {
		return file.Name
	}
	return file.PrefixDate.Format("2006-01-02_15-04-05_") + file.Name
}
