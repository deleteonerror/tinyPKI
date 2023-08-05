package logger

import (
	"fmt"
	"log"
	"path/filepath"
	"runtime"
)

const (
	DEBUG = iota
	INFO
	WARNING
	ERROR
)

var LogSeverity = INFO

func Debug(format string, a ...interface{}) {
	if LogSeverity <= DEBUG {
		logMessage("DEBUG", format, a...)
	}
}

func Info(format string, a ...interface{}) {
	if LogSeverity <= INFO {
		logMessage("INFO", format, a...)
	}
}

func Warning(format string, a ...interface{}) {
	if LogSeverity <= WARNING {
		logMessage("WARNING", format, a...)
	}
}

func Error(format string, a ...interface{}) {
	if LogSeverity <= ERROR {
		_, file, line, ok := runtime.Caller(1)

		if ok {
			filename := filepath.Base(file)
			f := fmt.Sprintf("%s:%d", filename, line)
			logError("ERROR", f, format, a...)
		} else {
			logMessage("ERROR", format, a...)
		}
	}
}

func logError(severity string, file string, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	log.Printf("%s [%s] %s", file, severity, msg)
}

func logMessage(severity string, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	log.Printf("[%s] %s", severity, msg)
}
