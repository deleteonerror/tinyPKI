package logger

import (
	"fmt"
	"log"
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
		logMessage("ERROR", format, a...)
	}
}

func logMessage(severity string, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	log.Printf("[%s] %s", severity, msg)
}
