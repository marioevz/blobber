package logger

import (
	"github.com/sirupsen/logrus"
)

// Logger interface defines the logging methods used throughout the application
type Logger interface {
	Debug(args ...interface{})
	Debugf(format string, args ...interface{})
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Warn(args ...interface{})
	Warnf(format string, args ...interface{})
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
	Fatal(args ...interface{})
	Fatalf(format string, args ...interface{})
	WithField(key string, value interface{}) Logger
	WithFields(fields map[string]interface{}) Logger
}

// LogrusLogger wraps logrus.Logger to implement our Logger interface
type LogrusLogger struct {
	*logrus.Entry
}

// New creates a new logger instance
func New() Logger {
	log := logrus.New()
	log.SetLevel(logrus.InfoLevel)
	return &LogrusLogger{Entry: logrus.NewEntry(log)}
}

// NewWithLevel creates a new logger instance with specified level
func NewWithLevel(level string) Logger {
	log := logrus.New()

	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	log.SetLevel(logLevel)

	return &LogrusLogger{Entry: logrus.NewEntry(log)}
}

// WithField returns a new logger with the added field
func (l *LogrusLogger) WithField(key string, value interface{}) Logger {
	return &LogrusLogger{Entry: l.Entry.WithField(key, value)}
}

// WithFields returns a new logger with the added fields
func (l *LogrusLogger) WithFields(fields map[string]interface{}) Logger {
	logrusFields := logrus.Fields{}
	for k, v := range fields {
		logrusFields[k] = v
	}
	return &LogrusLogger{Entry: l.Entry.WithFields(logrusFields)}
}
