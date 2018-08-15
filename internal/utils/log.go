package utils

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
)

// LogLevel of quic-go
type LogLevel uint8

const logEnv = "QUIC_GO_LOG_LEVEL"

const (
	// LogLevelNothing disables
	LogLevelNothing LogLevel = iota
	// LogLevelError enables err logs
	LogLevelError
	// LogLevelInfo enables info logs (e.g. packets)
	LogLevelInfo
	// LogLevelDebug enables debug logs (e.g. packet contents)
	LogLevelDebug
)

var (
	logLevel   = LogLevelNothing
	timeFormat = ""
)

// SetLogLevel sets the log level
func SetLogLevel(level LogLevel) {
	logLevel = level
}

// SetLogTimeFormat sets the format of the timestamp
// an empty string disables the logging of timestamps
func SetLogTimeFormat(format string) {
	log.SetFlags(0) // disable timestamp logging done by the log package
	timeFormat = format
}

// Debugf logs something
func Debugf(format string, args ...interface{}) {
	if logLevel == LogLevelDebug {
		logMessage(format, args...)
	}
}

// Infof logs something
func Infof(format string, args ...interface{}) {
	if logLevel >= LogLevelInfo {
		logMessage(format, args...)
	}
}

var perspective string

func RecordAsClient() {
	perspective = "client"
	if _, err := os.Stat("./result_tmp.json"); os.IsNotExist(err) {
		f, err := os.Create("result_tmp.json")
		if err != nil {
			panic(err)
		}
		f.Close()
	}

}
func RecordAsServer() {
	perspective = "server"
	if _, err := os.Stat("./result_tmp.json"); os.IsNotExist(err) {
		f, err := os.Create("result_tmp.json")
		if err != nil {
			panic(err)
		}
		f.Close()
	}
}

//RecordF logs something
func RecordF(key string, value int64, timeoffset int64) {
	if perspective == "client" {
		return //For now, we don't record as client
	}
	var err error
	var f *os.File
	f, err = os.OpenFile("result_tmp.json", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	_, err = f.WriteString("{\"key\":\"" + key + "_" + perspective + "\", \"value\":" + strconv.FormatInt(value, 10) + ", \"offset\":" + strconv.FormatInt(timeoffset, 10) + "}\n")

	if err != nil {
		panic(err)
	}
}

//RecordF logs something
func RecordF2(key string, value int64, timeoffset int64) {
	var err error
	var f *os.File
	f, err = os.OpenFile("result_tmp.json", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	_, err = f.WriteString("{\"key\":\"" + key + "_" + perspective + "\", \"value\":" + strconv.FormatInt(value, 10) + ", \"offset\":" + strconv.FormatInt(timeoffset, 10) + "}\n")

	if err != nil {
		panic(err)
	}
}

// Errorf logs something
func Errorf(format string, args ...interface{}) {
	if logLevel >= LogLevelError {
		logMessage(format, args...)
	}
}

func logMessage(format string, args ...interface{}) {
	if len(timeFormat) > 0 {
		log.Printf(time.Now().Format(timeFormat)+" "+format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// Debug returns true if the log level is LogLevelDebug
func Debug() bool {
	return logLevel == LogLevelDebug
}

func init() {
	readLoggingEnv()
}

func readLoggingEnv() {
	switch os.Getenv(logEnv) {
	case "":
		return
	case "DEBUG":
		logLevel = LogLevelDebug
	case "INFO":
		logLevel = LogLevelInfo
	case "ERROR":
		logLevel = LogLevelError
	default:
		fmt.Fprintln(os.Stderr, "invalid quic-go log level, see https://github.com/lucas-clemente/quic-go/wiki/Logging")
	}
}
