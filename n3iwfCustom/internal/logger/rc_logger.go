package logger

import (
	"encoding/json"
	"os"
	"time"
)

var (
	fileRC *os.File
)

type RCLogEntry struct {
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
	Data      any    `json:"data"`
}

func InitRCLogger(logPath string) error {
	var err error

	// File per RC
	fileRC, err = os.OpenFile(logPath+".rc.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	return nil
}

func LogRCMetrics(data any) {
	if fileRC == nil {
		return
	}

	entry := RCLogEntry{
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		Data:      data,
	}

	jsonBytes, err := json.Marshal(entry)
	if err != nil {
		// Se fallisce la serializzazione, non scrive niente
		return
	}

	// Scrittura su file KPM
	if err := fileRC.Truncate(0); err != nil {
		fileRC.Close()
		fileRC = nil
		return
	}
	fileRC.Write(jsonBytes)
	fileRC.Write([]byte("\n"))
}
