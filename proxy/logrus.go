package proxy

import (
	"bytes"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"strings"
)

const (
	red           = 31
	yellow        = 33
	blue          = 36
	gray          = 37
	pathSplitFlag = "trojan-go/"
)

func SetLogLevel(level string) {
	logrus.SetReportCaller(true)
	logrus.SetFormatter(&LogFormatter{})
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.SetLevel(lvl)
}

func SetOutput(w io.Writer) {
	logrus.SetOutput(w)
}

type LogFormatter struct{}

// Format 实现Formatter(entry *logrus.Entry) ([]byte, error)接口
func (t *LogFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	//根据不同的level去展示颜色
	var levelColor int
	switch entry.Level {
	case logrus.DebugLevel, logrus.TraceLevel:
		levelColor = gray
	case logrus.InfoLevel:
		levelColor = blue
	case logrus.WarnLevel:
		levelColor = yellow
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		levelColor = red
	default:
		return nil, fmt.Errorf("unknown log level: %v", entry.Level)
	}
	var b *bytes.Buffer
	if entry.Buffer != nil {
		b = entry.Buffer
	} else {
		b = &bytes.Buffer{}
	}
	//自定义日期格式
	timestamp := entry.Time.Format("2006-01-02 15:04:05")
	if entry.HasCaller() {
		//自定义文件路径
		funcVal := entry.Caller.Function
		_, path, found := strings.Cut(entry.Caller.File, pathSplitFlag)
		if !found {
			path = entry.Caller.File
		}
		fileVal := fmt.Sprintf("%s:%d", path, entry.Caller.Line)
		//自定义输出格式
		fmt.Fprintf(b, "[%s] \x1b[%dm[%s]\x1b[0m %s %s; %s\n", timestamp, levelColor, entry.Level, fileVal, funcVal, entry.Message)
	} else {
		fmt.Fprintf(b, "[%s] \x1b[%dm[%s]\x1b[0m  %s\n", timestamp, levelColor, entry.Level, entry.Message)
	}
	return b.Bytes(), nil
}
