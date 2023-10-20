package logger

import (
	"io"
	"os"

	"github.com/rs/zerolog"
)

const (
	TimeFormat = "2006-01-02 15:04:05.999"
)

var (
	log zerolog.Logger
	env = os.Getenv("GP_ENV")
)

func init() {
	var (
		w     io.Writer
		level zerolog.Level
		err   error
	)

	if env == "dev" {
		w = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: TimeFormat,
		}
		level = zerolog.TraceLevel
	} else {
		w, err = os.OpenFile("gp.log", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
		if err != nil {
			panic(err)
		}
		level = zerolog.InfoLevel
	}
	log = zerolog.New(w).Level(level)

	zerolog.TimeFieldFormat = TimeFormat
	log = log.With().
		CallerWithSkipFrameCount(2).
		Timestamp().
		Logger()
}

func GetLogger() *zerolog.Logger {
	return &log
}

func GetEnv() string {
	return env
}
