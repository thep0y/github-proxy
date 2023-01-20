/**
 * @Author:      thepoy
 * @Email:       thepoy@163.com
 * @File Name:   logger.go
 * @Created At:  2023-01-20 11:22:51
 * @Modified At: 2023-01-20 17:55:44
 * @Modified By: thepoy
 */

package logger

import (
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	TimeFormat = "2006-01-02 15:04:05.999"
)

// Config defines the config for logger middleware.
type Config struct {
	// Next defines a function to skip this middleware.
	Next func(ctx *fiber.Ctx) bool

	// Logger is a *zerolog.Logger that writes the logs.
	//
	// Default: log.Logger.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	Logger *zerolog.Logger
}

// New is a zerolog middleware that allows you to pass a Config.
//
//	app := fiber.New()
//
//	// Without config
//	app.Use(New())
//
//	// With config
//	app.Use(New(Config{Logger: &zerolog.New(os.Stdout)}))
func New(config ...Config) fiber.Handler {
	var conf Config

	if len(config) > 0 {
		conf = config[0]
	}

	var sublog zerolog.Logger
	if conf.Logger == nil {
		sublog = log.Logger.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	} else {
		sublog = *conf.Logger
	}

	return func(c *fiber.Ctx) error {
		// Don't execute the middleware if Next returns true
		if conf.Next != nil && conf.Next(c) {
			return c.Next()
		}

		start := time.Now()

		// Handle request, store err for logging
		chainErr := c.Next()

		code := c.Response().StatusCode()

		dumplogger := sublog.With().
			Int("status-code", code).
			Str("method", c.Method()).
			Str("path", c.Path()).
			Str("client-ip", c.IP()).
			Str("latency", time.Since(start).String()).
			Str("user-agent", c.Get(fiber.HeaderUserAgent)).
			Logger()

		if chainErr != nil {
			if e, ok := chainErr.(*fiber.Error); ok {
				dumplogger.Err(chainErr).Int("status-code", e.Code).Send()
			} else {
				dumplogger.Err(chainErr).Int("status-code", fiber.StatusInternalServerError).Msg("unkown error")
			}

			return chainErr
		}

		switch {
		case code >= fiber.StatusInternalServerError:
			dumplogger.Error().Msg("server error")
		case code >= fiber.StatusBadRequest:
			dumplogger.Error().Msg("client error")
		case code >= fiber.StatusMultipleChoices:
			dumplogger.Warn().Msg("redirect")
		case code >= fiber.StatusOK:
			dumplogger.Info().Msg("success")
		case code == fiber.StatusSwitchingProtocols:
			dumplogger.Info().Msg("switching protocol")
		case code == fiber.StatusContinue:
			dumplogger.Info().Msg("continue")
		default:
			dumplogger.Warn().Msg("unknown status")
		}

		return nil
	}
}
