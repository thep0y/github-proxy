/**
 * @Author:      thepoy
 * @Email:       thepoy@163.com
 * @File Name:   main.go
 * @Created At:  2023-01-12 10:26:09
 * @Modified At: 2023-01-20 17:47:29
 * @Modified By: thepoy
 */

package main

import (
	"errors"
	"fmt"
	"github-proxy/middleware/logger"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

const (
	// 免费用户单个文件允许代理的最大体积 200 M
	MAX_SIZE = 200 * 1024 * 1024
)

var (
	ptn1 = regexp.MustCompile(`^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:releases|archive)/.*$`)
	ptn2 = regexp.MustCompile(`^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:blob|raw)/.*$`)
	ptn3 = regexp.MustCompile(`^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:info|git-).*$`)
	ptn4 = regexp.MustCompile(`^(?:https?://)?raw\.(?:githubusercontent|github)\.com/(?P<author>.+?)/(?P<repo>.+?)/.+?/.+$`)
	ptn5 = regexp.MustCompile(`^(?:https?://)?gist\.(?:githubusercontent|github)\.com/(?P<author>.+?)/.+?/.+$`)

	regexps = [5]*regexp.Regexp{ptn1, ptn2, ptn3, ptn4, ptn5}

	log = zerolog.New(zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: logger.TimeFormat,
	}).
		Level(zerolog.TraceLevel)
)

type OverLimit struct {
	size float64
}

func (ol *OverLimit) Error() string {
	return fmt.Sprintf("文件体积超限: %.2fM > 200M", ol.size)
}

var (
	ErrInvalidInput = errors.New("链接无效")
	ErrTimeout      = errors.New("请求超时")
)

type ErrorResponse struct {
	Error string `json:"error"`
}

func newErrorResponse(err error) ErrorResponse {
	return ErrorResponse{err.Error()}
}

var clientPool sync.Pool

func acquireClient() *http.Client {
	client := clientPool.Get()
	if client != nil {
		return client.(*http.Client)
	}

	return &http.Client{
		Timeout: 10 * time.Second,
	}
}

func releaseClient(client *http.Client) {
	client.CheckRedirect = nil
	client.Jar = nil
	client.Timeout = 10 * time.Second
	client.Transport = nil

	clientPool.Put(client)
}

var requestPool sync.Pool

func acquireRequest(u string) (*http.Request, error) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return nil, err
	}

	req := requestPool.Get()
	if req != nil {
		r := req.(*http.Request)
		r.URL = parsedURL
		return r, nil
	}

	return &http.Request{
		Method:     http.MethodGet,
		URL:        parsedURL,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       nil,
		Host:       parsedURL.Host,
	}, nil
}

func releaseRequest(req *http.Request) {
	req.Method = ""
	req.URL = nil
	req.Header = make(http.Header)
	req.Host = ""

	requestPool.Put(req)
}

func checkURL(u string) bool {
	for _, e := range regexps {
		if e.MatchString(u) {
			return true
		}
	}

	return false
}

func proxy(c *fiber.Ctx, u string) error {
	log.Info().Str("url", u).Msg("download")

	c.Request().Header.Del("Host")

	client := acquireClient()
	defer releaseClient(client)

	req, err := acquireRequest(u)
	if err != nil {
		return err
	}
	defer releaseRequest(req)

	c.Request().Header.VisitAll(func(key, value []byte) {
		k := string(key)
		if k != "Host" {
			req.Header.Set(k, string(value))
		}
	})

	resp, err := client.Do(req)
	if err != nil {
		if e, ok := err.(*url.Error); ok {
			if e.Timeout() {
				c.Status(fiber.StatusGatewayTimeout)
				return ErrTimeout
			}
		}

		c.Status(fiber.StatusInternalServerError)
		return err
	}

	response := c.Response()
	switch resp.StatusCode {
	case fiber.StatusOK:
		var (
			contentLength int64
		)
		contentLength, err = strconv.ParseInt(resp.Header.Get("Content-Length"), 0, 64)
		if err != nil {
			return err
		}

		fileSize := float64(contentLength) / 1024 / 1024

		log.Info().Str("src", u).Str("size", fmt.Sprintf("%.2fM", fileSize)).Msg("file size")

		// TODO: 以后可以给捐赠用户开放此限制
		if contentLength > MAX_SIZE {
			c.Status(fiber.StatusForbidden)
			return &OverLimit{fileSize}
		}

		for key, values := range resp.Header {
			for _, value := range values {
				response.Header.Set(key, value)
			}
		}

		response.SetBodyStream(resp.Body, int(contentLength))

		return nil
	case fiber.StatusFound:
		return proxy(c, resp.Header.Get("Location"))
	default:
		c.Status(resp.StatusCode)
		log.Error().
			Int("status-code", resp.StatusCode).
			Msg("响应错误")
	}

	return nil
}

func handler(c *fiber.Ctx) error {
	url := c.Params("+")
	if url[:4] != "http" {
		url = "https://" + url
	}

	if !checkURL(url) {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(newErrorResponse(ErrInvalidInput))
	}

	if ptn2.MatchString(url) {
		url = strings.Replace(url, "/blob/", "/raw/", 1)
	}

	err := proxy(c, url)
	if err != nil {
		return c.JSON(newErrorResponse(err))
	}

	return nil
}

// func test(c *fiber.Ctx) error {
// 	url := c.Params("+")

// 	err := proxy(c, url)
// 	if err != nil {
// 		return c.JSON(newErrorResponse(err))
// 	}

// 	return nil
// }

func init() {
	rand.Seed(time.Now().UnixNano())

	zerolog.TimeFieldFormat = logger.TimeFormat
	log = log.With().CallerWithSkipFrameCount(2).Timestamp().Logger()
}

func main() {
	app := fiber.New()
	app.Use(logger.New(logger.Config{Logger: &log}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World 👋!")
	})

	app.Get("/download/+", handler)
	// app.Get("/test/+", test)

	app.Listen(":3000")
}
