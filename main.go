/**
 * @Author:      thepoy
 * @Email:       thepoy@163.com
 * @File Name:   main.go
 * @Created At:  2023-01-12 10:26:09
 * @Modified At: 2023-01-26 08:46:09
 * @Modified By: thepoy
 */

package main

import (
	"errors"
	"fmt"
	"github-proxy/middleware/logger"
	"io"
	"math/rand"
	"net"
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

	TIMEOUT = 10 * time.Second
)

var (
	ptn1 = regexp.MustCompile(`^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:releases|archive)/.*$`)
	ptn2 = regexp.MustCompile(`^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:blob|raw)/.*$`)
	ptn3 = regexp.MustCompile(`^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:info|git-).*$`)
	ptn4 = regexp.MustCompile(`^(?:https?://)?raw\.(?:githubusercontent|github)\.com/(?P<author>.+?)/(?P<repo>.+?)/.+?/.+$`)
	ptn5 = regexp.MustCompile(`^(?:https?://)?gist\.(?:githubusercontent|github)\.com/(?P<author>.+?)/.+?/.+$`)

	regexps = [5]*regexp.Regexp{ptn1, ptn2, ptn3, ptn4, ptn5}

	log zerolog.Logger
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

func dialTimeout(network, addr string) (net.Conn, error) {
	return net.DialTimeout(network, addr, TIMEOUT)
}

var (
	transport = http.Transport{
		Dial: dialTimeout,
	}

	clientPool sync.Pool
)

func acquireClient() *http.Client {
	log.Trace().Msg("acquire a client")

	client := clientPool.Get()
	if client != nil {
		return client.(*http.Client)
	}

	return &http.Client{
		Transport: &transport,
	}
}

func releaseClient(client *http.Client) {
	client.CheckRedirect = nil
	client.Jar = nil
	client.Transport = &transport

	clientPool.Put(client)

	log.Trace().Msg("release a client")
}

var requestPool sync.Pool

func acquireRequest(u string) (*http.Request, error) {
	log.Trace().Msg("acquire a request")

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

	log.Trace().Msg("release a request")
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

	log.Trace().Msg("send a request")

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

	log.Trace().Msg("got a response")

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

func handler(c *fiber.Ctx) (err error) {
	u := c.Params("+")
	if u[:4] != "http" {
		u = "https://" + u
	}

	u, err = url.QueryUnescape(u)
	if err != nil {
		return
	}

	if !checkURL(u) {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(newErrorResponse(ErrInvalidInput))
	}

	if ptn2.MatchString(u) {
		u = strings.Replace(u, "/blob/", "/raw/", 1)
	}

	err = proxy(c, u)
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

	var (
		w     io.Writer
		level zerolog.Level
		err   error
	)
	env := os.Getenv("GP_ENV")
	if env == "dev" {
		w = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: logger.TimeFormat,
		}
		level = zerolog.TraceLevel
	} else {
		w, err = os.OpenFile("proxy.log", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
		if err != nil {
			panic(err)
		}
		level = zerolog.DebugLevel
	}
	log = zerolog.New(w).Level(level)

	zerolog.TimeFieldFormat = logger.TimeFormat
	log = log.With().
		CallerWithSkipFrameCount(2).
		Timestamp().
		Logger()
}

func main() {
	app := fiber.New()
	app.Use(logger.New(logger.Config{Logger: &log}))
	app.Static("/", "./static", fiber.Static{
		Compress:      true,
		ByteRange:     true,
		Browse:        true,
		CacheDuration: 10 * time.Hour * 24, // 缓存 10 天
		MaxAge:        60 * 60 * 24 * 10,   // 缓存 10 天
	})

	// app.Get("/", func(c *fiber.Ctx) error {
	// 	return c.SendString("Hello, World 👋!")
	// })

	app.Get("/+", handler)
	// app.Get("/test/+", test)

	app.Listen(":3000")
}
