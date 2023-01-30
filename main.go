/**
 * @Author:      thepoy
 * @Email:       thepoy@163.com
 * @File Name:   main.go
 * @Created At:  2023-01-12 10:26:09
 * @Modified At: 2023-01-30 19:06:08
 * @Modified By: thepoy
 */

package main

import (
	"bytes"
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
	"github.com/valyala/fasthttp"
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

	env = os.Getenv("GP_ENV")
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
	ErrMethod       = errors.New("错误的请求方式")
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

func disableRedirect(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

func acquireClient() *http.Client {
	log.Trace().Msg("Acquire a client")

	client := clientPool.Get()
	if client != nil {
		return client.(*http.Client)
	}

	return &http.Client{
		Transport:     &transport,
		CheckRedirect: disableRedirect,
	}
}

func releaseClient(client *http.Client) {
	client.CheckRedirect = nil
	client.Jar = nil
	client.Transport = &transport

	clientPool.Put(client)

	log.Trace().Msg("Release a client")
}

var requestPool sync.Pool

func newBody(body []byte) io.ReadCloser {
	if body == nil {
		return nil
	}

	bodyBuffer := bytes.NewBuffer(body)
	return io.NopCloser(bodyBuffer)
}

func convertHeader(src *fasthttp.RequestHeader) http.Header {
	if src == nil {
		return nil
	}

	header := make(http.Header)

	src.VisitAll(func(key, value []byte) {
		if string(key) != "Host" {
			header[string(key)] = append(header[string(key)], string(value))
		}
	})

	return header
}

func acquireRequest(u string, header *fasthttp.RequestHeader, body []byte) (*http.Request, error) {
	log.Trace().Msg("Acquire a request")

	parsedURL, err := url.Parse(u)
	if err != nil {
		return nil, err
	}

	req := requestPool.Get()
	if req != nil {
		r := req.(*http.Request)
		r.Method = string(header.Method())
		r.URL = parsedURL
		r.Header = convertHeader(header)
		r.Body = newBody(body)

		return r, nil
	}

	return &http.Request{
		Method:     string(header.Method()),
		URL:        parsedURL,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     convertHeader(header),
		Body:       newBody(body),
		Host:       parsedURL.Host,
	}, nil
}

func releaseRequest(req *http.Request) {
	req.Method = ""
	req.URL = nil
	req.Header = make(http.Header)
	req.Host = ""
	req.Body = nil

	requestPool.Put(req)

	log.Trace().Msg("Release a request")
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
	switch c.Method() {
	case fiber.MethodGet:
		log.Info().Str("url", u).Msg("Downloading")
	case fiber.MethodPost:
		log.Info().Str("url", u).Msg("Pushing")
	default:
		log.Error().Msg("Invalid method")

		return ErrMethod
	}

	c.Request().Header.Del("Host")

	client := acquireClient()
	defer releaseClient(client)

	req, err := acquireRequest(u, &c.Request().Header, c.Request().Body())
	if err != nil {
		return err
	}
	defer releaseRequest(req)

	if env == "dev" {
		fields := make(map[string]interface{})
		for k, v := range req.Header {
			fields[k] = v
		}
		log.Debug().Str("method", req.Method).Dict("headers", zerolog.Dict().Fields(fields)).Msg("Request info")
	}

	log.Trace().Msg("Send a request")

	// TODO: 响应池？
	// TODO: 客户端中断请求后这里的请求也需要中断
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

	if env == "dev" {
		fields := make(map[string]interface{})
		for k, v := range resp.Header {
			fields[k] = v
		}
		log.Debug().
			Int("status-code", resp.StatusCode).
			Dict("headers", zerolog.Dict().Fields(fields)).
			Msg("Got a response")
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

		log.Info().Str("src", u).Str("size", fmt.Sprintf("%.2fM", fileSize)).Msg("File info")

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
		c.Status(fiber.StatusFound)
		response.Header.Set("Location", "/"+resp.Header.Get("Location"))

		return nil
	default:
		c.Status(resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		log.Error().
			Bytes("body", body).
			Interface("request-headers", resp.Request.Header).
			Msg("响应错误")
	}

	return nil
}

func handler(c *fiber.Ctx) (err error) {
	u := c.Params("*")

	log.Debug().Str("url", u).Msg("URL in request")

	if u[:4] != "http" {
		u = "https://" + u
	}

	u, err = url.QueryUnescape(u)
	if err != nil {
		return
	}

	log.Debug().Str("url", u).Msg("Got a request from client")

	if !checkURL(u) {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(newErrorResponse(ErrInvalidInput))
	}

	log.Trace().Msg("Url is valid")

	if ptn2.MatchString(u) {
		u = strings.Replace(u, "/blob/", "/raw/", 1)
	}

	// fiber 用路由匹配规则会过滤掉查询参数，需要手动添加
	queryString := string(c.Request().URI().QueryString())
	if queryString != "" {
		u = u + "?" + queryString
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
		level = zerolog.InfoLevel
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

	app.All("/*", handler)
	// app.Get("/test/+", test)

	app.Listen(":3000")
}
