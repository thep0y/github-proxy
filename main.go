package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"

	"github-proxy/middleware/logger"
)

const (
	// 免费用户单个文件允许代理的最大体积 200 M
	MAX_SIZE = 200 * 1024 * 1024

	TIMEOUT = 10 * time.Second
)

var (
	ptn1 = regexp.MustCompile(
		`^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:releases|archive)/.*$`,
	)
	ptn2 = regexp.MustCompile(
		`^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:blob|raw)/.*$`,
	)
	ptn3 = regexp.MustCompile(
		`^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:info|git-).*$`,
	)
	ptn4 = regexp.MustCompile(
		`^(?:https?://)?raw\.(?:githubusercontent|github)\.com/(?P<author>.+?)/(?P<repo>.+?)/.+?/.+$`,
	)
	ptn5 = regexp.MustCompile(
		`^(?:https?://)?gist\.(?:githubusercontent|github)\.com/(?P<author>.+?)/.+?/.+$`,
	)
	ptn6 = regexp.MustCompile(`^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)(\.git)/.+$`)

	regexps = [6]*regexp.Regexp{ptn1, ptn2, ptn3, ptn4, ptn5, ptn6}

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

	clientPool = &sync.Pool{
		New: func() any {
			client := new(http.Client)
			client.Transport = &transport

			return client
		},
	}
)

func disableRedirect(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

func acquireClient() *http.Client {
	log.Trace().Msg("Acquire a client")

	return clientPool.Get().(*http.Client)
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

func convertHeader(src http.Header) http.Header {
	if src == nil {
		return nil
	}

	header := make(http.Header)

	for key, value := range src {
		if key != "Host" {
			header[key] = value
		}
	}

	return header
}

func acquireRequest(
	method, u string,
	header http.Header,
	body io.ReadCloser,
) (*http.Request, error) {
	log.Trace().Msg("Acquire a request")

	parsedURL, err := url.Parse(u)
	if err != nil {
		return nil, err
	}

	req := requestPool.Get()
	if req != nil {
		r := req.(*http.Request)
		r.Method = method
		r.URL = parsedURL
		r.Header = convertHeader(header)
		r.Body = body

		return r, nil
	}

	return &http.Request{
		Method: method,
		URL:    parsedURL,
		Header: convertHeader(header),
		Body:   body,

		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
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

func handleMethod(u, method string) error {
	switch method {
	case http.MethodGet:
		log.Info().Str("url", u).Msg("Downloading")
	case http.MethodPost:
		log.Info().Str("url", u).Msg("Pushing")
	default:
		log.Error().Msg("Invalid method")

		return ErrMethod
	}

	return nil
}

func handleResponse(c *gin.Context, resp *http.Response) error {
	reader := resp.Body
	contentLength := resp.ContentLength
	contentType := resp.Header.Get("Content-Type")

	c.DataFromReader(resp.StatusCode, contentLength, contentType, reader, nil)

	return nil
}

func handleDownloadResponse(
	c *gin.Context,
	u string,
	resp *http.Response,
) error {
	contentLength := resp.ContentLength

	fileSize := float64(contentLength) / 1024 / 1024

	log.Info().Str("src", u).Str("size", fmt.Sprintf("%.2fM", fileSize)).Msg("File info")

	// TODO: 以后可以给捐赠用户开放此限制
	if contentLength > MAX_SIZE {
		c.Status(http.StatusForbidden)
		return &OverLimit{fileSize}
	}

	handleResponse(c, resp)

	return nil
}

func handleResponseError(c *gin.Context, err error) error {
	if e, ok := err.(*url.Error); ok {
		if e.Timeout() {
			c.Status(http.StatusGatewayTimeout)
			return ErrTimeout
		}
	}

	c.Status(http.StatusInternalServerError)
	return err
}

func handleInvalidResponse(c *gin.Context, resp *http.Response) error {
	c.Status(resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().
			Err(err).
			Interface("request-headers", resp.Request.Header).
			Msg("响应错误")
		return err
	}

	log.Error().
		Bytes("body", body).
		Interface("request-headers", resp.Request.Header).
		Msg("响应错误")

	return nil
}

func proxy(c *gin.Context, u string, followRedirect bool) error {
	err := handleMethod(u, c.Request.Method)
	if err != nil {
		return err
	}

	c.Request.Header.Del("Host")

	req, err := acquireRequest(c.Request.Method, u, c.Request.Header, c.Request.Body)
	if err != nil {
		return err
	}
	defer releaseRequest(req)

	if env == "dev" {
		fields := make(map[string]interface{})
		for k, v := range req.Header {
			fields[k] = v
		}
		log.Debug().
			Str("method", req.Method).
			Dict("headers", zerolog.Dict().Fields(fields)).
			Msg("Request info")
	}

	client := acquireClient()

	if !followRedirect {
		client.CheckRedirect = disableRedirect
	}

	log.Trace().Msg("Sending request")

	resp, err := client.Do(req)
	if err != nil {
		return handleResponseError(c, err)
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

	switch resp.StatusCode {
	case http.StatusOK, http.StatusPartialContent:
		if env == "dev" || req.Header.Get("User-Agent")[:3] == "git" {
			return handleResponse(c, resp)
		}

		return handleDownloadResponse(c, u, resp)
	case http.StatusFound:
		location := resp.Header.Get("Location")
		if checkURL(location) {
			c.Status(http.StatusFound)
			c.Header("Location", "/"+resp.Header.Get("Location"))

			return nil
		}

		return proxy(c, location, true)
	case http.StatusNotModified:
		c.Status(resp.StatusCode)

		return nil
	default:
		return handleInvalidResponse(c, resp)
	}
}

func handler(c *gin.Context) {
	u := c.Param("target")

	log.Debug().Str("url", u).Msg("URL in request")

	// 防止有人访问不存在文件，如 <HOST>/.env，长度小于等于 4 时会 panic
	if len(u) <= 4 {
		c.Status(http.StatusNotFound)

		return
	}

	if u[:5] != "/http" {
		u = "https:/" + u
	} else {
		u = u[1:]
	}

	u, err := url.QueryUnescape(u)
	if err != nil {
		c.Status(http.StatusBadRequest)

		return
	}

	log.Debug().Str("url", u).Msg("Got a request from client")

	if !checkURL(u) {
		c.JSON(http.StatusBadRequest, newErrorResponse(ErrInvalidInput))

		return
	}

	log.Trace().Msg("Url is valid")

	if ptn2.MatchString(u) {
		u = strings.Replace(u, "/blob/", "/raw/", 1)
	}

	// http.用路由匹配规则会过滤掉查询参数，需要手动添加
	queryString := string(c.Request.URL.RawQuery)
	if queryString != "" {
		u = u + "?" + queryString
	}

	err = proxy(c, u, false)
	if err != nil {
		return
	}

	return
}

func init() {
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
	r := gin.Default()

	r.Any("/*target", handler)

	r.Run(":3000")
}
