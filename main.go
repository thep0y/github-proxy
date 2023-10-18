package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"

	"github-proxy/middleware/logger"
)

const (
	// 单个文件允许代理的最大体积 200 M，可根据实际需求修改
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

	log = logger.GetLogger()

	env = logger.GetEnv()

	client = &http.Client{
		Timeout: TIMEOUT,
	}
)

type OverLimit struct {
	size float64
}

func (ol *OverLimit) Error() string {
	return fmt.Sprintf("文件体积超限: %.2fM > %dM", ol.size, MAX_SIZE/1024/1024)
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

var transport = http.Transport{
	Dial:                dialTimeout,
	MaxIdleConns:        100,
	MaxIdleConnsPerHost: 100,
}

func disableRedirect(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

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
		log.Error().Str("method", method).Str("url", u).Msg("Invalid method")

		return ErrMethod
	}

	return nil
}

func handleResponse(c *gin.Context, resp *http.Response) {
	defer resp.Body.Close()

	contentLength := resp.ContentLength
	contentType := resp.Header.Get("Content-Type")

	headers := make(map[string]string)
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
	}

	c.DataFromReader(resp.StatusCode, contentLength, contentType, resp.Body, headers)
}

func handleDownloadResponse(
	c *gin.Context,
	u string,
	resp *http.Response,
) error {
	contentLength := resp.ContentLength

	fileSize := float64(contentLength) / 1024 / 1024

	log.Info().Str("src", u).Str("size", fmt.Sprintf("%.2fM", fileSize)).Msg("File info")

	// 根据实际情况可以解除此限制
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

	if errors.Is(err, &OverLimit{}) {
		c.Status(http.StatusForbidden)
	} else {
		c.Status(http.StatusInternalServerError)
	}

	log.Error().
		Err(err).
		Msg("处理响应错误")

	return err
}

func newRequest(method, url string, header http.Header, body io.ReadCloser) (*http.Request, error) {
	req, error := http.NewRequest(method, url, body)
	if error != nil {
		return nil, error
	}

	req.Header = convertHeader(header)

	return req, nil
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
	if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodPost {
		return ErrMethod
	}

	c.Request.Header.Del("Host")

	req, err := newRequest(c.Request.Method, u, c.Request.Header, c.Request.Body)
	if err != nil {
		return err
	}

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
			handleResponse(c, resp)

			return nil
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

	log.Debug().Str("url", u).Msg("Got a request from remote")

	if !checkURL(u) {
		c.JSON(http.StatusBadRequest, newErrorResponse(ErrInvalidInput))
		return
	}

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

func index(c *gin.Context) {
	c.HTML(http.StatusOK, "./static/index.html", nil)
}

func main() {
	r := gin.Default()

	// 传入包含 index.html 的静态文件路径
	r.Use(
		static.Serve("/", static.LocalFile("../caddy/static", false)),
	)

	r.Any("/*target", handler)

	r.Run(":3000")
}
