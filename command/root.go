package command

import (
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/spf13/cobra"

	"github-proxy/middleware/logger"
	"github-proxy/server"
)

var (
	log = logger.GetLogger()

	host     string
	port     uint
	max_size uint
)

var (
	ErrStaticDirNotFound    = errors.New("静态文件目录不存在")
	ErrIndexHTMLNotFound    = errors.New("index.html 不存在")
	ErrMissingStaticDir     = errors.New("缺少静态文件目录")
	ErrOnlyOnePositionalArg = errors.New("只允许传入一个位置参数")
)

func isPathExists(path string) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func checkStatic(staticDir string) error {
	if !isPathExists(staticDir) {
		return ErrStaticDirNotFound
	}

	index := path.Join(staticDir, "index.html")
	if !isPathExists(index) {
		return ErrIndexHTMLNotFound
	}

	return nil
}

var rootCmd = &cobra.Command{
	Use:   "gp [STATIC_DIR]",
	Short: "使用指定的静态文件启动 github proxy 代理服务",
	Args: func(_ *cobra.Command, args []string) error {
		argsLen := len(args)
		if argsLen == 0 {
			return ErrMissingStaticDir
		}

		if argsLen > 1 {
			return fmt.Errorf("%w，你传入了 %d 个", ErrOnlyOnePositionalArg, argsLen)
		}

		return checkStatic(args[0])
	},
	Run: func(_ *cobra.Command, args []string) {
		log.Info().Str("static-dir", args[0]).Str("host", host).Uint("port", port).Msg("命令行参数")

		server.Run(args[0], host, port, max_size)
	},
}

func init() {
	rootCmd.Flags().StringVar(&host, "host", "localhost", "本服务使用的主机")
	rootCmd.Flags().UintVar(&port, "port", 3000, "本服务使用的端口")
	rootCmd.Flags().UintVar(&max_size, "max-size", 500, "允许的最大体积，为 0 时无限制。单位为为 MB")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Err(err).Send()
	}
}
