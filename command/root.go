package command

import (
	"errors"
	"os"
	"path"

	"github.com/spf13/cobra"

	"github-proxy/middleware/logger"
	"github-proxy/server"
)

var (
	log = logger.GetLogger()

	host string
	port uint
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
		return errors.New("静态文件目录不存在")
	}

	index := path.Join(staticDir, "index.html")
	if !isPathExists(index) {
		return errors.New("index.html 不存在")
	}

	return nil
}

var rootCmd = &cobra.Command{
	Use:   "gp [STATIC_DIR]",
	Short: "使用指定的静态文件启动 github proxy 代理服务",
	Args: func(_ *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("缺少静态文件目录")
		}

		return checkStatic(args[0])
	},
	Run: func(_ *cobra.Command, args []string) {
		log.Info().Str("static-dir", args[0]).Str("host", host).Uint("port", port).Msg("命令行参数")

		server.Run(args[0], host, port)
	},
}

func init() {
	rootCmd.Flags().StringVar(&host, "host", "localhost", "本服务使用的主机")
	rootCmd.Flags().UintVar(&port, "port", 3000, "本服务使用的端口")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Err(err).Send()
	}
}
