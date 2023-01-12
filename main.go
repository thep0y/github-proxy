/**
 * @Author:      thepoy
 * @Email:       thepoy@163.com
 * @File Name:   main.go
 * @Created At:  2023-01-12 10:26:09
 * @Modified At: 2023-01-12 10:32:12
 * @Modified By: thepoy
 */

package main

import "github.com/gofiber/fiber/v2"

func main() {
	app := fiber.New()

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World 👋!")
	})

	app.Listen(":3000")
}
