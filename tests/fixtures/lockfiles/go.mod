module example.com/demo

go 1.21

require github.com/gin-gonic/gin v1.6.0

require (
	golang.org/x/net v0.7.0 // indirect
	github.com/stretchr/testify v1.8.4
)

replace example.com/other => ../other
