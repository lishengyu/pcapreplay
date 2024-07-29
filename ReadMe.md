go env -w GOOS=windows GOARCH=amd64
go build -o client.exe client.go
go build -o server.exe server.go

go env -w GOOS=linux GOARCH=amd64
go build -o client client.go
go build -o server server.go
