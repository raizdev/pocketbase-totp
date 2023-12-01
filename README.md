# pocketbase-totp
A module that makes totp authentication possible in PocketBase

1. To init the dependencies
   ``run go mod init myapp && go mod tidy.``
   
3. To start the application
   ``run go run main.go serve``
   
5. To build a statically linked executable
   You can run ``CGO_ENABLED=0 go build`` and then start the created executable with ``./myapp serve``.
