# pocketbase-totp
A module that makes totp authentication possible in PocketBase

Example how to integrade it with VueJS
https://github.com/raizdev/pocketbase-totp-vue[https://github.com/raizdev/pocketbase-totp-vue]

1. To init the dependencies
   ``run go mod init myapp && go mod tidy.``
   
3. To start the application
   ``run go run main.go serve``
   
5. To build a statically linked executable
   You can run ``CGO_ENABLED=0 go build`` and then start the created executable with ``./myapp serve``.

# Examples
Generate TOTP function returns secret code which can be used for otp:totp qr code
otpauth://totp/fixedserver.dev:test@gmail.co?secret=ABCODI2928D&issuer=fixedserver.dev

````
   pb.send('/auth-generate-totp')
````

Remove TOTP secret code for user in pocketbase

````
   pb.send('/auth-remove-totp', { method: "POST", body: { totpCode: "214142" } })
````

Activate TOTP for user and generates secretcode and store user in pocketbase

````
   pb.send('/auth-activate-totp', { method: "POST", body: { secret: "ABCODI2928D", issuer: "fixedserver.dev", totpCode: "214142" } })
````

Login with TOTP
   totpCode attr must always be provided even when user don't have totp active.
   If user has totp active status: authenticator_enabled will be returned.
   Store email and user password and set totpcode which inserted by user.
   Token and record will be returned after succesfull login

````
   const auth = pb.send('/auth-login-totp', { method: "POST", body: { email: "test@gmail.com", password: "test1234", totpCode: "" } })

   # to store record in authstore
   pb.authStore.save(auth.token, auth.record)
````
