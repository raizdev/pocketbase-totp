package main

import (
    "log"
    "net/http"
    "os"

    "github.com/joho/godotenv"
    "github.com/labstack/echo/v5"
    "github.com/pocketbase/pocketbase"
    "github.com/pocketbase/pocketbase/apis"
    "github.com/pocketbase/pocketbase/models"
    "github.com/pocketbase/pocketbase/core"
    "github.com/pquerna/otp/totp"
)

func goDotEnvVariable(key string) string {

    // load .env file
    err := godotenv.Load(".env")
  
    if err != nil {
      log.Fatalf("Error loading .env file")
    }
  
    return os.Getenv(key)
  }

func main() {

    app := pocketbase.New()

    // serves static files from the provided public dir (if exists)
    app.OnBeforeServe().Add(func(e *core.ServeEvent) error {

        issuer := goDotEnvVariable("issuer")
        secretField := goDotEnvVariable("secretField")
        
        e.Router.POST("/auth-login", func(c echo.Context) error {
    
            data := &struct {
                Email           string `form:"email" json:"email"`
                Password        string `form:"password" json:"password"`
                TwoFactorCode   string `form:"twoFactorCode" json:"twoFactorCode"`
            }{}

            if err := c.Bind(data); err != nil {
                return apis.NewBadRequestError("Failed to read request data", err)
            }

            record, err := app.Dao().FindFirstRecordByData("users", "email", data.Email)
            if err != nil || !record.ValidatePassword(data.Password) {
                return apis.NewBadRequestError("Invalid credentials", err)
            }

            if record.Get(secretField) != nil && data.TwoFactorCode == "" {
                return c.JSON(http.StatusOK, map[string]bool{"tfa_required": true})
            }

            if data.TwoFactorCode != "" {
                valid := totp.Validate(data.TwoFactorCode, record.Get(secretField).(string))
                if !valid {
                    return apis.NewBadRequestError("Google authenticator code not correct", nil)
                }
            }

            return apis.RecordAuthResponse(app, c, record, nil)
        }, apis.ActivityLogger(app))

        e.Router.POST("/auth-remove-totp", func(c echo.Context) error {

            data := &struct {
                TwoFactorCode string `form:"twoFactorCode" json:"twoFactorCode"`
            }{}

            if err := c.Bind(data); err != nil {
                return apis.NewBadRequestError("Failed to read request data", err)
            }

            authRecord, _ := c.Get(apis.ContextAuthRecordKey).(*models.Record)
            if authRecord == nil {
                return apis.NewForbiddenError("Only auth records can access this endpoint", nil)
            }

            valid := totp.Validate(data.TwoFactorCode, authRecord.Get(secretField).(string))
            if !valid {
                return apis.NewForbiddenError("Google authenticator code not correct", nil)
            }

            authRecord.Set(secretField, nil)
	        app.Dao().Save(authRecord)
    
            return c.JSON(http.StatusOK, map[string]string{"message": "Google Authenticator is now deactivated", "status": "success"})
        }, /* optional middlewares */)

        e.Router.POST("/auth-activate-totp", func(c echo.Context) error {

            data := &struct {
                Secret          string `form:"secret" json:"secret"`
                Issuer          string `form:"issuer" json:"issuer"`
                TwoFactorCode   string `form:"twoFactorCode" json:"twoFactorCode"`
            }{}

            // read the request data
            if err := c.Bind(data); err != nil {
                return apis.NewBadRequestError("Failed to read request data", err)
            }

            if data.Issuer != issuer {
                return apis.NewForbiddenError("Unkown authentication issuer", nil)
            }

            authRecord, _ := c.Get(apis.ContextAuthRecordKey).(*models.Record)
            if authRecord == nil {
                return apis.NewForbiddenError("Only auth records can access this endpoint", nil)
            }

            valid := totp.Validate(data.TwoFactorCode, data.Secret)
            if !valid {
                return apis.NewForbiddenError("Google authenticator code not correct", nil)
            }

            authRecord.Set(secretField, data.Secret)
	        app.Dao().Save(authRecord)
    
            return c.JSON(http.StatusOK, map[string]string{"message": "Google Authenticator is now activated", "status": "success"})
        }, /* optional middlewares */)
    
        e.Router.GET("/auth-generate-totp", func(c echo.Context) error {
            
            authRecord, _ := c.Get(apis.ContextAuthRecordKey).(*models.Record)
            if authRecord == nil {
                return apis.NewForbiddenError("Only auth records can access this endpoint", nil)
            }

            if authRecord.Get(secretField) != "" {
                return apis.NewForbiddenError("Authenticator already exists for this user", nil)
            }

            key, err := totp.Generate(totp.GenerateOpts{
                Issuer: issuer,
                AccountName: authRecord.Get("email").(string),
            })

            if err != nil {
                return apis.NewForbiddenError(err.Error(), nil)
            }

            return c.JSON(http.StatusOK, map[string]string{"secret": key.Secret(), "issuer": issuer, "status": "success"})
        }, /* optional middlewares */)
    
        return nil
    })

    if err := app.Start(); err != nil {
        log.Fatal(err)
    }
}
