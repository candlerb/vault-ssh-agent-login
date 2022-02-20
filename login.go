package main

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/pkg/browser"
)

// Login to Vault
func VaultLogin(c *Config) (bool, error) {
	switch c.AuthMethod {
	case "":
		return false, loginToken(c)
	case "oidc":
		return true, loginOIDC(c)
	default:
		return false, fmt.Errorf("Auth method unknown/not implemented")
	}
	return false, nil
}

// Login via token
// FIXME: is there an official way to access the token cache?
func loginToken(c *Config) error {
	if os.Getenv("VAULT_TOKEN") != "" {
		log.Printf("[INFO] Using token from VAULT_TOKEN")
	} else {
		tokenFile := c.TokenFile
		if len(tokenFile) > 2 && tokenFile[0:2] == "~/" {
			u, err := user.Current()
			if err != nil {
				return fmt.Errorf("Expanding user homedir: %v", err)
			}
			tokenFile = filepath.Join(u.HomeDir, tokenFile[2:])
		}
		token, err := ioutil.ReadFile(tokenFile)
		if err != nil {
			return fmt.Errorf("Reading token from file: %v", err)
		}
		c.vault.SetToken(string(token))
		log.Printf("[INFO] Using token from file")
	}
	return nil
}

// Login via OIDC: based on vault-plugin-auth-jwt/cli.go
func loginOIDC(c *Config) error {
	// Defaults
	mount := c.AuthPath
	if mount == "" {
		mount = c.AuthMethod
	}

	// Prepare request
	redirectURI := "http://localhost:8250/oidc/callback"
	nonceBytes := make([]byte, 16)
	n, err := rand.Reader.Read(nonceBytes)
	if err != nil {
		return fmt.Errorf("Creating nonce: %v", err)
	}
	if n != 16 {
		return fmt.Errorf("Got %d bytes, expected 16", n)
	}
	clientNonce := fmt.Sprintf("%x", nonceBytes)

	// Start listening on the response port
	type resultType struct {
		secret *api.Secret
		err    error
	}
	resultChan := make(chan resultType)
	http.HandleFunc("/oidc/callback", func(w http.ResponseWriter, req *http.Request) {
		var response string
		var result resultType
		defer func() {
			w.Write([]byte(response))
			resultChan <- result
		}()

		data := map[string][]string{
			"state":        {req.FormValue("state")},
			"code":         {req.FormValue("code")},
			"id_token":     {req.FormValue("id_token")},
			"client_nonce": {clientNonce},
		}
		if req.Method == http.MethodPost {
			url := c.vault.Address() + filepath.Join("/v1/auth", mount, "oidc/callback")
			resp, err := http.PostForm(url, data)
			if err != nil {
				response = fmt.Sprintf("Error in form post: %v", err)
				result.err = fmt.Errorf("Error in form post: %v", err)
				return
			}
			defer resp.Body.Close()
			delete(data, "id_token")
		}

		result.secret, result.err = c.vault.Logical().ReadWithData(fmt.Sprintf("auth/%s/oidc/callback", mount), data)
		if result.err != nil {
			response = fmt.Sprintf("Error in callback: %v", result.err)
			return
		}
		response = "Authentication complete: you may now close this browser window"
	})
	go func() {
		log.Fatal(http.ListenAndServe("127.0.0.1:8250", nil))
	}()

	data := map[string]interface{}{
		"redirect_uri": redirectURI,
		"client_nonce": clientNonce,
	}
	if c.AuthRole != "" {
		data["role"] = c.AuthRole
	}
	secret, err := c.vault.Logical().Write(fmt.Sprintf("auth/%s/oidc/auth_url", mount), data)
	if err != nil {
		return fmt.Errorf("Writing to auto/%s/oidc/auth_url: %v", mount, err)
	}
	authURL, ok := secret.Data["auth_url"].(string)
	if !ok || authURL == "" {
		return fmt.Errorf("Empty auth_url")
	}

	err = browser.OpenURL(authURL)
	if err != nil {
		return fmt.Errorf("Unable to open browser")
	}
	select {
	case result := <-resultChan:
		if result.err != nil {
			return err
		}
		if result.secret == nil || result.secret.Auth == nil {
			return fmt.Errorf("OIDC result missing auth data")
		}
		c.vault.SetToken(result.secret.Auth.ClientToken)
		log.Printf("[INFO] OIDC login successful: token accessor %s",
			result.secret.Auth.Accessor)

	case <-time.After(5 * time.Minute):
		return fmt.Errorf("Timeout waiting for OIDC response")
	}
	return nil
}
