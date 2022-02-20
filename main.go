package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"hash/crc32"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

/*
This binary will:
- connect to your ssh-agent and to Hashicorp Vault
- generate a new SSH key
- get it signed by Vault
- insert the key+cert into ssh-agent
- run an ssh command, if extra arguments given

If there is an existing key with the same comment in the agent, then no
new key or cert are generated unless you supply "-force"

TODO:
- selectable key type?
- config file?
*/

type Config struct {
	Force               bool
	Quiet               bool
	KeyComment          string
	KeyConfirmBeforeUse bool
	MountPoint          string
	Role                string
	ValidPrincipals     string
	Extensions          string
	TTL                 string
	WritePubkey         string
	WriteCert           string
	TokenFile           string
	AuthMethod          string
	AuthPath            string
	AuthRole            string

	vault *api.Client
	agent agent.ExtendedAgent
}

func main() {
	var c Config
	if err := ParseArgs(&c, os.Args); err != nil {
		log.Printf("[ERROR] %s", err)
		os.Exit(1)
	}
	if err := Prepare(&c); err != nil {
		log.Printf("[ERROR] %s", err)
		os.Exit(1)
	}
	if err := Run(&c); err != nil {
		log.Printf("[ERROR] %s", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func ParseArgs(c *Config, args []string) error {
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.BoolVar(&c.Force, "force", false, "Force generation of new key/cert")
	flags.BoolVar(&c.Quiet, "quiet", false, "Do not warn if no need to generate new key/cert")
	flags.StringVar(&c.KeyComment, "key-comment", "", "Override comment for key+cert in ssh-agent keyring")
	flags.BoolVar(&c.KeyConfirmBeforeUse, "key-confirm-before-use", false, "Tell agent to confirm before each use of key")
	flags.StringVar(&c.MountPoint, "mount-point", "ssh", "Mount path to the SSH secrets engine")
	flags.StringVar(&c.Role, "role", "", "SSH CA signing role (required)")
	flags.StringVar(&c.ValidPrincipals, "valid-principals", "", "List of certificate principals")
	flags.StringVar(&c.Extensions, "extensions", "", "List of certificate extensions")
	flags.StringVar(&c.TTL, "ttl", "", "Requested certificate TTL, e.g. '5m'")
	flags.StringVar(&c.WritePubkey, "write-pubkey", "", "Write public key to given filename")
	flags.StringVar(&c.WriteCert, "write-cert", "", "Write certificate to given filename")
	flags.StringVar(&c.TokenFile, "token-file", "~/.vault-token", "Path to existing token")
	flags.StringVar(&c.AuthMethod, "auth-method", "", "Auth type to use to fetch token")
	flags.StringVar(&c.AuthPath, "auth-path", "", "Path to auth method")
	flags.StringVar(&c.AuthRole, "auth-role", "default", "Role for auth method")

	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if len(flags.Args()) > 0 {
		return fmt.Errorf("Spurious arguments at end of line")
	}
	return nil
}

// Configure Vault and Agent API connections, and set default KeyComment
func Prepare(c *Config) error {
	if c.Role == "" {
		return fmt.Errorf("-role must be specified")
	}

	// Configure Vault client; DefaultConfig calls ReadEnvironment
	vaultConfig := api.DefaultConfig()
	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return err
	}
	c.vault = client

	// Open agent connection
	agent_path := os.Getenv("SSH_AUTH_SOCK")
	if agent_path == "" {
		return fmt.Errorf("SSH_AUTH_SOCK not set.  This program requires access to an ssh agent")
	}
	conn, err := net.Dial("unix", agent_path)
	if err != nil {
		return fmt.Errorf("Connecting to ssh-agent: %v", err)
	}
	c.agent = agent.NewClient(conn)
	if c.agent == nil {
		return fmt.Errorf("Nil ssh-agent")
	}

	// Generate a key comment if one hasn't been set explicitly, so we can
	// tell if we already have an existing key+cert generated with the same parameters
	if c.KeyComment == "" {
		h1 := crc32.ChecksumIEEE([]byte(vaultConfig.Address))
		c.KeyComment = fmt.Sprintf("vault-%08x-%s", h1, c.Role)
	}
	return nil
}

func Run(c *Config) error {
	// Always list keys in agent: this checks agent connectivity
	agentKeys, err := c.agent.List()
	if err != nil {
		return fmt.Errorf("Listing keys from ssh-agent: %v", err)
	}

	// Unless forced, avoid generating a key+cert if we already have a matching one
	if !c.Force {
		for _, key := range agentKeys {
			if key.Comment == c.KeyComment {
				if !c.Quiet {
					log.Printf("[INFO] Found existing key with comment '%s'. Use -force to generate new key+cert", c.KeyComment)
					// TODO: renew it anyway if due to expire in a few seconds?
				}
				return nil
			}
		}
	}

	// Set up Vault credentials
	err = VaultLogin(c)
	if err != nil {
		return fmt.Errorf("Vault login: %v", err)
	}

	// Validate token before burning entropy (assume default policy allows this)
	_, err = c.vault.Auth().Token().LookupSelf()
	if err != nil {
		return fmt.Errorf("Validating token: %v", err)
	}

	// Generate new key pair
	log.Printf("[INFO] Generating new key pair %s", c.KeyComment)
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("Could not generate private key: %v", err)
	}
	pubKey, err := ssh.NewPublicKey(&privKey.PublicKey)
	if err != nil {
		return fmt.Errorf("Could not generate public key: %v", err)
	}
	pubKeyBytes := ssh.MarshalAuthorizedKey(pubKey)
	pubKeyBytes = pubKeyBytes[0 : len(pubKeyBytes)-1] // strip trailing newline
	pubKeyBytes = append(pubKeyBytes, (" " + c.KeyComment + "\n")...)

	// Sign certificate
	data := map[string]interface{}{
		"cert_type":  "user",
		"public_key": base64.StdEncoding.EncodeToString(pubKey.Marshal()),
	}
	if c.ValidPrincipals != "" {
		data["valid_principals"] = c.ValidPrincipals
	}
	if c.Extensions != "" {
		extensions := make(map[string]string)
		for _, extension := range strings.Split(c.Extensions, ",") {
			extensions[extension] = ""
		}
		data["extensions"] = extensions
	}
	if c.TTL != "" {
		data["ttl"] = c.TTL
	}
	signer := c.vault.SSHWithMountPoint(c.MountPoint)
	secret, err := signer.SignKey(c.Role, data)
	if err != nil {
		return fmt.Errorf("Signing cert: %v", err)
	}
	certString, ok := secret.Data["signed_key"].(string)
	if !ok || certString == "" {
		return fmt.Errorf("Cert is missing signed_key")
	}
	cPubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certString))
	if err != nil {
		return fmt.Errorf("Unable to parse certificate response")
	}
	cert, ok := cPubkey.(*ssh.Certificate)
	if !ok {
		return fmt.Errorf("Parsed response is not a certificate")
	}
	lifetimeSecs := int64(cert.ValidBefore) - time.Now().Unix()
	log.Printf("[INFO] Certificate id %s", cert.KeyId)
	log.Printf("[INFO] Certificate serial %d valid for %ds", cert.Serial, lifetimeSecs)

	// If forced, remove any existing matching keys
	if c.Force {
		for _, key := range agentKeys {
			if key.Comment == c.KeyComment {
				pk, err := ssh.ParsePublicKey(key.Marshal())
				if err != nil {
					log.Printf("[WARN] Unable to parse existing key from agent: %v", err)
					continue
				}
				err = c.agent.Remove(pk)
				if err != nil {
					log.Printf("[WARN] Unable to remove existing key from agent: %v", err)
					continue
				}
				pkc, ok := pk.(*ssh.Certificate)
				if ok {
					// Matches output of ssh-add -l
					log.Printf("[INFO] Removed existing key/cert %s", ssh.FingerprintSHA256(pkc.Key))
				} else {
					log.Printf("[INFO] Removed existing key %s", ssh.FingerprintSHA256(pk))
				}
			}
		}
	}

	// Insert key+certificate into agent, with comment / expiry time / usage constraints
	err = c.agent.Add(agent.AddedKey{
		PrivateKey:       privKey,
		Certificate:      cert,
		Comment:          c.KeyComment,
		LifetimeSecs:     uint32(lifetimeSecs),
		ConfirmBeforeUse: c.KeyConfirmBeforeUse,
	})
	if err != nil {
		return fmt.Errorf("Inserting key into agent: %s", err)
	}
	log.Printf("[INFO] New key/cert inserted into agent with comment '%s'", c.KeyComment)

	// Optionally write out pubkey and cert to files
	if c.WritePubkey != "" {
		f, err := os.Create(c.WritePubkey)
		if err != nil {
			return fmt.Errorf("Opening pubkey file for write: %v", err)
		}
		defer f.Close()
		_, err = f.Write(pubKeyBytes)
		if err != nil {
			return fmt.Errorf("Writing pubkey: %v", err)
		}
		log.Printf("[INFO] Written pubkey to %s", c.WritePubkey)
	}
	if c.WriteCert != "" {
		f, err := os.Create(c.WriteCert)
		if err != nil {
			return fmt.Errorf("Opening cert file for write: %v", err)
		}
		defer f.Close()
		_, err = f.Write([]byte(certString))
		if err != nil {
			return fmt.Errorf("Writing cert: %v", err)
		}
		log.Printf("[INFO] Written cert to %s", c.WriteCert)
	}

	return nil
}
