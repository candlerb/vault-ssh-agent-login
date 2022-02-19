vault-ssh-agent-login: main.go
	go build .

.PHONY: install
install: vault-ssh-agent-login
	cp vault-ssh-agent-login /usr/local/bin/
