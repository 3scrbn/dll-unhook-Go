package main

import (
	"classic"
	"direct"
)

func main() {
	classic.UnhookDllClassic()
	direct.UnhookDllDirectSyscalls()
}
