module test

go 1.24.2

require (
	classic v0.0.0
	direct v0.0.0
)

require (
	github.com/Binject/debug v0.0.0-20200830173345-f54480b6530f // indirect
	github.com/C-Sto/BananaPhone v0.0.0-20220220002628-6585e5913761 // indirect
	github.com/awgh/rawreader v0.0.0-20200626064944-56820a9c6da4 // indirect
	golang.org/x/sys v0.33.0 // indirect
)

replace classic => "./Classic unhook"

replace direct => "./Unhook with direct syscalls"
