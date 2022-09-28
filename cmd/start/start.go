package start

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

	pty "github.com/MCSManager/pty/console"
	"github.com/mattn/go-colorable"
)

var (
	dir, cmd, coder, ptySize string
	cmds                     []string
	colorAble                bool
)

type PtyInfo struct {
	Pid int `json:"pid"`
}

func init() {
	if runtime.GOOS == "windows" {
		flag.StringVar(&cmd, "cmd", "[\"cmd\"]", "command")
	} else {
		flag.StringVar(&cmd, "cmd", "[\"sh\"]", "command")
	}

	flag.BoolVar(&colorAble, "color", false, "colorable (default false)")
	flag.StringVar(&coder, "coder", "UTF-8", "Coder")
	flag.StringVar(&dir, "dir", ".", "command work path")
	flag.StringVar(&ptySize, "size", "80,50", "Initialize pty size, stdin will be forwarded directly")
}

func Main() {
	flag.Parse()
	json.Unmarshal([]byte(cmd), &cmds)

	con := pty.New(coder, colorAble)
	if err := con.ResizeWithString(ptySize); err != nil {
		fmt.Printf("[MCSMANAGER-PTY] PTY ReSize Error: %v\n", err)
		return
	}

	err := con.Start(dir, cmds)
	info, _ := json.Marshal(&PtyInfo{
		Pid: con.Pid(),
	})
	fmt.Println(string(info))
	if err != nil {
		fmt.Printf("[MCSMANAGER-PTY] Process Start Error: %v\n", err)
		return
	}
	defer con.Close()

	HandleStdIO(con)
	con.Wait()
}

func HandleStdIO(c pty.Console) {
	go io.Copy(c.StdIn(), os.Stdin)
	if runtime.GOOS == "windows" && c.StdErr() != nil {
		go io.Copy(os.Stderr, c.StdErr())
	}
	handleStdOut(c)
}

func handleStdOut(c pty.Console) {
	var stdout io.Writer
	if colorAble {
		stdout = colorable.NewColorable(os.Stdout)
	} else {
		stdout = colorable.NewNonColorable(os.Stdout)
	}
	io.Copy(stdout, c.StdOut())
}