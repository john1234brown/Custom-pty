//go:build !windows
// +build !windows

package console

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
        "regexp"
        "strings"

	"github.com/MCSManager/pty/console/iface"
	"github.com/MCSManager/pty/utils"
	"github.com/creack/pty"
)

var _ iface.Console = (*console)(nil)

type console struct {
	file  *os.File
	cmd   *exec.Cmd
	coder utils.CoderType

	stdIn  io.Writer
	stdOut io.Reader
	stdErr io.Reader // nil

	initialCols uint
	initialRows uint

	env []string
}

// start pty subroutine
func (c *console) Start(dir string, command []string) error {
	if dir, err := filepath.Abs(dir); err != nil {
		return err
	} else if err := os.Chdir(dir); err != nil {
		return err
	}
	// Split the command string into arguments
    	commandArgs := strings.Fields(command)
    
    	// Sanitize the command arguments
    	sanitizedArgs := make([]string, len(commandArgs))
    	for i, arg := range commandArgs {
        	sanitizedArgs[i] = sanitizeCommand(arg)
    	}

    	// Other existing code...
    	cmd, err := c.buildCmd(sanitizedArgs)
	if err != nil {
		return err
	}
	c.cmd = cmd
	cmd.Dir = dir
	cmd.Env = c.env
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: uint16(c.initialRows), Cols: uint16(c.initialCols)})
	if err != nil {
		return err
	}
	c.stdIn = utils.DecoderWriter(c.coder, f)
	c.stdOut = utils.DecoderReader(c.coder, f)
	c.stdErr = nil
	c.file = f
	return nil
}

func sanitizeCommand(arg string) string {
    // Remove control characters and non-printable characters
    re := regexp.MustCompile(`[\x00-\x1F\x7F-\x9F]`)
    arg = re.ReplaceAllString(arg, "")

    // Remove special characters that could be used in exploits
    arg = strings.ReplaceAll(arg, "|", "")
    arg = strings.ReplaceAll(arg, "`", "")
    arg = strings.ReplaceAll(arg, "\\", "")

    // Prevent path traversal attacks by removing '..'
    arg = strings.ReplaceAll(arg, "..", "")

    // Remove escaped character sequences like \xHH and \uHHHH
    re = regexp.MustCompile(`\\([0-9a-fA-F]{2})`)
    arg = re.ReplaceAllString(arg, "")

    // Remove Unicode escape sequences like \uHHHH
    re = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
    arg = re.ReplaceAllString(arg, "")

    // Remove specific dangerous commands
    dangerousCommands := []string{
        "rm -r /", "rm -R /", "rm -rf /", "rm -Rf /",
        "rm -r -f /", "rm -R -f /", "rm -r -R /", "rm -rf -r /",
        "rm -r -rf /", "rm -Rf -r /", "rm -R -rf /", "rm -r -f -R /",
        "rm -R -f -r /", "rm -r -R -f /", "rm -rf -r -R /", "rm -r -rf -R /",
        "rm -Rf -r -f /", "rm -R -rf -r /", "rm -r -f -R -f /", "rm -R -f -r -f /",
        "sh", "sudo", "mv /", "chmod -R 777", "chown -R", "dd if=/dev/zero", "mkfs",
    }

    for _, dc := range dangerousCommands {
        arg = strings.ReplaceAll(arg, dc, "")
    }

    return arg
}

func (c *console) buildCmd(args []string) (*exec.Cmd, error) {
	if len(args) == 0 {
		return nil, ErrInvalidCmd
	}
	var err error
	if args[0], err = exec.LookPath(args[0]); err != nil {
		return nil, err
	}
	cmd := exec.Command(args[0], args[1:]...)
	return cmd, nil
}

// set pty window size
func (c *console) SetSize(cols uint, rows uint) error {
	c.initialRows = rows
	c.initialCols = cols
	if c.file == nil {
		return nil
	}
	return pty.Setsize(c.file, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
}

// Get the process id of the pty subprogram
func (c *console) Pid() int {
	if c.cmd == nil {
		return 0
	}

	return c.cmd.Process.Pid
}

func (c *console) findProcess() (*os.Process, error) {
	if c.cmd == nil {
		return nil, ErrProcessNotStarted
	}
	return c.cmd.Process, nil
}

// Force kill pty subroutine
func (c *console) Kill() error {
	proc, err := c.findProcess()
	if err != nil {
		return err
	}
	// try to kill all child processes
	pgid, err := syscall.Getpgid(proc.Pid)
	if err != nil {
		return proc.Kill()
	}
	return syscall.Kill(-pgid, syscall.SIGKILL)
}
