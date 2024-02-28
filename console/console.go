//go:build !windows
// +build !windows

package console

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

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
	// Sanitize the command arguments
    	sanitizedCommand := sanitizeCommand(command)

    	// Other existing code...
    	cmd, err := c.buildCmd(sanitizedCommand)
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

func sanitizeCommand(command []string) []string {
    // Implement your sanitization logic here
    // For example, remove any characters or commands that are not allowed
    // and return the sanitized command arguments
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
