package compute

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// Compiler models a generic compiler execution command that each Toolchain can
// use to run its compiler and standardise flow control and output.
type Compiler struct {
	command string
	args    []string
	env     []string
	verbose bool
	output  io.Writer
}

// NewCompiler constructs a new Compiler instance.
func NewCompiler(cmd string, args, env []string, verbose bool, out io.Writer) *Compiler {
	return &Compiler{
		cmd,
		args,
		env,
		verbose,
		out,
	}
}

// Exec executes the compiler command and pipes the child process stdout and
// stderr output to the supplied io.Writer, it waits for the command to exit
// cleanly or returns an error.
func (c Compiler) Exec() error {
	//Constrcut the command with given arguments and environment.
	//
	// gosec flagged this:
	// G204 (CWE-78): Subprocess launched with variable
	// Disabling as the variables come from trusted sources.
	/* #nosec */
	cmd := exec.Command(c.command, c.args...)
	cmd.Env = append(os.Environ(), c.env...)

	// Pipe the child process stdout and stderr to our own output writer.
	var stdoutBuf, stderrBuf bytes.Buffer
	stdoutIn, _ := cmd.StdoutPipe()
	stderrIn, _ := cmd.StderrPipe()
	stdout := io.MultiWriter(c.output, &stdoutBuf)
	stderr := io.MultiWriter(c.output, &stderrBuf)

	// Start the command.
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start compilation process: %w", err)
	}

	var errStdout, errStderr error
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		_, errStdout = io.Copy(stdout, stdoutIn)
		wg.Done()
	}()

	_, errStderr = io.Copy(stderr, stderrIn)
	wg.Wait()

	if errStdout != nil {
		return fmt.Errorf("error streaming stdout output from child process: %w", errStdout)
	}
	if errStderr != nil {
		return fmt.Errorf("error streaming stderr output from child process: %w", errStderr)
	}

	// Wait for the command to exit.
	if err := cmd.Wait(); err != nil {
		// If we're not in verbose mode return the bufferred stderr output
		// from cargo as the error.
		if !c.verbose && stderrBuf.Len() > 0 {
			return fmt.Errorf("error during compilation process:\n%s", strings.TrimSpace(stderrBuf.String()))
		}
		return fmt.Errorf("error during compilation process")
	}

	return nil
}
