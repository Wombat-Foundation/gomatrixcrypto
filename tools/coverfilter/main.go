package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func main() {
	inPath := flag.String("in", "coverage.out", "input coverage profile")
	outPath := flag.String("out", "", "output coverage profile (default stdout)")
	modulePath := flag.String("module", "", "module path prefix to strip from profile file paths")
	marker := flag.String("marker", "coverage:ignore", "source marker used to ignore a coverage block")
	flag.Parse()

	must(run(*inPath, *outPath, *modulePath, *marker))
}

func detectModulePath() *string {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Path}}").Output()
	if err != nil {
		return new(string)
	}
	value := strings.TrimSpace(string(out))
	return &value
}

func run(inPath, outPath, modulePath, marker string) (err error) {
	if modulePath == "" {
		modulePath = *detectModulePath()
	}

	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := in.Close(); err == nil && cerr != nil {
			err = cerr
		}
	}()

	if outPath == "" {
		return filterProfile(in, os.Stdout, modulePath, marker)
	}

	if filepath.Clean(inPath) == filepath.Clean(outPath) {
		dir := filepath.Dir(outPath)
		tmp, err := os.CreateTemp(dir, "coverfilter-*.out")
		if err != nil {
			return err
		}
		tmpPath := tmp.Name()
		if err = filterProfile(in, tmp, modulePath, marker); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
			return err
		}
		if err = tmp.Close(); err != nil {
			_ = os.Remove(tmpPath)
			return err
		}
		if err = os.Rename(tmpPath, outPath); err != nil {
			_ = os.Remove(tmpPath)
			return err
		}
		return nil
	}

	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); err == nil && cerr != nil {
			err = cerr
		}
	}()

	return filterProfile(in, out, modulePath, marker)
}

func filterProfile(in io.Reader, out io.Writer, modulePath, marker string) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	sourceCache := make(map[string][]string)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "mode:") {
			if _, err := fmt.Fprintln(out, line); err != nil {
				return err
			}
			continue
		}
		if line == "" {
			continue
		}
		filePath, startLine, _, ok := parseCoverageLine(line)
		if !ok {
			continue
		}
		sourcePath := resolveSourcePath(filePath, modulePath)
		lines := sourceCache[sourcePath]
		if lines == nil {
			lines = readSourceLines(sourcePath)
			sourceCache[sourcePath] = lines
		}
		if blockIgnored(lines, startLine, marker) {
			continue
		}
		if _, err := fmt.Fprintln(out, line); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func parseCoverageLine(line string) (string, int, int, bool) {
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		return "", 0, 0, false
	}
	filePath := line[:colon]
	rest := line[colon+1:]
	parts := strings.Fields(rest)
	if len(parts) < 2 {
		return "", 0, 0, false
	}
	span := strings.Split(parts[0], ",")
	if len(span) != 2 {
		return "", 0, 0, false
	}
	startLine, _, ok := parseLineCol(span[0])
	if !ok {
		return "", 0, 0, false
	}
	endLine, _, ok := parseLineCol(span[1])
	if !ok {
		return "", 0, 0, false
	}
	return filePath, startLine, endLine, true
}

func parseLineCol(value string) (int, int, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return 0, 0, false
	}
	line, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	col, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, false
	}
	return line, col, true
}

func resolveSourcePath(profilePath, modulePath string) string {
	if modulePath != "" {
		prefix := modulePath + "/"
		if strings.HasPrefix(profilePath, prefix) {
			return filepath.FromSlash(strings.TrimPrefix(profilePath, prefix))
		}
	}
	if filepath.IsAbs(profilePath) {
		return profilePath
	}
	return filepath.FromSlash(profilePath)
}

func readSourceLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(string(data), "\n")
}

func blockIgnored(lines []string, startLine int, marker string) bool {
	if len(lines) == 0 || startLine <= 0 {
		return false
	}
	if startLine-2 >= 0 && startLine-2 < len(lines) && strings.Contains(lines[startLine-2], marker) {
		return true
	}
	if startLine-1 < len(lines) && strings.Contains(lines[startLine-1], marker) {
		return true
	}
	return false
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
