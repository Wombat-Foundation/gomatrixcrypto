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

	if *modulePath == "" {
		modulePath = detectModulePath()
	}

	in, err := os.Open(*inPath)
	must(err)
	defer func() {
		must(in.Close())
	}()

	var out io.Writer = os.Stdout
	var file *os.File
	if *outPath != "" {
		file, err = os.Create(*outPath)
		must(err)
		defer func() {
			must(file.Close())
		}()
		out = file
	}

	if err := filterProfile(in, out, *modulePath, *marker); err != nil {
		must(err)
	}
}

func detectModulePath() *string {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Path}}").Output()
	if err != nil {
		return new(string)
	}
	value := strings.TrimSpace(string(out))
	return &value
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
