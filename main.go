package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
)

const (
	execName          = "tug"
	maxExpressionSize = 256
	readChunkSize     = 1024
	warnLevel         = "[WARNING]"
	errorLevel        = "[ERROR]"
)

// runTimeOptions will be used during the search
type runTimeOptions struct {
	lineNumber     bool
	allFiles       bool
	reallyAllFiles bool
	simpleSearch   bool
}

// arugments are the defined regex and search space in the command
type arguments struct {
	regularExpression *regexp.Regexp
	searchSpace       []string
}

var (
	globalWg   sync.WaitGroup
	errNotText = errors.New("not a text file")
	// http://tools.ietf.org/html/draft-abarth-mime-sniff-06#page-8
	binaryFlags = []uint8{
		1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
)

// welcome to the main of tug :)
func main() {
	// make it killable
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// parse the input
	opts, args, err := parseInput()
	if err != nil {
		fmt.Fprintf(os.Stdout, "%v in input parse: %v\nUsage: %s [OPTIONS]... PATTERNS [FILE]...\nuse %s --help for details\n", errorLevel, err, os.Args[0], os.Args[0])
		return
	}

	// and begin a wild tug
	globalWg.Add(1)
	tugSearch(ctx, opts, args, os.Stdout, 0)
	globalWg.Wait()

	// final print
	select {
	case <-ctx.Done():
		fmt.Fprintf(os.Stdout, "\n%v the %v run was cancelled, results might be imcomplete...", warnLevel, execName)
	default:
	}
}

// TODO: have enough flags for this to be an actual grepworking system
// parseInput will do a flag set, get flags and args
func parseInput() (currentOpts *runTimeOptions, currentArgs *arguments, err error) {
	// do initial flagset setup
	flagSet := flag.NewFlagSet(execName, flag.ExitOnError)
	flagSet.SetOutput(os.Stdout)
	flagSet.Usage = func() {
		fmt.Fprintf(flagSet.Output(), "Usage: %s [OPTIONS]... PATTERNS [FILE]...\nSearch for PATTERNS in each FILE (or DIR)\nExample: %s -i 'hello wolrd' main.go go.mod\n\nOptions:\n", os.Args[0], os.Args[0])
		flagSet.PrintDefaults()
	}
	// and basic checks
	if len(os.Args) < 2 {
		return nil, nil, fmt.Errorf("not enough arguments provided")
	}

	// define flag arguments
	// first run time options
	lineNumber := flagSet.Bool("n", false, "print line number")
	allFiles := flagSet.Bool("a", false, "most files/directories, included hidden")
	reallyAllFiles := flagSet.Bool("A", false, "all files/directories included hidden AND pure binary")
	simpleSearch := flagSet.Bool("s", false, "simple search, i.e., non recursive if directories are found")
	// then the regex options
	ignoreCase := flagSet.Bool("i", false, "ignore case")

	// parse flag arguments
	flagSet.Parse(os.Args[1:])
	currentOpts = &runTimeOptions{
		lineNumber:     *lineNumber,
		allFiles:       *allFiles,
		reallyAllFiles: *reallyAllFiles,
		simpleSearch:   *simpleSearch,
	}

	// parse runtime arguments
	args := flagSet.Args()
	if len(args) < 1 {
		return nil, nil, fmt.Errorf("not enough arguments provided")
	}

	// take out the regular expression
	rawRegularExpression := args[0]
	if len(rawRegularExpression) > maxExpressionSize {
		return nil, nil, fmt.Errorf("we don't do big ass regex like this")
	}
	// apply the regex options
	if *ignoreCase {
		rawRegularExpression = "(?i)" + rawRegularExpression
	}
	// and compile it
	regularExpression, err := regexp.Compile(rawRegularExpression)
	if err != nil {
		return nil, nil, err
	}
	currentArgs = &arguments{
		regularExpression: regularExpression,
	}

	// default to search in current directory
	currentArgs.searchSpace = make([]string, 0, len(args)-1)
	if len(args) < 2 {
		currentArgs.searchSpace = []string{"."}
		return currentOpts, currentArgs, nil
	}

	for _, arg := range args[1:] {
		cleanArg := filepath.Clean(arg)
		_, err := os.Stat(arg)
		if err != nil {
			return nil, nil, err
		}
		currentArgs.searchSpace = append(currentArgs.searchSpace, cleanArg)
	}
	return currentOpts, currentArgs, nil
}

// it's really not that unsafe since your shell should run in a controlled environment
// but stdout is still thread unsafe (you can get some weird mixed results or concurrent reads)
// infinitly spawning go routines can also mess up a bit the stack / mem / io management
// run this at your own risk :)
func tugSearch(ctx context.Context, opts *runTimeOptions, args *arguments, out io.Writer, depth int) {
	defer globalWg.Done()
	// give a chance to yeet everything at the beginning of a search
	if yeet(ctx) {
		return
	}

	for _, node := range args.searchSpace {
		fStat, err := os.Lstat(node)
		if err != nil {
			fmt.Fprintf(out, "%v skipping file %v, got %v\n", warnLevel, node, err)
			continue
		}
		// skip symlinks
		if fStat.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if !opts.reallyAllFiles && !opts.allFiles && fStat.Name()[0] == byte('.') && len(fStat.Name()) > 1 {
			continue
		}

		if fStat.IsDir() {
			// we're in simple search, so don't recursively search other folders
			if opts.simpleSearch && depth > 0 {
				continue
			}
			// list contents of dir
			entries, err := os.ReadDir(node)
			if err != nil {
				fmt.Fprintf(out, "%v skipping dir %v, got %v\n", warnLevel, node, err)
				continue
			}
			if len(entries) == 0 {
				continue
			}
			subArgs := &arguments{
				regularExpression: args.regularExpression,
				searchSpace:       make([]string, 0, len(entries)-1),
			}
			for _, e := range entries {
				fileName := filepath.Join(node, e.Name())
				subArgs.searchSpace = append(subArgs.searchSpace, fileName)
			}
			// go another tugSearch
			globalWg.Add(1)
			go tugSearch(ctx, opts, subArgs, out, depth+1)
			continue
		}

		// read the whole file and start spewing lines!
		err = func() error {
			f, err := os.Open(node)
			if err != nil {
				return err
			}
			defer f.Close()

			readBuffer := make([]byte, readChunkSize)
			currentReadBytes := int64(0)
			leftoverBuffer := make([]byte, 0)
			for {
				// yeet calculations
				if yeet(ctx) {
					return nil
				}

				// actual file parsing and regex matching
				nByteRead, err := f.Read(readBuffer)
				if err != nil && !errors.Is(err, io.EOF) {
					return err
				}
				if nByteRead == 0 {
					break
				}
				currentReadBytes += int64(nByteRead)

				// run time opts to check for only text files
				if !opts.reallyAllFiles && isBinaryData(readBuffer[:nByteRead]) {
					return nil
				}

				validRead := append(leftoverBuffer, readBuffer[:nByteRead]...)
				var linefeed, prevLinefeed int
				for i := 0; i < len(validRead); i++ {
					if validRead[i] == '\n' {
						// fetch line info
						prevLinefeed = linefeed
						linefeed = i + 1 // to ensure line feed also comes into the string
						// match regex
						if args.regularExpression.Match(validRead[prevLinefeed:linefeed]) {
							// do -1 to take out the extra line feed from the printout
							fmt.Fprintf(out, "%v: %s\n", node, validRead[prevLinefeed:linefeed-1])
						}
					}
				}
				// if we didn't find a line feed at the last byte, store leftovers
				if linefeed != len(validRead)-1 {
					leftoverBuffer = make([]byte, len(validRead)-linefeed)
					copy(leftoverBuffer, validRead[linefeed:])
				}
			}
			if len(leftoverBuffer) == 0 {
				return nil
			}
			// just do the leftover comparision before leaving
			if args.regularExpression.Match(leftoverBuffer) {
				fmt.Fprintf(out, "%v: %s\n", node, leftoverBuffer)
			}

			return nil
		}()
		if err != nil {
			fmt.Fprintf(out, "%v while parsing %v, got %v\n", errorLevel, node, err)
		}

	}
	return
}

// just check if it's yeeting time
func yeet(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
	}
	return false
}

// TODO: find a better way to do this "isBinaryData" check, but efficient enough
// disclaimer: this is not really a very valid binary check file
// but it's good enough for now to check for plain text
// inspired from: https://github.com/adobe/webkit/blob/master/Source/WebCore/platform/network/MIMESniffing.cpp
func isBinaryData(data []byte) bool {
	for i := 0; i < len(data); i++ {
		// a byte will be between 0-255 and len(binaryFlags) == 256
		if binaryFlags[data[i]] == 1 {
			return true
		}
	}
	return false
}
