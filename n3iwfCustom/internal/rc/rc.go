package rc

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/free5gc/n3iwf/internal/snapshot"
)

const (
	defaultHostapdCLI = "hostapd_cli"
	defaultTimeout    = 2 * time.Second
)

var (
	macRegex            = regexp.MustCompile(`^(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}$`)
	selectedIfaceRegexp = regexp.MustCompile(`Selected interface '([^']+)'`)
)

// HostapdOptions definisce i parametri usati per interrogare hostapd.
type HostapdOptions struct {
	Command    string
	ControlDir string
	Interfaces []string
	Timeout    time.Duration
}

// DefaultHostapdOptions costruisce un set di opzioni utilizzando eventuali variabili
// d'ambiente (HOSTAPD_CLI_PATH, HOSTAPD_CTRL_PATH, HOSTAPD_INTERFACES).
func DefaultHostapdOptions() HostapdOptions {
	opts := HostapdOptions{
		Command:    os.Getenv("HOSTAPD_CLI_PATH"),
		ControlDir: os.Getenv("HOSTAPD_CTRL_PATH"),
		Timeout:    defaultTimeout,
	}
	if opts.Command == "" {
		opts.Command = defaultHostapdCLI
	}
	if list := os.Getenv("HOSTAPD_INTERFACES"); list != "" {
		opts.Interfaces = splitInterfaceList(list)
	}
	return opts
}

func (o HostapdOptions) withDefaults() HostapdOptions {
	opts := o
	if opts.Command == "" {
		opts.Command = defaultHostapdCLI
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if len(opts.Interfaces) == 0 {
		if list := os.Getenv("HOSTAPD_INTERFACES"); list != "" {
			opts.Interfaces = splitInterfaceList(list)
		}
	}
	if opts.ControlDir == "" {
		opts.ControlDir = os.Getenv("HOSTAPD_CTRL_PATH")
	}
	return opts
}

// CollectHostapdSnapshot esegue hostapd_cli per ciascuna interfaccia indicata e
// restituisce uno snapshot pronto da registrare.
func CollectHostapdSnapshot(ctx context.Context, options HostapdOptions) (snapshot.RCSnapshot, error) {
	opts := options.withDefaults()
	if ctx == nil {
		ctx = context.Background()
	}

	interfaces := opts.Interfaces
	if len(interfaces) == 0 {
		interfaces = []string{""}
	}

	var ifaceSnaps []snapshot.RCInterfaceSnapshot
	var errs []string

	now := time.Now()
	for _, iface := range interfaces {
		args := opts.buildAllStaArgs(iface)
		commandString := buildCommandString(opts.Command, args)

		cmdCtx := ctx
		cancel := func() {}
		if opts.Timeout > 0 {
			cmdCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
		}
		output, runErr := runCommand(cmdCtx, opts.Command, args)
		cancel()

		ifaceSnap := snapshot.RCInterfaceSnapshot{
			Interface: iface,
			Raw:       output,
			Command:   []string{commandString},
		}

		if runErr != nil {
			ifaceSnap.Error = runErr.Error()
			errs = append(errs, fmt.Sprintf("%s: %v", commandString, runErr))
			ifaceSnaps = append(ifaceSnaps, ifaceSnap)
			continue
		}

		detected := iface
		if detected == "" {
			if parsed := detectSelectedInterface(output); parsed != "" {
				detected = parsed
			}
		}
		ifaceSnap.Interface = detected

		stations, parseErr := parseHostapdAllSta(output)
		ifaceSnap.Stations = stations
		if parseErr != nil {
			ifaceSnap.Error = parseErr.Error()
			errs = append(errs, fmt.Sprintf("%s parse: %v", commandString, parseErr))
		}

		ifaceSnaps = append(ifaceSnaps, ifaceSnap)
	}

	snap := snapshot.RCSnapshot{
		Timestamp:  now,
		Interfaces: ifaceSnaps,
	}
	if len(errs) > 0 {
		snap.Errors = errs
		return snap, fmt.Errorf(strings.Join(errs, "; "))
	}
	return snap, nil
}

func (o HostapdOptions) buildAllStaArgs(iface string) []string {
	args := make([]string, 0, 6)
	if o.ControlDir != "" {
		args = append(args, "-p", o.ControlDir)
	}
	if iface != "" {
		args = append(args, "-i", iface)
	}
	args = append(args, "all_sta")
	return args
}

func runCommand(ctx context.Context, bin string, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		trimmed := strings.TrimSpace(output)
		if trimmed != "" {
			err = fmt.Errorf("%w: %s", err, trimmed)
		}
		return output, err
	}
	return output, nil
}

func buildCommandString(bin string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, bin)
	for _, arg := range args {
		if strings.ContainsAny(arg, " \t") {
			parts = append(parts, strconv.Quote(arg))
		} else {
			parts = append(parts, arg)
		}
	}
	return strings.Join(parts, " ")
}

func detectSelectedInterface(output string) string {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		matches := selectedIfaceRegexp.FindStringSubmatch(line)
		if len(matches) == 2 {
			return matches[1]
		}
	}
	return ""
}

func parseHostapdAllSta(output string) ([]snapshot.RCStation, error) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	var stations []snapshot.RCStation
	var current *snapshot.RCStation

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "selected interface") {
			// Già gestito separatamente
			continue
		}

		switch {
		case macRegex.MatchString(line):
			if current != nil {
				stations = append(stations, *current)
			}
			current = &snapshot.RCStation{
				MAC:           strings.ToLower(line),
				Fields:        make(map[string]string),
				OrderedFields: make([]snapshot.RCField, 0, 32),
			}

		case strings.HasPrefix(strings.ToLower(line), "station="):
			mac := strings.TrimSpace(line[len("station="):])
			if macRegex.MatchString(mac) {
				if current != nil {
					stations = append(stations, *current)
				}
				current = &snapshot.RCStation{
					MAC:           strings.ToLower(mac),
					Fields:        make(map[string]string),
					OrderedFields: make([]snapshot.RCField, 0, 32),
				}
			}

		default:
			if current == nil {
				continue
			}
			key, value := parseKeyValue(line)
			if key != "" {
				current.Fields[key] = value
			}
			current.OrderedFields = append(current.OrderedFields, snapshot.RCField{
				Key:   key,
				Value: value,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return stations, err
	}
	if current != nil {
		stations = append(stations, *current)
	}
	return stations, nil
}

func parseKeyValue(line string) (string, string) {
	if idx := strings.Index(line, "="); idx != -1 {
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		return key, value
	}
	return "", strings.TrimSpace(line)
}

func splitInterfaceList(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || r == ','
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if trimmed := strings.TrimSpace(f); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
