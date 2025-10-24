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
	defaultTimeout    = 5 * time.Second
)

var (
	macRegex            = regexp.MustCompile(`^(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}$`)
	selectedIfaceRegexp = regexp.MustCompile(`Selected interface '([^']+)'`)
)

// HostapdOptions definisce i parametri usati per interrogare hostapd.
type HostapdOptions struct {
	Command       string
	CommandPrefix []string
	ControlDir    string
	Interfaces    []string
	Timeout       time.Duration
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
	opts.CommandPrefix = splitCommandList(os.Getenv("HOSTAPD_COMMAND_PREFIX"))
	if timeoutStr := strings.TrimSpace(os.Getenv("HOSTAPD_TIMEOUT")); timeoutStr != "" {
		if dur, err := time.ParseDuration(timeoutStr); err == nil {
			opts.Timeout = dur
		} else if ms, err := strconv.Atoi(timeoutStr); err == nil {
			opts.Timeout = time.Duration(ms) * time.Millisecond
		}
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
		_, snap, errList := collectStations(ctx, opts, iface)
		if errList != nil {
			errs = append(errs, errList...)
		}
		ifaceSnaps = append(ifaceSnaps, snap)
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

func (o HostapdOptions) buildListStaArgs(iface string) []string {
	args := make([]string, 0, 6)
	if o.ControlDir != "" {
		args = append(args, "-p", o.ControlDir)
	}
	if iface != "" {
		args = append(args, "-i", iface)
	}
	args = append(args, "list_sta")
	return args
}

func (o HostapdOptions) buildStaArgs(iface, mac string) []string {
	args := make([]string, 0, 7)
	if o.ControlDir != "" {
		args = append(args, "-p", o.ControlDir)
	}
	if iface != "" {
		args = append(args, "-i", iface)
	}
	args = append(args, "sta", strings.ToLower(mac))
	return args
}

func runCommand(ctx context.Context, opts HostapdOptions, args []string) (string, error) {
	argv := make([]string, 0, len(opts.CommandPrefix)+1+len(args))
	argv = append(argv, opts.CommandPrefix...)
	argv = append(argv, opts.Command)
	argv = append(argv, args...)
	if len(argv) == 0 {
		return "", fmt.Errorf("hostapd_cli command not configured")
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
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

func buildCommandString(prefix []string, bin string, args []string) string {
	parts := make([]string, 0, len(prefix)+len(args)+1)
	parts = append(parts, prefix...)
	parts = append(parts, bin)
	parts = append(parts, args...)
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
				MAC:     strings.ToLower(line),
				Fields:  make(map[string]string),
				Hostapd: make(map[string]string),
			}

		case strings.HasPrefix(strings.ToLower(line), "station="):
			mac := strings.TrimSpace(line[len("station="):])
			if macRegex.MatchString(mac) {
				if current != nil {
					stations = append(stations, *current)
				}
				current = &snapshot.RCStation{
					MAC:     strings.ToLower(mac),
					Fields:  make(map[string]string),
					Hostapd: make(map[string]string),
				}
			}

		default:
			if current == nil {
				continue
			}
			key, value := parseKeyValue(line)
			if key != "" {
				current.Fields[key] = value
				current.Hostapd[key] = value
				if key == "ip" || key == "ip_addr" || key == "ipv4" {
					current.IP = strings.TrimSpace(value)
				}
			}
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

func splitCommandList(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return strings.Fields(value)
}

func collectStations(ctx context.Context, opts HostapdOptions, iface string) ([]snapshot.RCStation, snapshot.RCInterfaceSnapshot, []string) {
	args := opts.buildAllStaArgs(iface)
	commandString := buildCommandString(opts.CommandPrefix, opts.Command, args)

	output, runErr := runWithTimeout(ctx, opts, args)

	ifaceSnap := snapshot.RCInterfaceSnapshot{
		Interface: iface,
		Raw:       output,
		Command:   []string{commandString},
	}

	var errorList []string

	if runErr == nil {
		if detected := detectSelectedInterface(output); detected != "" {
			ifaceSnap.Interface = detected
		}
		stations, parseErr := parseHostapdAllSta(output)
		if parseErr == nil {
			ifaceSnap.Stations = stations
			return stations, ifaceSnap, nil
		}
		ifaceSnap.Error = parseErr.Error()
		errorList = append(errorList, fmt.Sprintf("%s parse: %v", commandString, parseErr))
	} else {
		ifaceSnap.Error = runErr.Error()
		errorList = append(errorList, fmt.Sprintf("%s: %v", commandString, runErr))
	}

	fallbackStations, fallbackRaw, fallbackCmds, fallbackErrs := collectStationsViaListSta(ctx, opts, iface)
	ifaceSnap.Raw = appendRaw(ifaceSnap.Raw, fallbackRaw)
	if len(fallbackCmds) > 0 {
		ifaceSnap.Command = append(ifaceSnap.Command, fallbackCmds...)
	}
	if len(fallbackStations) > 0 {
		ifaceSnap.Stations = fallbackStations
	}

	if len(fallbackErrs) == 0 {
		ifaceSnap.Error = ""
		return fallbackStations, ifaceSnap, errorList
	}

	if ifaceSnap.Error == "" {
		ifaceSnap.Error = strings.Join(fallbackErrs, "; ")
	}
	errorList = append(errorList, fallbackErrs...)
	return fallbackStations, ifaceSnap, errorList
}

func collectStationsViaListSta(ctx context.Context, opts HostapdOptions, iface string) ([]snapshot.RCStation, string, []string, []string) {
	var rawParts []string
	var commands []string
	var errorList []string

	run := func(args []string) (string, error) {
		return runWithTimeout(ctx, opts, args)
	}

	listArgs := opts.buildListStaArgs(iface)
	listCmd := buildCommandString(opts.CommandPrefix, opts.Command, listArgs)
	listOut, listErr := run(listArgs)
	commands = append(commands, listCmd)
	rawParts = append(rawParts, formatCommandOutput(listCmd, listOut))
	if listErr != nil {
		errorList = append(errorList, fmt.Sprintf("%s: %v", listCmd, listErr))
		return nil, strings.Join(rawParts, "\n"), commands, errorList
	}

	macs := parseListSta(listOut)
	if len(macs) == 0 {
		return []snapshot.RCStation{}, strings.Join(rawParts, "\n"), commands, errorList
	}

	stations := make([]snapshot.RCStation, 0, len(macs))
	for _, mac := range macs {
		staArgs := opts.buildStaArgs(iface, mac)
		staCmd := buildCommandString(opts.CommandPrefix, opts.Command, staArgs)
		staOut, staErr := run(staArgs)
		commands = append(commands, staCmd)
		rawParts = append(rawParts, formatCommandOutput(staCmd, staOut))
		if staErr != nil {
			errorList = append(errorList, fmt.Sprintf("%s: %v", staCmd, staErr))
			continue
		}
		stations = append(stations, parseHostapdSta(mac, staOut))
	}

	return stations, strings.Join(rawParts, "\n"), commands, errorList
}

func runWithTimeout(ctx context.Context, opts HostapdOptions, args []string) (string, error) {
	cmdCtx := ctx
	cancel := func() {}
	if opts.Timeout > 0 {
		cmdCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
	}
	defer cancel()
	return runCommand(cmdCtx, opts, args)
}

func parseListSta(output string) []string {
	var macs []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if macRegex.MatchString(line) {
			macs = append(macs, strings.ToLower(line))
		}
	}
	return macs
}

func parseHostapdSta(mac string, output string) snapshot.RCStation {
	station := snapshot.RCStation{
		MAC:     strings.ToLower(mac),
		Fields:  make(map[string]string),
		Hostapd: make(map[string]string),
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "selected interface") {
			continue
		}
		key, value := parseKeyValue(line)
		if key != "" {
			station.Fields[key] = value
			station.Hostapd[key] = value
			if station.IP == "" && (key == "ip" || key == "ip_addr" || key == "ipv4") {
				station.IP = strings.TrimSpace(value)
			}
		}
	}

	return station
}

func appendRaw(base, extra string) string {
	base = strings.TrimSpace(base)
	extra = strings.TrimSpace(extra)
	switch {
	case base == "":
		return extra
	case extra == "":
		return base
	default:
		return base + "\n---\n" + extra
	}
}

func formatCommandOutput(cmd, output string) string {
	return fmt.Sprintf("$ %s\n%s", cmd, strings.TrimSpace(output))
}
