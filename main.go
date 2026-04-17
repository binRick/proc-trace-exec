// extrace-go — trace exec() calls system-wide via Linux proc connector
//
// Port of extrace by Leah Neukirchen <leah@vuxu.org>
// Requires CONFIG_CONNECTOR=y and CONFIG_PROC_EVENTS=y
// Requires root or CAP_NET_ADMIN
//
// Usage: extrace [-deflqQtu] [-o FILE] [-p PID | CMD...]
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// ─── Netlink / proc connector constants ──────────────────────────────────────

const (
	netlinkConnector   = 11
	cnIdxProc          = 1
	cnValProc          = 1
	procCnMcastListen  = 1
	procCnMcastIgnore  = 2

	procEventNone = uint32(0x00000000)
	procEventFork = uint32(0x00000001)
	procEventExec = uint32(0x00000002)
	procEventExit = uint32(0x80000000)

	nlmsgHdrSize = 16 // sizeof(struct nlmsghdr)
	cnMsgSize    = 20 // sizeof(struct cn_msg): 4+4+4+4+2+2
	procEvtHdr   = 16 // what(4)+cpu(4)+ts(8)
)

// ─── Proc database ───────────────────────────────────────────────────────────

type pidEntry struct {
	depth   int
	startNs uint64
	cmdline string // first arg, for exit line
}

var (
	mu    sync.Mutex
	pidDB = make(map[int32]*pidEntry)
)

// ─── Global options ───────────────────────────────────────────────────────────

var (
	watchPID   int32 = 1 // only trace descendants of this PID (1 = everyone)
	showCwd    bool
	showEnv    bool
	flatMode   bool
	fullPath   bool
	showArgs   = true
	showErrors = true
	showExit   bool
	showUser   bool
	out        io.Writer = os.Stdout
)

// ─── main ─────────────────────────────────────────────────────────────────────

func main() {
	args := os.Args[1:]
	var cmdArgs []string // remaining args after flags (CMD mode)
	var outFile string

	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[0] != '-' {
			cmdArgs = args[i:]
			break
		}
		for _, ch := range a[1:] {
			switch ch {
			case 'd':
				showCwd = true
			case 'e':
				showEnv = true
			case 'f':
				flatMode = true
			case 'l':
				fullPath = true
			case 'q':
				showArgs = false
			case 'Q':
				showErrors = false
			case 't':
				showExit = true
			case 'u':
				showUser = true
			case 'p':
				if i+1 >= len(args) {
					fatal("flag -p requires an argument")
				}
				i++
				pid, err := strconv.Atoi(args[i])
				if err != nil || pid <= 0 {
					fatalf("-p: invalid PID: %s", args[i])
				}
				if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
					fatalf("-p %d: no such process", pid)
				}
				watchPID = int32(pid)
			case 'o':
				if i+1 >= len(args) {
					fatal("flag -o requires an argument")
				}
				i++
				outFile = args[i]
			case 'h':
				usage()
			default:
				fatalf("unknown flag -%c", ch)
			}
		}
	}

	if outFile != "" {
		f, err := os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			fatalf("open %s: %v", outFile, err)
		}
		defer f.Close()
		out = f
	}

	// Build netlink socket
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, netlinkConnector)
	if err != nil {
		fatalf("socket: %v", err)
	}
	defer syscall.Close(fd)

	sa := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Groups: cnIdxProc,
		Pid:    uint32(os.Getpid()),
	}
	if err := syscall.Bind(fd, sa); err != nil {
		fatalf("bind: %v", err)
	}

	if err := sendMcastOp(fd, procCnMcastListen); err != nil {
		fatalf("subscribe: %v", err)
	}

	// CMD mode: fork the command and only trace its descendants
	if len(cmdArgs) > 0 {
		watchPID = int32(os.Getpid())
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			fatalf("exec %s: %v", cmdArgs[0], err)
		}
		go func() {
			cmd.Wait()
			// unsubscribe and exit when child exits
			sendMcastOp(fd, procCnMcastIgnore) //nolint
			os.Exit(0)
		}()
	}

	// Event loop
	buf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			fatalf("recvfrom: %v", err)
		}
		dispatchNlMsg(buf[:n])
	}
}

// ─── Netlink helpers ──────────────────────────────────────────────────────────

// sendMcastOp sends PROC_CN_MCAST_LISTEN or _IGNORE to the kernel.
func sendMcastOp(fd int, op uint32) error {
	var buf [nlmsgHdrSize + cnMsgSize + 4]byte
	le := binary.LittleEndian

	total := uint32(len(buf))
	le.PutUint32(buf[0:], total)           // nlmsg_len
	le.PutUint16(buf[4:], syscall.NLMSG_DONE) // nlmsg_type
	le.PutUint16(buf[6:], 0)              // nlmsg_flags
	le.PutUint32(buf[8:], 0)              // nlmsg_seq
	le.PutUint32(buf[12:], uint32(os.Getpid())) // nlmsg_pid

	// cn_msg
	le.PutUint32(buf[16:], cnIdxProc) // id.idx
	le.PutUint32(buf[20:], cnValProc) // id.val
	le.PutUint32(buf[24:], 0)         // seq
	le.PutUint32(buf[28:], 0)         // ack
	le.PutUint16(buf[32:], 4)         // len = sizeof(uint32)
	le.PutUint16(buf[34:], 0)         // flags

	le.PutUint32(buf[36:], op)

	to := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	return syscall.Sendto(fd, buf[:], 0, to)
}

// dispatchNlMsg processes one or more netlink messages in a received buffer.
func dispatchNlMsg(data []byte) {
	msgs, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return
	}
	for _, msg := range msgs {
		d := msg.Data
		if len(d) < cnMsgSize+procEvtHdr {
			continue
		}
		// Verify this is a proc connector message
		idx := binary.LittleEndian.Uint32(d[0:])
		val := binary.LittleEndian.Uint32(d[4:])
		if idx != cnIdxProc || val != cnValProc {
			continue
		}
		// Parse proc_event header
		what := binary.LittleEndian.Uint32(d[cnMsgSize:])
		tsNs := binary.LittleEndian.Uint64(d[cnMsgSize+8:])
		evData := d[cnMsgSize+procEvtHdr:]

		switch what {
		case procEventExec:
			handleExec(evData, tsNs)
		case procEventExit:
			handleExit(evData, tsNs)
		}
	}
}

// ─── Event handlers ───────────────────────────────────────────────────────────

func handleExec(data []byte, tsNs uint64) {
	if len(data) < 8 {
		return
	}
	pid := int32(binary.LittleEndian.Uint32(data[0:]))

	d := pidDepth(pid)
	if d < 0 {
		return // not a descendant of watchPID
	}

	mu.Lock()
	ent, exists := pidDB[pid]
	if !exists {
		ent = &pidEntry{}
		pidDB[pid] = ent
	}

	// Print previous exec info for this pid if show_exit (C's "pid+ ... execed time=Xs")
	if showExit && exists && ent.cmdline != "" {
		line := buildExecedLine(ent, pid)
		mu.Unlock()
		fmt.Fprintln(out, line)
		mu.Lock()
	}

	ent.depth = d
	ent.startNs = tsNs
	ent.cmdline = readFirstArg(pid)
	mu.Unlock()

	printExec(pid, d, tsNs)
}

func handleExit(data []byte, tsNs uint64) {
	if len(data) < 24 {
		return
	}
	pid := int32(binary.LittleEndian.Uint32(data[0:]))
	exitCode := binary.LittleEndian.Uint32(data[8:])

	mu.Lock()
	ent, ok := pidDB[pid]
	if ok {
		delete(pidDB, pid)
	}
	mu.Unlock()

	if !ok || !showExit {
		return
	}

	indent := indentStr(ent.depth)
	elapsed := float64(tsNs-ent.startNs) / 1e9

	var exitStr string
	if exitCode&0x7f == 0 { // WIFEXITED
		exitStr = fmt.Sprintf("status=%d", (exitCode>>8)&0xff)
	} else { // signaled
		exitStr = fmt.Sprintf("signal=%s", sigName(int(exitCode&0x7f)))
	}

	fmt.Fprintf(out, "%s%d- %s exited %s time=%.3fs\n",
		indent, pid, shQuote(ent.cmdline), exitStr, elapsed)
}

// ─── Output formatting ────────────────────────────────────────────────────────

func printExec(pid int32, depth int, tsNs uint64) {
	indent := indentStr(depth)

	var sb strings.Builder
	sb.WriteString(indent)
	sb.WriteString(strconv.Itoa(int(pid)))
	if showExit {
		sb.WriteByte('+')
	}

	if showUser {
		name := procUser(pid)
		sb.WriteString(" <")
		sb.WriteString(name)
		sb.WriteByte('>')
	}

	sb.WriteByte(' ')

	if showCwd {
		cwd := procCwd(pid)
		sb.WriteString(shQuote(cwd))
		sb.WriteString(" % ")
	}

	// argv[0] (or full exe path with -l)
	argv := readCmdline(pid)
	if len(argv) == 0 {
		// kernel thread or vanished
		comm := readComm(pid)
		if comm == "" {
			return // completely vanished
		}
		sb.WriteByte('[')
		sb.WriteString(comm)
		sb.WriteByte(']')
	} else {
		if fullPath {
			exe := readExe(pid)
			if exe != "" {
				sb.WriteString(shQuote(exe))
			} else {
				sb.WriteString(shQuote(argv[0]))
			}
		} else {
			sb.WriteString(shQuote(argv[0]))
		}
		if showArgs && len(argv) > 1 {
			for _, arg := range argv[1:] {
				sb.WriteByte(' ')
				sb.WriteString(shQuote(arg))
			}
		}
	}

	if showEnv {
		env := readEnviron(pid)
		sb.WriteString("\n  ")
		for _, e := range env {
			sb.WriteByte(' ')
			eq := strings.IndexByte(e, '=')
			if eq >= 0 {
				sb.WriteString(shQuote(e[:eq]))
				sb.WriteByte('=')
				sb.WriteString(shQuote(e[eq+1:]))
			} else {
				sb.WriteString(shQuote(e))
			}
		}
	}

	fmt.Fprintln(out, sb.String())
}

func buildExecedLine(ent *pidEntry, pid int32) string {
	indent := indentStr(ent.depth)
	return fmt.Sprintf("%s%d- %s execed", indent, pid, shQuote(ent.cmdline))
}

func indentStr(depth int) string {
	if flatMode || depth <= 0 {
		return ""
	}
	return strings.Repeat("  ", depth)
}

// ─── Depth / ancestry ─────────────────────────────────────────────────────────

// pidDepth returns the indentation depth of pid relative to watchPID,
// or -1 if pid is not a descendant of watchPID.
func pidDepth(pid int32) int {
	if pid == watchPID {
		return 0
	}
	ppid := statPPID(pid)
	if ppid <= 0 {
		runtimeErr("extrace: cannot read ppid for pid %d", pid)
		return -1
	}
	if ppid == watchPID {
		return 0
	}

	// Check cache
	mu.Lock()
	if ent, ok := pidDB[ppid]; ok {
		d := ent.depth
		mu.Unlock()
		return d + 1
	}
	mu.Unlock()

	// Recurse
	d := pidDepth(ppid)
	if d == -1 {
		return -1
	}
	return d + 1
}

// statPPID reads the ppid from /proc/pid/stat (handles parens in comm).
func statPPID(pid int32) int32 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return -1
	}
	// Format: pid (comm) state ppid ...
	// Find the last ')' to skip comm which may contain spaces/parens
	idx := bytes.LastIndexByte(data, ')')
	if idx < 0 {
		return -1
	}
	rest := strings.TrimLeft(string(data[idx+1:]), " ")
	// rest: "state ppid ..."
	fields := strings.Fields(rest)
	if len(fields) < 2 {
		return -1
	}
	ppid, err := strconv.ParseInt(fields[1], 10, 32)
	if err != nil {
		return -1
	}
	return int32(ppid)
}

// ─── /proc helpers ────────────────────────────────────────────────────────────

func readCmdline(pid int32) []string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(data) == 0 {
		return nil
	}
	data = bytes.TrimRight(data, "\x00")
	parts := bytes.Split(data, []byte{0})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, string(p))
	}
	return out
}

func readFirstArg(pid int32) string {
	argv := readCmdline(pid)
	if len(argv) == 0 {
		return readComm(pid)
	}
	return filepath.Base(argv[0])
}

func readExe(pid int32) string {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return exe
}

func readComm(pid int32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(data), "\n")
}

func procCwd(pid int32) string {
	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		if os.IsPermission(err) {
			return "EACCES"
		}
		return "EUNKNOWN"
	}
	return cwd
}

func readEnviron(pid int32) []string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil || len(data) == 0 {
		return nil
	}
	data = bytes.TrimRight(data, "\x00")
	parts := bytes.Split(data, []byte{0})
	env := make([]string, 0, len(parts))
	for _, p := range parts {
		env = append(env, string(p))
	}
	return env
}

func procUser(pid int32) string {
	info, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		return "?"
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "?"
	}
	u, err := user.LookupId(strconv.Itoa(int(stat.Uid)))
	if err != nil {
		return strconv.Itoa(int(stat.Uid))
	}
	return u.Username
}

// ─── Shell quoting (mirrors print_shquoted in C) ──────────────────────────────

// shQuote returns s shell-quoted if it contains any unsafe characters.
func shQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, c := range s {
		if c <= ' ' || strings.ContainsRune("`^#*[]=|\\?${}()'\"<>&;\x7f", c) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	var sb strings.Builder
	sb.WriteByte('\'')
	for _, c := range s {
		if c == '\'' {
			sb.WriteString("'\\''")
		} else if c == '\n' {
			sb.WriteString("'$'\\n''")
		} else {
			sb.WriteRune(c)
		}
	}
	sb.WriteByte('\'')
	return sb.String()
}

// ─── Signal names ─────────────────────────────────────────────────────────────

func sigName(sig int) string {
	names := map[int]string{
		1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL",
		5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE",
		9: "SIGKILL", 10: "SIGUSR1", 11: "SIGSEGV", 12: "SIGUSR2",
		13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM", 17: "SIGCHLD",
		18: "SIGCONT", 19: "SIGSTOP", 20: "SIGTSTP", 21: "SIGTTIN",
		22: "SIGTTOU", 23: "SIGURG", 24: "SIGXCPU", 25: "SIGXFSZ",
		26: "SIGVTALRM", 27: "SIGPROF", 28: "SIGWINCH", 29: "SIGIO",
		30: "SIGPWR", 31: "SIGSYS",
	}
	if name, ok := names[sig]; ok {
		return name
	}
	return fmt.Sprintf("SIG%d", sig)
}

// ─── Error helpers ────────────────────────────────────────────────────────────

func runtimeErr(f string, args ...any) {
	if showErrors {
		fmt.Fprintf(os.Stderr, f+"\n", args...)
	}
}

func fatalf(f string, args ...any) {
	fmt.Fprintf(os.Stderr, "extrace: "+f+"\n", args...)
	os.Exit(1)
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "extrace: "+msg)
	os.Exit(1)
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: extrace [-deflqQtu] [-o FILE] [-p PID | CMD...]")
	fmt.Fprintln(os.Stderr, "  -d    print cwd of process")
	fmt.Fprintln(os.Stderr, "  -e    print environment of process")
	fmt.Fprintln(os.Stderr, "  -f    flat output: no indentation")
	fmt.Fprintln(os.Stderr, "  -l    print full path of argv[0]")
	fmt.Fprintln(os.Stderr, "  -o FILE  log to FILE instead of stdout")
	fmt.Fprintln(os.Stderr, "  -p PID   only trace descendants of PID")
	fmt.Fprintln(os.Stderr, "  -q    suppress arguments")
	fmt.Fprintln(os.Stderr, "  -Q    suppress error messages")
	fmt.Fprintln(os.Stderr, "  -t    show exit status and timing")
	fmt.Fprintln(os.Stderr, "  -u    print user of process")
	os.Exit(1)
}
