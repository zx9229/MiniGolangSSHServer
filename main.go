// Based on server_complex.go at https://github.com/Scalingo/go-ssh-examples/
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"github.com/kr/pty"
	"golang.org/x/crypto/ssh"
)

/*
// Configuration variables
var (
	defaultShell = "sh" // Shell used if the SHELL environment variable isn't set

	// Public keys used for authentication.  Equivalent of the SSH authorized_hosts files
	authPublicKeys = map[string]string{
		"user": "AAAAC3NzaC1lZDI1NTE5AAAAIADi9ZoVZstck6ELY0EIB863kD4qp5i6DYpQJHkwBiEo",
		//"user2": "AAAAC3NzaC1lZDI1NTE5AAAAIADi9ZoVZstck6ELY0EIB863kD4qp5i6DYpQJHkwBiEo",
	}

	// SSH server host identification key
	hostKeyBytes = []byte(`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCbwxBo/3QT+gE3R2U0m71gJvCeLY5wYzaaDBXd6J59HQAAAJDpU9P06VPT
9AAAAAtzc2gtZWQyNTUxOQAAACCbwxBo/3QT+gE3R2U0m71gJvCeLY5wYzaaDBXd6J59HQ
AAAEDJR51JvnXwYB6ZDMIHqtE1ke12AfQ/T0Fc5OZ5FOmiRpvDEGj/dBP6ATdHZTSbvWAm
8J4tjnBjNpoMFd3onn0dAAAACXJvb3RAa2FsaQECAwQ=
-----END OPENSSH PRIVATE KEY-----`)

	sshServerConfig = &ssh.ServerConfig{
		//ServerVersion:     "SSH-2.0-OpenSSH_7.3p1 Debian-1",
		ServerVersion:     "",
		PublicKeyCallback: publicKeyCallback,
	}
)*/

var (
	GlobalConfigData      *ConfigData
	GlobalSshServerConfig *ssh.ServerConfig
	HardCodedHostKey      = `-----BEGIN RSA PRIVATE KEY-----
MIIEoAIBAAKCAQEAkiUqO6yn+UKgQmUvrnv92xsDx8wteFlJeHG5GQUK5fx2gOO2
ZVomv/+ko2lNBtlVNAnjn1jlBRZnKSWs9gpIi2gcjx3ppWp8Ck4m7Eu7vxa/PPU9
EAQ9o0uxGgJE+62wZqPKr3ufr1oCokCWqPBqKW4Qh8Mvhb5Sr9ZGvtygftS0jUMA
25U/qsYV1udoxRkLeD13SRppXPNJLTMTIjSTdvEdKmZfmKM4GGicnkS4JvrR9KpM
CSlOkz6NCW0UBMg45zQ3Kl8qLu5XG4ibsdaMwCnc/ASJzrwUvo0XZ00eo1wNEdHx
RIU6vqtdD1f9lLotYNAaYB6VbkX6lzL+mj1bfwIBIwKCAQA2SFGD4QswsljINDZI
H2zq+2fN3h+EeO9nQC7Ox1vRxCwD/M637kjoOmG5CdrIB5Ss7bryCxM8Z2glOeEo
L7SLjRHsA8vPudZM+HTbbJYxCHLqwX0Uk9xhOV8JqRJO2hzy7GE53XXTapNDlFU3
bz1f2GyKMo3+eeQyrqyQCM3l9qwPjJ1QhO0gncsjAeS/wYkRuxooZCdssSK+hrCs
Ts/OWsvHUU8gjJKuUmEk+e57A5IVlp5WUDAzj4k93X6NUn1wexaCMM5A/M9mK0kJ
4RKCZ8M7w2XPBF0RES7neUUZfsm/QEif5/wpWng2fywKIRjGCCngzxiDo1BerPeR
MstzAoGBAMGYvaUPuHr15HSMyuxRoS4qsFBW4DoiRwueCRPEvfxsr44AFyNdD4SR
IsSt2s4G3MkGgkxg65vhaMVfTYyqoTKNWxzjyeI1eMoNLvP7XbYYqpWhPycHcR4l
nBFDxa6LGTVKpfbP1eA5WsuSf/Xc8RmQKeV38kcTP/dtPmrf2xWLAoGBAMFAz7RB
2Vn6m0NOUncMvZOnqRuZLIoCWS7JSTdmLEAtdH45Ed1aGTxPe760Pyz8T3+gV2kO
oOInBJE+o9AscFIrA92s/jBeL16sgqf+VfOXLNdDt1Ctoa1Dm2B5QPEiY6Trpkqe
yJ/umBLCvLiI0m6ny04BEm7ROqDv+4MMFJhdAoGAY5BhiBa2paMHxulSaugnAczP
tEnvqN5trjQEqxS5eoEJ1AAL5k0d7Gfl/r/PnSgZxnhgRImdveGjmLSriivd33vl
txYQDe+dNLZSqVyz2f4OlhhpnwskO2PMmyorJpCt4OSP3gR8nzNwhfOSQ+34Vkok
LN6Z22j8U1zBA8OVPkcCgYAxsZR+zxqiG97IKhU0jj9ge5HihnkqzWdjzVv4TXkX
0SyVfGOt8pjGXZTZRErCbMP8PyxreMpIyDRf3OhLeSQyYtUbvsUFH4iGDxpIdJnC
S3HuNfvwLKXquZz7jOTQSqvolF317lDYqxEpZUZ4mDYcdEo4oTCgJyxVRQYpAxs9
HwKBgAE/T4oHr2zspJcPCXCphZbwpx8eue4MhqVk72D+VfNm99GfITN9te8WxxhL
puEW8ZV4pJZMKuNpICcixh9CeVUoK+W5wUczmre3+HWoBpXTkNu1Nd1EXMFPMnuK
q1YwWb4VHBqECkkpUsyhtB3t7QycFciEDKdDIujQDHI7dXp4
-----END RSA PRIVATE KEY-----`

//对于HostKey,你可以[ssh-keygen -t rsa -f ./tmprsa]然后将[./tmprsa]文件的内容拷贝到这里来.
)

// An SSH server is represented by a ServerConfig, which holds
// certificate details and handles authentication of ServerConns.

func helpMessage() string {
	LF := "\n"
	message := ""
	message += "show this help." + LF
	message += LF
	message += exampleConfigData()
	return message
}

func main() {
	helpPtr := flag.Bool("help", false, helpMessage())
	dataPtr := flag.String("base64", "", "base64 encoding data of config")
	stdinPtr := flag.Bool("cin", false, "base64 encoding data of config")
	flag.Parse()

	if *helpPtr { //实际上,如果命令行参数里面有-help,应当走不到这里,直接在flag.Parse里面就结束了.
		flag.Usage()
		os.Exit(0)
	}

	var err error

	if *stdinPtr {
		inputReader := bufio.NewReader(os.Stdin)
		if *dataPtr, err = inputReader.ReadString('\n'); err != nil {
			log.Printf("inputReader.ReadString, err=%v", err)
			os.Exit(100)
		}
	}

	if GlobalConfigData, err = calcConfigData(*dataPtr); err != nil {
		log.Printf("calcConfigData, err=%v", err)
		os.Exit(100)
	}

	if len(GlobalConfigData.HostKey) == 0 {
		GlobalConfigData.HostKey = HardCodedHostKey
	}

	hostKey, err := ssh.ParsePrivateKey([]byte(GlobalConfigData.HostKey))
	if err != nil {
		log.Printf("ParsePrivateKey, err=%v", err)
		os.Exit(100)
	}

	GlobalSshServerConfig = GlobalConfigData.sshServerConfig()
	GlobalSshServerConfig.PasswordCallback = tmpPasswordCallback
	GlobalSshServerConfig.AddHostKey(hostKey)

	//sshServerConfig =

	// You can generate a keypair with 'ssh-keygen -t rsa -C "test@example.com"'
	/*privateBytes, err := ioutil.ReadFile("./id_rsa")

	if err != nil {
		log.Fatal("Failed to load private key (./id_rsa)")
	}
	*/
	/*var IPAddress, Port string

	if len(os.Args) == 2 {
		IPAddress = "localhost"
		Port = os.Args[1]
	} else if len(os.Args) == 3 {
		IPAddress = os.Args[1]
		Port = os.Args[2]
	} else {
		fmt.Println("syntax: ")
		fmt.Println("	<IPAddress> <port>  Binds to the specified IP and port")
		fmt.Println("	<port>  			Binds to localhost and the specified port")
		return
	}

	hostKey, err := ssh.ParsePrivateKey(hostKeyBytes)
	if err != nil {
		log.Fatal("Failed to parse host key")
	}

	sshServerConfig.AddHostKey(hostKey)

	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen("tcp4", IPAddress+":"+Port)
	if err != nil {
		log.Fatalf("failed to listen on %s:%s", IPAddress, Port)
	}

	// Accept all connections
	log.Printf("listening on %s:%s", IPAddress, Port)*/
	listener, err := net.Listen("tcp4", GlobalConfigData.Address)
	if err != nil {
		log.Printf("Listen, Address=%v, err=%v", GlobalConfigData.Address, err)
		os.Exit(100)
	}

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			//log.Printf("failed to accept incoming connection (%s)", err)
			log.Printf("listener.Accept, err=%v", err)
			continue
		}
		// Before use, a handshake must be performed on the incoming net.Conn.
		//sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, sshServerConfig)
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, GlobalSshServerConfig)
		if err != nil {
			//log.Printf("failed to handshake (%s)", err)
			log.Printf("ssh.NewServerConn, err=%v", err)
			continue
		}

		// Check remote address
		//log.Printf("new connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		log.Printf("new connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

		// Print incoming out-of-band Requests
		go handleRequests(reqs)
		// Accept all channels
		go handleChannels(chans)
	}
}

func handleRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		log.Printf("recieved out-of-band request: %+v", req)
	}
}

// Start assigns a pseudo-terminal tty os.File to c.Stdin, c.Stdout,
// and c.Stderr, calls c.Start, and returns the File of the tty's
// corresponding pty.
func PtyRun(c *exec.Cmd, tty *os.File) (err error) {
	defer tty.Close()
	c.Stdout = tty
	c.Stdin = tty
	c.Stderr = tty
	c.SysProcAttr = &syscall.SysProcAttr{
		Setctty: true,
		Setsid:  true,
	}
	return c.Start()
}

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if t := newChannel.ChannelType(); t != "session" {
			newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("could not accept channel (%s)", err)
			continue
		}

		// allocate a terminal for this channel
		log.Print("creating pty...")
		// Create new pty
		f, tty, err := pty.Open()
		if err != nil {
			log.Printf("could not start pty (%s)", err)
			continue
		}

		var shell string
		shell = os.Getenv("SHELL")
		if shell == "" {
			//shell = defaultShell
			shell = GlobalConfigData.DefaultShell
		}

		// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
		go func(in <-chan *ssh.Request) {
			for req := range in {
				//log.Printf("%v %s", req.Payload, req.Payload)
				ok := false
				switch req.Type {
				case "exec":
					ok = true
					command := string(req.Payload[4 : req.Payload[3]+4])
					cmd := exec.Command(shell, []string{"-c", command}...)

					cmd.Stdout = channel
					cmd.Stderr = channel
					cmd.Stdin = channel

					err := cmd.Start()
					if err != nil {
						log.Printf("could not start command (%s)", err)
						continue
					}

					// teardown session
					go func() {
						_, err := cmd.Process.Wait()
						if err != nil {
							log.Printf("failed to exit bash (%s)", err)
						}
						channel.Close()
						log.Printf("session closed")
					}()
				case "shell":
					cmd := exec.Command(shell)
					cmd.Env = []string{"TERM=xterm"}
					err := PtyRun(cmd, tty)
					if err != nil {
						log.Printf("%s", err)
					}

					// Teardown session
					var once sync.Once
					close := func() {
						channel.Close()
						log.Printf("session closed")
					}

					// Pipe session to bash and visa-versa
					go func() {
						io.Copy(channel, f)
						once.Do(close)
					}()

					go func() {
						io.Copy(f, channel)
						once.Do(close)
					}()

					// We don't accept any commands (Payload),
					// only the default shell.
					if len(req.Payload) == 0 {
						ok = true
					}
				case "pty-req":
					// Responding 'ok' here will let the client
					// know we have a pty ready for input
					ok = true
					// Parse body...
					termLen := req.Payload[3]
					termEnv := string(req.Payload[4 : termLen+4])
					w, h := parseDims(req.Payload[termLen+4:])
					SetWinsize(f.Fd(), w, h)
					log.Printf("pty-req '%s'", termEnv)
				case "window-change":
					w, h := parseDims(req.Payload)
					SetWinsize(f.Fd(), w, h)
					continue //no response
				case "env":
					log.Printf("%v, %v, %v", req.Type, req.WantReply, parseSshRequestPayload_obsolete(req.Payload))
				}

				if !ok {
					log.Printf("declining %s request...", req.Type)
				}

				req.Reply(ok, nil)
			}
		}(requests)
	}
}

//parseSshRequestPayload_obsolete 我原本想写一个通用解析函数,然后发现"并非所有类型都是一个解析逻辑",比如"pty-req"就不是这个逻辑.
func parseSshRequestPayload_obsolete(data []byte) []string {
	bytes2int := func(byteSlice []byte) int {
		var i int32
		binary.Read(bytes.NewBuffer(byteSlice), binary.BigEndian, &i)
		return int(i)
	}
	strSlice := make([]string, 0)
	for i := 0; i < len(data); {
		sLen := bytes2int(data[i : i+4])
		i += 4
		strSlice = append(strSlice, string(data[i:i+sLen]))
		i += sLen
	}
	return strSlice
}

//tryShowData 和 parseSshRequestPayload_obsolete 的作用差不多.
func tryShowData(data []byte) string {
	message := ""
	for _, b := range data {
		if 32 <= b && b <= 126 {
			message += string(b)
		} else {
			message += "<" + strconv.Itoa(int(b)) + ">"
		}
	}
	return message
}

// =======================

// parseDims extracts two uint32s from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	log.Printf("window resize %dx%d", w, h)
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}

/*
// publicKeyCallback handles SSH key-based authentication
// This function is largely based off of the code in this post: https://lukevers.com/2016/05/01/ssh-as-authentication-for-web-applications
func publicKeyCallback(remoteConn ssh.ConnMetadata, remoteKey ssh.PublicKey) (*ssh.Permissions, error) {
	fmt.Println("Trying to auth user " + remoteConn.User())

	// Is it a valid user?
	authPublicKey, User := authPublicKeys[remoteConn.User()]
	if !User {
		fmt.Println("User does not exist")
		return nil, errors.New("User does not exist")
	}

	authPublicKeyBytes, err := base64.StdEncoding.DecodeString(authPublicKey)
	if err != nil {
		fmt.Println("Could not base64 decode key")
		return nil, errors.New("Could not base64 decode key")
	}

	// Parse public key
	parsedAuthPublicKey, err := ssh.ParsePublicKey([]byte(authPublicKeyBytes))
	if err != nil {
		fmt.Println("Could not parse public key")
		return nil, err
	}

	// Make sure the key types match
	if remoteKey.Type() != parsedAuthPublicKey.Type() {
		fmt.Println("Key types don't match")
		return nil, errors.New("Key types do not match")
	}

	remoteKeyBytes := remoteKey.Marshal()
	authKeyBytes := parsedAuthPublicKey.Marshal()

	// Make sure the key lengths match
	if len(remoteKeyBytes) != len(authKeyBytes) {
		fmt.Println("Key lengths don't match")
		return nil, errors.New("Keys do not match")
	}

	// Make sure every byte of the key matches up
	// TODO: This should be a constant time check
	keysMatch := true
	for i, b := range remoteKeyBytes {
		if b != authKeyBytes[i] {
			keysMatch = false
		}
	}

	if keysMatch == false {
		fmt.Println("Keys don't match")
		return nil, errors.New("Keys do not match")
	}

	return nil, nil
}*/

func tmpPasswordCallback(remoteConn ssh.ConnMetadata, password []byte) (p *ssh.Permissions, err error) {
	log.Println("Trying to auth user " + remoteConn.User())

	for range "1" {
		if GlobalConfigData.UserPwds == nil {
			err = errors.New("User does not exist")
			log.Println(err)
			break
		}
		curPwd, isOk := GlobalConfigData.UserPwds[remoteConn.User()]
		if !isOk {
			err = errors.New("User does not exist")
			log.Println(err)
			break
		}
		if curPwd != string(password) {
			err = errors.New("Incorrect password")
			log.Println(err)
			break
		}
	}

	return
}
