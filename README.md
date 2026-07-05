# TCP Packet Sniffer (libpcap)

C 언어와 libpcap API를 이용해 네트워크 패킷을 캡처하고, 각 계층의 헤더 정보와 애플리케이션 데이터를 출력하는 간단한 패킷 스니퍼입니다.

TCP 패킷만을 대상으로 하며(UDP 등은 무시), 다음 정보를 출력합니다.

- **Ethernet Header**: 출발지 / 목적지 MAC 주소
- **IP Header**: 출발지 / 목적지 IP 주소
- **TCP Header**: 출발지 / 목적지 포트 번호
- **HTTP Message**: TCP payload(애플리케이션 계층 데이터)

## 요구 사항

- Linux 환경 (Ubuntu 등)
- `gcc`
- `libpcap-dev`

설치 예시:

```sh
sudo apt update
sudo apt install -y gcc libpcap-dev
```

## 빌드

```sh
gcc sniff_improved.c -o sniff_improved -lpcap
```

## 실행

패킷 캡처에는 관리자 권한이 필요합니다.

```sh
sudo ./sniff_improved
```

코드 내부의 캡처 대상 네트워크 인터페이스 이름은 사용 환경에 맞게 수정해야 합니다. `ip link` 또는 `ifconfig` 명령으로 인터페이스 이름을 확인할 수 있습니다.

## 동작 원리

패킷은 `[Ethernet Header][IP Header][TCP Header][Payload]` 순서로 이어져 있는 하나의 연속된 바이트 배열입니다. 스니퍼는 이 배열을 앞에서부터 각 계층의 구조체로 해석해 나가며, 이때 **각 헤더의 길이 정보를 정확히 사용하는 것**이 핵심입니다. IP·TCP 헤더는 옵션 필드 때문에 고정 길이가 아니므로, 길이를 잘못 계산하면 그 뒤에 오는 헤더나 payload의 시작 위치가 어긋나 값이 깨져 보입니다.

### 1. Ethernet Header

캡처된 패킷의 맨 앞이 Ethernet Header입니다. 처음 6바이트가 목적지 MAC, 다음 6바이트가 출발지 MAC, 그다음 2바이트가 상위 프로토콜 타입입니다.

```c
struct ethheader {
    u_char  ether_dhost[6]; /* destination host address */
    u_char  ether_shost[6]; /* source host address */
    u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};
```

패킷 포인터를 구조체 포인터로 캐스팅해 접근합니다. IP 패킷(`ether_type == 0x0800`)만 처리하도록 걸러 줍니다.

```c
struct ethheader *eth = (struct ethheader *)packet;

if (ntohs(eth->ether_type) != 0x0800) {
    return; // not IP
}
```

MAC 주소는 6바이트를 각각 16진수 2자리(`%02x`)로 출력합니다.

```c
printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
    eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
    eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
    eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
    eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
```

### 2. IP Header

IP Header는 Ethernet Header 바로 뒤에 위치하므로, 패킷 포인터에 Ethernet Header 크기(고정 14바이트)를 더해 시작 위치를 얻습니다.

```c
struct ipheader *ip = (struct ipheader *)
                      (packet + sizeof(struct ethheader));
```

이 스니퍼는 TCP만 대상으로 하므로, IP Header의 프로토콜 필드가 TCP가 아니면 처리를 중단합니다.

```c
if (ip->iph_protocol != IPPROTO_TCP) {
    return; // ignore UDP / others
}
```

여기서 중요한 부분이 **IP Header 길이 계산**입니다. IP Header는 옵션 필드 때문에 가변 길이입니다. `iph_ihl`(IHL, Internet Header Length) 필드는 헤더 길이를 32비트(4바이트) 단위로 저장하므로, 실제 바이트 길이를 구하려면 4를 곱합니다.

```c
int ip_header_len = ip->iph_ihl * 4;   // iph_ihl is in 32-bit words
```

옵션이 없는 일반 IP Header는 `iph_ihl` 값이 5이고, 4를 곱하면 20바이트가 됩니다. 이 `ip_header_len` 값은 이후 TCP Header의 시작 위치를 계산할 때 그대로 사용됩니다.

IP 주소는 `struct in_addr` 타입으로 저장되어 있으므로, `inet_ntoa()`로 점 표기법 문자열(예: `192.0.2.1`)로 변환해 출력합니다.

```c
printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));
```

### 3. TCP Header

TCP Header는 IP Header 바로 뒤에 옵니다. IP Header가 가변 길이이므로, 앞서 구한 `ip_header_len`을 더해 시작 위치를 계산합니다. 이 값을 20바이트로 고정해 버리면 IP 옵션이 붙은 패킷에서 포인터가 엉뚱한 위치를 가리키게 됩니다.

```c
struct tcpheader *tcp = (struct tcpheader *)
                        (packet + sizeof(struct ethheader) + ip_header_len);
```

TCP Header 역시 옵션 때문에 가변 길이입니다. 헤더 길이는 `tcp_offx2` 필드의 상위 4비트(data offset)에 32비트 단위로 저장되어 있습니다. `TH_OFF` 매크로가 상위 4비트만 뽑아내며, 여기에 4를 곱하면 바이트 단위 길이가 됩니다.

```c
#define TH_OFF(th)  (((th)->tcp_offx2 & 0xf0) >> 4)

int tcp_header_len = TH_OFF(tcp) * 4;  // data offset is in 32-bit words
```

포트 번호는 네트워크 바이트 오더(빅엔디안)로 저장되어 있으므로 `ntohs()`로 변환한 뒤 출력합니다. 변환하지 않으면 바이트 순서가 뒤집혀 잘못된 값이 나옵니다.

```c
printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));
```

### 4. HTTP Message (Payload)

앞선 세 헤더의 길이를 모두 구했으므로, payload의 시작 위치와 길이를 정확히 계산할 수 있습니다.

**시작 위치**는 세 헤더 길이의 합만큼 패킷 포인터를 이동시켜 얻습니다.

```c
int eth_header_len    = sizeof(struct ethheader);
int total_headers_len = eth_header_len + ip_header_len + tcp_header_len;

const u_char *payload = packet + total_headers_len;
```

**길이**는 IP Header의 `iph_len`(IP 패킷 전체 길이 = IP 헤더 + 데이터)에서 IP 헤더 길이와 TCP 헤더 길이를 빼서 구합니다. `iph_len` 역시 네트워크 바이트 오더이므로 `ntohs()`로 변환합니다.

```c
int ip_total_len = ntohs(ip->iph_len);   // total IP packet length (header + data)
int payload_len  = ip_total_len - ip_header_len - tcp_header_len;
```

즉 다음 관계가 성립합니다.

> (IP 전체 길이) − (IP 헤더 길이) − (TCP 헤더 길이) = (애플리케이션 데이터 길이)

payload가 실제로 존재할 때만 출력합니다. payload는 null로 끝난다는 보장이 없고, 암호화된 트래픽이나 바이너리가 섞여 있을 수 있으므로, 출력 가능한 ASCII(32~126)와 개행·탭 같은 일부 제어문자만 그대로 출력하고 나머지는 `.`으로 치환해 안전하게 표시합니다.

```c
if (payload_len > 0) {
    printf("Payload Length: %d bytes\n", payload_len);
    printf("Message:\n");
    for (int i = 0; i < payload_len; i++) {
        unsigned char c = payload[i];
        if ((c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t')
            putchar(c);
        else
            putchar('.');
    }
    printf("\n");
} else {
    printf("Message: (no payload / not HTTP data)\n");
}
```

## 캡처 필터

`main`에서 pcap 필터 표현식을 지정해 원하는 트래픽만 캡처할 수 있습니다.

```c
char filter_exp[] = "tcp";                  // TCP 전체
// char filter_exp[] = "tcp and ip and port 80";  // 80번 포트 TCP만
```

## 참고 사항

- 평문 HTTP 요청은 payload에 요청 라인(`GET / HTTP/1.1`), 헤더(`Host:`, `User-Agent:` 등)가 그대로 보입니다.
- HTTPS는 TLS로 암호화되어 있어 payload 대부분이 `.`으로 치환되어 출력됩니다.
- 로컬에서 임의의 TCP 트래픽을 만들어 테스트하려면 `nc`(netcat) 등으로 포트를 열고 접속하는 방식을 사용할 수 있습니다. 방화벽(예: `ufw`)이 켜져 있다면 해당 포트를 열어 주어야 합니다.