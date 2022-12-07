#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define IP_TCP 6
#define ETH_HLEN 14

const static HTTP_TOK[] = {"HTTP", "GET", "POST"};

// Check it is begin with tok
// Return true if it is.
static inline int my_strstr(const char *src, const char *tok);

/*eBPF program.
  Filter IP and TCP packets, having payload not empty
  and containing "HTTP", "GET", "POST" ... as first bytes of payload
  if the program is loaded as PROG_TYPE_SOCKET_FILTER
  and attached to a socket
  return  0 -> DROP the packet
  return -1 -> KEEP the packet and return it to user space (userspace can read it from the socket_fd )
*/
int http_filter(struct __sk_buff *skb)
{

	u8 *cursor = 0;

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	// filter IP packets (ethernet type = 0x0800)
	if (!(ethernet->type == 0x0800))
	{
		goto DROP;
	}

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
	// filter TCP packets (ip next protocol = 0x06)
	if (ip->nextp != IP_TCP)
	{
		goto DROP;
	}

	u32 tcp_header_length = 0;
	u32 ip_header_length = 0;
	u32 payload_offset = 0;
	u32 payload_length = 0;

	// calculate ip header length
	// value to multiply * 4
	// e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte
	ip_header_length = ip->hlen << 2; // SHL 2 -> *4 multiply

	// check ip header length against minimum
	if (ip_header_length < sizeof(*ip))
	{
		goto DROP;
	}

	// shift cursor forward for dynamic ip header size
	void *_ = cursor_advance(cursor, (ip_header_length - sizeof(*ip)));

	struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

	// calculate tcp header length
	// value to multiply *4
	// e.g. tcp->offset = 5 ; TCP Header Length = 5 x 4 byte = 20 byte
	tcp_header_length = tcp->offset << 2; // SHL 2 -> *4 multiply

	// calculate payload offset and length
	payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
	payload_length = ip->tlen - ip_header_length - tcp_header_length;

	// http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes
	// minimum length of http request is always geater than 7 bytes
	// avoid invalid access memory
	// include empty payload
	if (payload_length < 7)
	{
		goto DROP;
	}

	// load first 7 byte of payload into p (payload_array)
	// direct access to skb not allowed
	unsigned long p[7];
	int i = 0;
	for (i = 0; i < 7; i++)
	{
		p[i] = load_byte(skb, payload_offset + i);
	}
	p[6] = 0;

	// Find HTTP related token
	for (i = 0; i < (sizeof(HTTP_TOK) / sizeof(*HTTP_TOK)); i++)
		if (my_strstr(p, HTTP_TOK[i]))
			goto KEEP;

	// no HTTP match
	goto DROP;

// keep the packet and send it to userspace returning -1
KEEP:
	return -1;

// drop the packet returning 0
DROP:
	return 0;
}

// Check it is begin with tok
// Return true if it is.
static inline int my_strstr(const char *src, const char *tok)
{
	int i = 0;
	for (i = 0; src[i] == tok[i] && (tok[i] != 0); i++)
		;

	return src[i] == 0 || tok[i] == 0;
}