#define IPTABLES		"iptables"
#define IPTABLES_REBIND_CHAIN	"REBIND"
#define IPTABLES_INPUT		"INPUT"
#define IPTABLES_NEW_CHAIN	"--new"
#define IPTABLES_FLUSH		"--flush"
#define IPTABLES_APPEND		"--append"
#define IPTABLES_PROTO		"--proto"
#define IPTABLES_PROTO_TCP	"tcp"
#define IPTABLES_DST_IP		"--destination"
#define IPTABLES_SRC_IP		"--source"
#define IPTABLES_DST_PORT	"--destination-port"
#define IPTABLES_SYN		"--syn"
#define IPTABLES_JUMP		"--jump"
#define IPTABLES_REJECT		"REJECT"
#define IPTABLES_REJECT_WITH	"--reject-with"
#define IPTABLES_ICMP_REJECT	"icmp-port-unreachable"
#define IPTABLES_TCP_RESET	"tcp-reset"
#define IPTABLES_RULE_DELETE	"--delete"
#define IPTABLES_CHAIN_DELETE	"--delete-chain"
#define IPTABLES_FAIL		-1
#define IPTABLES_OK		0

int iptables_exec(char *const args[]);
int iptables_init();
int iptables_flush();
int iptables_block(char *src_ip, char *dst_ip, int dst_port, char *protocol);
int iptables_unblock(char *src_ip, char *dst_ip, int dst_port, char *protocol);
int iptables_destroy();
