#include <netinet/in.h>

#define IPV4_ADDR_LEN		0x0004
#define DNS_REPLY_FLAGS		0x8180
#define DNS_REPLY_REFUSED	0x8183
#define DNS_REPLY_NAME		0xC00C
#define DNS_REPLY_TTL		0x0005
#define DNS_CLASS_IN		0x0001
#define DNS_TYPE_A		0x0001
#define DNS_TYPE_NS		0x0002
#define DNS_NUM_ANSWERS		0x0002
#define NAMESERVER_ONE		"ns1"
#define NAMESERVER_TWO		"ns2"
#define WWW			"www"
#define NS_NAME_ONE		"\x03ns1\xC0\x0C"
#define NS_NAME_TWO		"\x03ns2\xC0\x0C"
#define NS_NAME_LEN		0x0006
#define MAX_DNS_QUESTIONS	1

struct dns_header
{
	uint16_t xid;
	uint16_t flags;
	uint16_t num_questions;
	uint16_t num_answers;
	uint16_t num_authority;
	uint16_t num_additional;
};

struct dns_question_section
{
	uint16_t type;
	uint16_t class;
};

struct dns_answer_section
{
	uint16_t name;
	uint16_t type;
	uint16_t class;
	uint16_t ttl_top;
	uint16_t ttl;
	uint16_t data_len;
};

int serve_dns();
int init_dns_config(char *domain, char *ip);
int resolve_ip(char *domain, in_addr_t *ip);
int update_dns_config(char *domain, char *ip);
char *get_domain_in_question(char *dns_packet,int packet_size);
int send_dns_reject(int sock, struct sockaddr_in *clientaddr, char *request_packet, int request_packet_size);
int send_dns_reply(char* question_domain, int sock, struct sockaddr_in *clientaddr, int dns_type, char *dns_packet, int packet_size);
