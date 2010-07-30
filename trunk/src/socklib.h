#include <netinet/in.h>

#define SOCK_FAIL			-1
#define SOCK_OK				0
#define MAX_CONNECTIONS			256
#define TCP_RECV_SIZE			8192
#define UDP_RECV_SIZE			512
#define MAX_CONTENT_LENGTH		1024
#define HTTP_OK                 	"HTTP/1.1 200 OK"
#define HTTP_OK_SIZE            	16
#define XDOMAIN_HEADER			"Access-Control-Allow-Origin: *"
#define XDOMAIN_HEADER_SIZE		31
#define XDOMAIN_METHODS			"Access-Control-Allow-Methods: GET,POST,HEAD,OPTIONS"
#define XDOMAIN_METHODS_SIZE		52
#define ALLOWED_METHODS			"Allow: GET,POST,HEAD,OPTIONS"
#define ALLOWED_METHODS_SIZE		29
#define HTTP_CONNECTION_CLOSE		"Connection: Close"
#define HTTP_CONNECTION_CLOSE_SIZE	18
#define HTTP_NO_CACHE			"Cache-control: no-cache\r\nCache-control: no-store\r\nPragma: no-cache\r\nExpires: 0"
#define HTTP_NO_CACHE_SIZE		79
#define HTTP_CONTENT_TYPE		"Content-Type: text/html"
#define HTTP_CONTENT_TYPE_SIZE		23
#define NULL_IP_ADDRESS			"0.0.0.0"
#define NULL_IP_ADDRESS_SIZE		7

int create_socket(char *ip, int port, int sock_type);
char *receive(int lsock, int sock_type, int *rx_bytes, int csock, struct sockaddr_in *clientaddr);
int send_http_response(int csock, char *data, int data_len);
int send_http_response_headers(int csock, int clen);
int send_http_redirect(int csock, char *domain, char *page);
char *get_interface_ip(char *iface);
char *get_user_defined_headers();
int close_socket(int sock);
