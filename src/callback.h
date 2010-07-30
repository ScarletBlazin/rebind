#define POST_PAGE		"/post"
#define POST_PAGE_SIZE		5
#define POLL_PAGE		"/poll"
#define POLL_PAGE_SIZE		5
#define HTTP_OK			"HTTP/1.1 200 OK"
#define RESPONSE_OK		"OK"
#define RESPONSE_OK_SIZE	2
#define URL_ID			"i="
#define URL_ID_SIZE		2
#define URL_DATA		"&d="
#define URL_DATA_SIZE		3
#define BASE16_TO_10(x) (((x) >= '0' && (x) <= '9') ? ((x) - '0') : (toupper((x)) - 'A' + 10))

int callback_server();
int process_request(char *buffer, int data_len, int csock, struct sockaddr_in *clientaddr);
void write_to_db(int id, char *client_ip_address, char *data, int data_len);
void update_client_list(char *ip);
void send_poll_response(int csock, char *client_ip_address);
char *get_user_defined_headers();
char *url_decode(char *url, int *url_len);
