#define SLASH				"/"
#define SLASH_SIZE			1
#define SLASH_CHAR			'/'
#define PROTOCOL_DELIMITER		"http://"
#define PROTOCOL_DELIMITER_SIZE		7
#define CONSOLE_HOST			"rebind"
#define CONSOLE_HOST_SIZE		6
#define BODY_BG_PNG_PATH		"/body_bg.png"
#define HEADER_PNG_PATH			"/header.png"
#define HEADER_BG_PNG_PATH		"/header_bg.png"
#define FOOTER_BG_PNG_PATH		"/footer_bg.png"
#define INDEX_PATH			"/"
#define INDEX_PATH_SIZE			1
#define CLIENT_TABLE_HEADERS		"<th>Client IP</th><th>Last Callback Time</th>"
#define CLIENT_TABLE_HEADERS_SIZE	46

int proxy_server();
int is_using_proxy(char *buffer);
char *get_method(char *buffer);
char *get_host_name(char *buffer);
char *get_url(char *buffer);
char *get_headers(char *buffer);
char *get_post_data(char *buffer, int buffer_size, int *data_size);
void show_web_ui(int csock, char *request);
void print_client_list(int csock);
