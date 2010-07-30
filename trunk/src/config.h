#define COOKIE_NAME		"cookie"
#define ATTACK_PORT_NAME	"attackport"
#define CALLBACK_PORT_NAME	"callbackport"
#define SERVER_IP_NAME		"serverip"
#define PATH_NAME		"path"
#define INTERVAL_NAME		"interval"
#define USER_NAME		"user"
#define PASS_NAME		"password"
#define FQDN_NAME		"fqdn"

void config_set_cookie(char *cookie);
char *config_get_cookie();
void config_set_callback_port(char *port);
char *config_get_callback_port();
void config_set_attack_port(char *port);
char *config_get_attack_port();
void config_set_server_ip(char *ip);
char *config_get_server_ip();
void config_set_path(char *path);
char *config_get_path();
void config_set_interval(char *interval);
char *config_get_interval();
int config_get_connection_timeout();
void config_set_pass(char *pass);
char *config_get_pass();
void config_set_user(char *user);
char *config_get_user();
void config_set_fqdn(char *fqdn);
char *config_get_fqdn();
char *config_get_fqdn_np();
