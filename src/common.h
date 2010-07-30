#include <sqlite3/sqlite3.h>

#define SQLITE_DB_NAME                  "/tmp/rebind.db"
#define SQLITE_SAVE_NAME		"rebind.db"
#define HTTP_GET			"GET"
#define HTTP_GET_SIZE			3
#define HTTP_POST			"POST"
#define HTTP_POST_SIZE 			4
#define HTTP_END_HEADERS		"\r\n\r\n"
#define HTTP_END_HEADERS_SIZE		4
#define CRLF                    	"\r\n"
#define CRLF_SIZE			2
#define HTTP_CONTENT_LENGTH     	"Content-Length:"
#define HTTP_CONTENT_LENGTH_SIZE	15
#define EXEC_REQUEST			"/exec"
#define EXEC_REQUEST_SIZE		5
#define PERIOD				"."
#define PERIOD_SIZE			1
#define QUESTION_MARK			"?"
#define SPACE_STR			" "
#define SPACE_CHAR			' ' 
#define SPACE_SIZE			1
#define COLON				':'
#define COLON_STR			":"
#define COLON_SIZE			1
#define BIT_BUCKET			"/dev/null"
#define DEFAULT_CONNECTION_TIMEOUT	3
#define SHORT_STR_LEN			5
#define DNS_PORT			53
#define PROXY_PORT			664
#define PERCENT_SIGN			'%'
#define MESSAGE_LINE			"\e[00;34m[+]\e[00m"
#define ERROR_LINE			"\e[00;31m[-]\e[00m"
#define DARK_GREY			"\e[01;30m"
#define RED				"\e[00;31m"
#define COLOR_END			"\e[00m"
#define LOG_MESSAGE_TYPE		0
#define LOG_ERROR_TYPE			1
#define MAX_MISSED_CALLBACKS		3

void glog(char *message, int type);
char *str_replace(char *buffer, char *replace, char *replace_with);
void js_format_headers(char *headers);
char *url_encode(char *buffer);

/* These globals are set once, read many */
struct global_variables
{
	pid_t parent_pid;
	pid_t attack_pid;
	pid_t callback_pid;
	pid_t proxy_pid;
	pid_t dns_pid;
	pid_t console_pid;
	sqlite3 *db;
} globals;
