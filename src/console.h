#define SHELL_PROMPT	"\e[00;32m>\e[00m "
#define TAB_MAX		7
#define SINGLE_TAB	"\t"
#define DOUBLE_TAB	"\t\t"

void console();
int execute(char *cmd);
char *command_generator(char *text, int state);
char **console_completer(char *text, int start, int end);
char **parse_command_line(char *cmd, int *argc);
char *concat_args(int argc, char *argv[], int start);

void console_usage(int argc, char **argv);
void console_config(int argc, char **argv);
void show_config();
void headers(int argc, char **argv);
void help(int argc, char **argv);
void show_all_clients(int argc, char **argv);
void show_inactive_clients(int argc, char **argv);
void show_active_clients(int argc, char **argv);
void show_completed_requests(int argc, char **argv);
void show_pending_requests(int argc, char **argv);
void show_logs(int argc, char **argv);
void show_errors(int argc, char **argv);
void show_dns(int argc, char **argv);
void show_targets();
void show_headers(int argc, char **argv);
void reset(int argc, char **argv);
void save_db(int argc, char **argv);
void targets(int argc, char **argv);
void quit(int argc, char **argv);
