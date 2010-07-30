#define VERSION		"0.3.1"
#define ICO		".ico"
#define GIF		".gif"
#define JPG		".jpg"
#define PNG		".png"
#define BMP		".bmp"
#define PROC_DIR	"/proc"
#define PATH		"PATH"
#define ROOT		0
#define MAX_PATH_SIZE	256

int which(char *file);
void usage(char *prog_name);
int process_exists(int pid);
static void sigint_handler(int signum);
void cleanup();
int parse_target_ips(char *comma_separated_list);
int parse_headers_file(char *file_name);
