/* Provides the command-line console for rebind */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "sql.h"
#include "dns.h"
#include "iptables.h"
#include "common.h"
#include "config.h"
#include "console.h"

extern char **completion_matches();
int completer_index;

struct cmd {
        char *name;
	char *arguments;
        Function *func;
        char *desc;
};

struct cmd commands[] = {
        {"active",NULL,(Function *) show_active_clients,"Display a list of all currently active clients"},
        {"clients",NULL,(Function *) show_all_clients,"Display a list of all clients"},
	{"completed",NULL,(Function *) show_completed_requests,"Show completed requests"},
	{"config","[key] [value]",(Function *) console_config,"View and edit payload configuration settings"},
        {"dns",NULL,(Function *) show_dns,"Display current DNS configuration"},
        {"errors",NULL,(Function *) show_errors,"Show all server errors"},
	{"headers","[add|del] [header] [value]",(Function *) headers,"View and edit user-defined HTTP headers"},
        {"help",NULL,(Function *) help,"Show console help"},
        {"inactive",NULL,(Function *) show_inactive_clients,"Display a list of all inactive clients"},
        {"logs",NULL,(Function *) show_logs,"Show all server logs"},
	{"pending",NULL,(Function *) show_pending_requests,"Show pending requests"},
        {"quit",NULL,(Function *) quit,"Quit Rebind"},
	{"reset",NULL,(Function *) reset,"Reset state settings"},
	{"save","[file]",(Function *) save_db,"Save database"},
	{"targets","[add|del] [ip]",(Function *) targets,"View and edit target IP addresses"},
        {NULL,NULL,NULL,NULL}
};

void console()
{	
	static char *line_read = NULL;
	
	completer_index = 0;
	rl_attempted_completion_function = (CPPFunction *)console_completer;

	while(1){

		/* If the buffer has been allocated, free it */
		if(line_read){
			free(line_read);
			line_read = NULL;
		}

		/* Read in command line from the user */
		line_read = readline(SHELL_PROMPT);

		/* If the line has text in it, add it to the history */
		if(line_read && *line_read){
			add_history(line_read);
			if(!execute(line_read)){
				printf("%sERROR: '%s' is not a recognized command! Try 'help'...%s\n",RED,line_read,COLOR_END);
			}
		}
	}

	return;
}

char **console_completer(char *text, int start, int end)
{
	char **matches = NULL;

	if(start == 0){
		matches = completion_matches(text,command_generator);
		end = 0;
	}

	return matches;
}

char *command_generator(char *text, int state)
{
	char *name = NULL;
	int text_len = 0;

	state = 0;
	text_len = strlen(text);

	while((name = commands[completer_index].name) != NULL){

		completer_index++;

		if(strncmp(name,text,text_len) == 0){
			return strdup(name);
		}
		
	}

	completer_index = 0;
	return NULL;
}

int execute(char *cmd)
{
	int i = 0, argc = 0;
	char **argv = NULL;
	Function *func = NULL;

	for(i=0; commands[i].name != NULL; i++){
		if(strncmp(commands[i].name,cmd,strlen(commands[i].name)) == 0){
			func = commands[i].func;
			break;
		}
	}

	if(func != NULL) {

		argv = parse_command_line(cmd,&argc);

		if(argc == 2 && argv[1][0] == '?'){
			console_usage(argc,argv);
		} else {
			func(argc,argv);
		}

		if(argv) free(argv);
		return 1;
	}

	return 0;
}

char **parse_command_line(char *cmd, int *argc)
{
	int i = 0, cmd_len = 0, looking_for_new_argv = 1;
	char **argv = NULL, **tmp = NULL;

	cmd_len = (int) strlen(cmd);

	for(i=0; i<cmd_len; i++){

		if(cmd[i] == ' ' || cmd[i] == '\t'){

			memset(cmd+i,0,1);
			looking_for_new_argv = 1;

		} else if(looking_for_new_argv){

			*argc = *argc + 1;
			tmp = argv;
			argv = realloc(argv,(*argc)*sizeof(char *));
			if(!argv){
				perror("Realloc error");
				*argc = 0;
				if(tmp) free(tmp);
				return NULL;
			}
			argv[*argc-1] = cmd+i;
			looking_for_new_argv = 0;
		}
	}

	return argv;
}

void reset(int argc, char **argv)
{
	char *sql = NULL, *fqdn = NULL, *server_ip = NULL;
	int err_code = 0, response_size = 0;

	/* Clear out the database */
	sql = sqlite3_mprintf("DELETE FROM %s",LOG_TABLE);
	sql_exec(sql,&response_size,&err_code);
	sqlite3_free(sql);
	if(err_code != SQLITE_OK){
		sql_log_error();
	}

	sql = sqlite3_mprintf("DELETE FROM %s",CLIENTS_TABLE);
        sql_exec(sql,&response_size,&err_code);
        sqlite3_free(sql);
        if(err_code != SQLITE_OK){
                sql_log_error();
        }

	sql = sqlite3_mprintf("DELETE FROM %s",QUEUE_TABLE);
        sql_exec(sql,&response_size,&err_code);
        sqlite3_free(sql);
        if(err_code != SQLITE_OK){
                sql_log_error();
        }

	/* Re-initialize the DNS configuration */
	fqdn = config_get_fqdn();
	server_ip = config_get_server_ip();
	init_dns_config(fqdn,server_ip);
	if(fqdn) free(fqdn);
	if(server_ip) free(server_ip);

	/* Clear out the iptables rules */
	iptables_flush();

	printf("%s Reset complete\n",MESSAGE_LINE);
	return;
}

void show_all_clients(int argc, char **argv)
{
	show_active_clients(argc, argv);
	show_inactive_clients(argc, argv);
	return;
}

void show_inactive_clients(int argc, char **argv)
{
	char *query = NULL, *ip = NULL, *timestamp = NULL;
	int rc = 0, col_type = 0;
	sqlite3_stmt *stmt = NULL;

	/* Prepare the SQL query */
        query = sqlite3_mprintf("SELECT ip,callback_time FROM %s WHERE strftime('%%s',callback_time) < strftime('%%s','now') ORDER BY id",CLIENTS_TABLE);
        rc = sqlite3_prepare_v2(globals.db,query,strlen(query),&stmt,NULL);
        if(rc != SQLITE_OK){
		sql_log_error();
		sqlite3_free(query);
                return;
        }

        /* Loop until the query has finished */
        while((rc = sqlite3_step(stmt)) != SQLITE_DONE){
                switch(rc){

                        case SQLITE_ERROR:
				sql_log_error();
                                sqlite3_finalize(stmt);
				sqlite3_free(query);
                                return;

                        case SQLITE_BUSY:
                                /* If the table is locked, wait then try again */
                                usleep(BUSY_WAIT_PERIOD);
                                break;

                        case SQLITE_ROW:
                        {
                                col_type = sqlite3_column_type(stmt,0);
                                switch(col_type)
                                {
                                        case SQLITE_TEXT:
                                                ip = (void *) sqlite3_column_text(stmt,0);
                                                timestamp = (void *) sqlite3_column_text(stmt,1);

						printf("%s %s%s\t\t%s%s\n",ERROR_LINE,DARK_GREY,ip,timestamp,COLOR_END);
                                                break;
  				}
                        }
                }
        }

        sqlite3_finalize(stmt);
        sqlite3_free(query);

	return;
}

void show_active_clients(int argc, char **argv)
{
        char *query = NULL, *ip = NULL, *timestamp = NULL;
        int rc = 0, col_type = 0;
        sqlite3_stmt *stmt = NULL;

        /* Prepare the SQL query */
        query = sqlite3_mprintf("SELECT ip,callback_time FROM %s WHERE strftime('%%s',callback_time) >= strftime('%%s','now') ORDER BY id",CLIENTS_TABLE);
        rc = sqlite3_prepare_v2(globals.db,query,strlen(query),&stmt,NULL);
        if(rc != SQLITE_OK){
		sql_log_error();
		sqlite3_free(query);
                return;
        }

        /* Loop until the query has finished */
        while((rc = sqlite3_step(stmt)) != SQLITE_DONE){
                switch(rc){

                        case SQLITE_ERROR:
				sql_log_error();
                                sqlite3_finalize(stmt);
				sqlite3_free(query);
                                return;

                        case SQLITE_BUSY:
                                /* If the table is locked, wait then try again */
                                usleep(BUSY_WAIT_PERIOD);
                                break;

                        case SQLITE_ROW:
                        {
                                col_type = sqlite3_column_type(stmt,0);
                                switch(col_type)
                                {
                                        case SQLITE_TEXT:
                                                ip = (void *) sqlite3_column_text(stmt,0);
                                                timestamp = (void *) sqlite3_column_text(stmt,1);

                                                printf("%s %s%s\t\t%s%s\n",MESSAGE_LINE,DARK_GREY,ip,timestamp,COLOR_END);
                                                break;
                                }
                        }
                }
        }

        sqlite3_finalize(stmt);
        sqlite3_free(query);

        return;
}

void show_dns(int argc, char **argv)
{
        char *query = NULL, *ip = NULL, *domain = NULL;
        int rc = 0, col_type = 0;
        sqlite3_stmt *stmt = NULL;

        /* Prepare the SQL query */
        query = sqlite3_mprintf("SELECT domain,ip FROM %s",DNS_TABLE);
        rc = sqlite3_prepare_v2(globals.db,query,strlen(query),&stmt,NULL);
        if(rc != SQLITE_OK){
		sql_log_error();
		sqlite3_free(query);
                return;
        }

        /* Loop until the query has finished */
        while((rc = sqlite3_step(stmt)) != SQLITE_DONE){
                switch(rc){

                        case SQLITE_ERROR:
				sql_log_error();
                                sqlite3_finalize(stmt);
				sqlite3_free(query);
                                return;

                        case SQLITE_BUSY:
                                /* If the table is locked, wait then try again */
                                usleep(BUSY_WAIT_PERIOD);
                                break;

                        case SQLITE_ROW:
                        {
                                col_type = sqlite3_column_type(stmt,0);
                                switch(col_type)
                                {
                                        case SQLITE_TEXT:
                                                domain = (void *) sqlite3_column_text(stmt,0);
                                                ip = (void *) sqlite3_column_text(stmt,1);

                                                printf("%s %s%s\t\t%s%s\n",MESSAGE_LINE,DARK_GREY,ip,domain,COLOR_END);
                                                break;
                                }
                        }
                }
        }

        sqlite3_finalize(stmt);
        sqlite3_free(query);

	return;
}

void save_db(int argc, char **argv)
{
	int done = 0, read_size = 0;
	struct stat gstat;
	char *save_file_name = NULL, *file_contents = NULL;
	FILE *fp = NULL;

	if(argc > 1){
		save_file_name = argv[1];
	} else {
		save_file_name = SQLITE_SAVE_NAME;
	}

	if(stat(SQLITE_DB_NAME,&gstat) == 0){
		file_contents = malloc(gstat.st_size);
		if(!file_contents){
			perror("Malloc failure");
			return;
		}
		memset(file_contents,0,gstat.st_size);

		fp = fopen(SQLITE_DB_NAME,"r");
		if(fp){
			read_size = (int) fread(file_contents,1,gstat.st_size,fp);
			fclose(fp);

			if(read_size == gstat.st_size){
				fp = fopen(save_file_name,"w");
				if(fp){
					if(fwrite(file_contents,1,gstat.st_size,fp) == (size_t) gstat.st_size){
						done = 1;
					}
					fclose(fp);
				}
			}
		}

		if(file_contents) free(file_contents);
	}

	if(!done){
		printf("%s Database copy failed!\n",ERROR_LINE);
	} else {
		printf("%s Database saved to '%s'\n",MESSAGE_LINE,save_file_name);
	}

	return;
}

void show_logs(int argc, char **argv)
{
	char *query = NULL, *message = NULL, *timestamp = NULL;
        int rc = 0, col_type = 0;
        sqlite3_stmt *stmt = NULL;

        /* Prepare the SQL query */
        query = sqlite3_mprintf("SELECT message,time FROM %s WHERE priority = '%d' ORDER BY id",LOG_TABLE,LOG_MESSAGE_TYPE);
        rc = sqlite3_prepare_v2(globals.db,query,strlen(query),&stmt,NULL);
        if(rc != SQLITE_OK){
		sql_log_error();
		sqlite3_free(query);
                return;
        }

        /* Loop until the query has finished */
        while((rc = sqlite3_step(stmt)) != SQLITE_DONE){
                switch(rc){

                        case SQLITE_ERROR:
				sql_log_error();
                                sqlite3_finalize(stmt);
				sqlite3_free(query);
                                return;

                        case SQLITE_BUSY:
                                /* If the table is locked, wait then try again */
                                usleep(BUSY_WAIT_PERIOD);
                                break;

                        case SQLITE_ROW:
                        {
                                col_type = sqlite3_column_type(stmt,0);
                                switch(col_type)
                                {
                                        case SQLITE_TEXT:
                                                message = (void *) sqlite3_column_text(stmt,0);
						timestamp = (void *) sqlite3_column_text(stmt,1);

                                                printf("%s %s%s\t\t%s%s\n",MESSAGE_LINE,DARK_GREY,timestamp,message,COLOR_END);
                                                break;
                                }
                        }
                }
        }

        sqlite3_finalize(stmt);
        sqlite3_free(query);

        return;
}

void show_errors(int argc, char **argv)
{
	char *query = NULL, *message = NULL, *timestamp = NULL;
        int rc = 0, col_type = 0;
        sqlite3_stmt *stmt = NULL;

        /* Prepare the SQL query */
        query = sqlite3_mprintf("SELECT message,time FROM %s WHERE priority = '%d' ORDER BY id",LOG_TABLE,LOG_ERROR_TYPE);
        rc = sqlite3_prepare_v2(globals.db,query,strlen(query),&stmt,NULL);
        if(rc != SQLITE_OK){
		sql_log_error();
		sqlite3_free(query);
                return;
        }

        /* Loop until the query has finished */
        while((rc = sqlite3_step(stmt)) != SQLITE_DONE){
                switch(rc){

                        case SQLITE_ERROR:
				sql_log_error();
                                sqlite3_finalize(stmt);
				sqlite3_free(query);
                                return;

                        case SQLITE_BUSY:
                                /* If the table is locked, wait then try again */
                                usleep(BUSY_WAIT_PERIOD);
                                break;

                        case SQLITE_ROW:
                        {
                                col_type = sqlite3_column_type(stmt,0);
                                switch(col_type)
                                {
                                        case SQLITE_TEXT:
                                                message = (void *) sqlite3_column_text(stmt,0);
						timestamp = (void *) sqlite3_column_text(stmt,1);

                                                printf("%s %s%s\t\t%s%s\n",ERROR_LINE,DARK_GREY,timestamp,message,COLOR_END);
                                                break;
                                }
                        }
                }
        }

        sqlite3_finalize(stmt);
        sqlite3_free(query);

        return;
}

void show_pending_requests(int argc, char **argv)
{
	char *query = NULL, *host = NULL, *url = NULL, *pdata = NULL;
        int rc = 0, col_type = 0;
        sqlite3_stmt *stmt = NULL;

        /* Prepare the SQL query */
        query = sqlite3_mprintf("SELECT host,url,pdata FROM %s WHERE id NOT IN (SELECT id FROM queue WHERE length(rdata)) ORDER BY id",QUEUE_TABLE);
        rc = sqlite3_prepare_v2(globals.db,query,strlen(query),&stmt,NULL);
        if(rc != SQLITE_OK){
                sql_log_error();
                sqlite3_free(query);
                return;
        }

        /* Loop until the query has finished */
        while((rc = sqlite3_step(stmt)) != SQLITE_DONE){
                switch(rc){

                        case SQLITE_ERROR:
                                sql_log_error();
                                sqlite3_finalize(stmt);
                                sqlite3_free(query);
                                return;

                        case SQLITE_BUSY:
                                /* If the table is locked, wait then try again */
                                usleep(BUSY_WAIT_PERIOD);
                                break;

                        case SQLITE_ROW:
                        {
                                col_type = sqlite3_column_type(stmt,0);
                                switch(col_type)
                                {
                                        case SQLITE_TEXT:
                                                host = (void *) sqlite3_column_text(stmt,0);
                                                url = (void *) sqlite3_column_text(stmt,1);
						pdata = (void *) sqlite3_column_text(stmt,2);

                                                if(pdata){
                                                        printf("%s %sPOST http://%s%s%s\n",MESSAGE_LINE,DARK_GREY,host,url,COLOR_END);
                                                } else {
                                                        printf("%s %sGET  http://%s%s%s\n",MESSAGE_LINE,DARK_GREY,host,url,COLOR_END);
                                                }

                                                break;
                                }
                        }
                }
        }

        sqlite3_finalize(stmt);
        sqlite3_free(query);

        return;
}

void show_completed_requests(int argc, char **argv)
{
	char *query = NULL, *host = NULL, *url = NULL, *pdata = NULL;         
        int rc = 0, col_type = 0;
        sqlite3_stmt *stmt = NULL;

        /* Prepare the SQL query */
        query = sqlite3_mprintf("SELECT host,url,pdata FROM %s WHERE length(rdata) ORDER BY id",QUEUE_TABLE); 
        rc = sqlite3_prepare_v2(globals.db,query,strlen(query),&stmt,NULL);
        if(rc != SQLITE_OK){
                sql_log_error();
                sqlite3_free(query);
                return;
        }

        /* Loop until the query has finished */
        while((rc = sqlite3_step(stmt)) != SQLITE_DONE){
                switch(rc){ 

                        case SQLITE_ERROR:
                                sql_log_error();
                                sqlite3_finalize(stmt);
                                sqlite3_free(query);
                                return;

                        case SQLITE_BUSY:
                                /* If the table is locked, wait then try again */ 
                                usleep(BUSY_WAIT_PERIOD);
                                break;

                        case SQLITE_ROW:
                        {
                                col_type = sqlite3_column_type(stmt,0);
                                switch(col_type)
                                {
                                        case SQLITE_TEXT:
                                                host = (void *) sqlite3_column_text(stmt,0);
                                                url = (void *) sqlite3_column_text(stmt,1);
                                                pdata = (void *) sqlite3_column_text(stmt,2);
		
						if(pdata){
                                                	printf("%s %sPOST http://%s%s%s\n",MESSAGE_LINE,DARK_GREY,host,url,COLOR_END);
						} else {
                                                	printf("%s %sGET  http://%s%s%s\n",MESSAGE_LINE,DARK_GREY,host,url,COLOR_END);
						}
                                                break;
                                }
                        }
                }
        }

        sqlite3_finalize(stmt);
        sqlite3_free(query);

        return;
}

void show_targets()
{
	char *query = NULL, *ip = NULL, *count = NULL;
        int rc = 0, col_type = 0;
        sqlite3_stmt *stmt = NULL;

        /* Prepare the SQL query */
        query = sqlite3_mprintf("SELECT ip,count FROM %s ORDER BY id",TARGETS_TABLE);
        rc = sqlite3_prepare_v2(globals.db,query,strlen(query),&stmt,NULL);
        if(rc != SQLITE_OK){
                sql_log_error();
                sqlite3_free(query);
                return;
        }

        /* Loop until the query has finished */
        while((rc = sqlite3_step(stmt)) != SQLITE_DONE){
                switch(rc){

                        case SQLITE_ERROR:
                                sql_log_error();
                                sqlite3_finalize(stmt);
                                sqlite3_free(query);
                                return;

                        case SQLITE_BUSY:
                                /* If the table is locked, wait then try again */
                                usleep(BUSY_WAIT_PERIOD);
                                break;

                        case SQLITE_ROW:
                        {
                                col_type = sqlite3_column_type(stmt,0);
                                switch(col_type)
                                {
                                        case SQLITE_TEXT:
                                                ip = (void *) sqlite3_column_text(stmt,0);
                                                count = (void *) sqlite3_column_text(stmt,1);

                                                printf("%s %s(%s)\t%s%s\n",MESSAGE_LINE,DARK_GREY,count,ip,COLOR_END);
                                                break;
                                }
                        }
                }
        }

        sqlite3_finalize(stmt);
        sqlite3_free(query);

        return;
}

void targets(int argc, char **argv)
{
	char *sql = NULL;
	int err_code = 0, result_size = 0;

	if(argc == 1){
		show_targets();
		return;
	} else if(argc != 3){
		console_usage(argc,argv);
		return;
	}
	
	if(argv[1][0] == 'a'){
		sql = sqlite3_mprintf("INSERT INTO %s (ip) VALUES (%Q)",TARGETS_TABLE,argv[2]);
	} else if(argv[1][0] == 'd'){
		sql = sqlite3_mprintf("DELETE FROM %s WHERE ip = %Q",TARGETS_TABLE,argv[2]);
	}

	if(sql){
		sql_exec(sql,&result_size,&err_code);
		if(err_code != SQLITE_OK){
			sql_log_error();
		}
		sqlite3_free(sql);
	}
	
	return;
}

void show_headers(int argc, char **argv)
{
	char *query = NULL, *header = NULL;
        int rc = 0, col_type = 0;
        sqlite3_stmt *stmt = NULL;

        /* Prepare the SQL query */
        query = sqlite3_mprintf("SELECT header FROM %s ORDER BY id",HEADERS_TABLE);
        rc = sqlite3_prepare_v2(globals.db,query,strlen(query),&stmt,NULL);
        if(rc != SQLITE_OK){
                sql_log_error();
                sqlite3_free(query);
                return;
        }

	rc = sqlite3_prepare_v2(globals.db,query,strlen(query),&stmt,NULL);
        if(rc != SQLITE_OK){
                sql_log_error();
                sqlite3_free(query);
                return;
        }

        /* Loop until the query has finished */
        while((rc = sqlite3_step(stmt)) != SQLITE_DONE){
                switch(rc){

                        case SQLITE_ERROR:
                                sql_log_error();
                                sqlite3_finalize(stmt);
                                sqlite3_free(query);
                                return;

                        case SQLITE_BUSY:
                                /* If the table is locked, wait then try again */
                                usleep(BUSY_WAIT_PERIOD);
                                break;

                        case SQLITE_ROW:
                        {
                                col_type = sqlite3_column_type(stmt,0);
                                switch(col_type)
                                {
                                        case SQLITE_TEXT:
                                                header = (void *) sqlite3_column_text(stmt,0);

                                                printf("%s %s%s%s\n",MESSAGE_LINE,DARK_GREY,header,COLOR_END);
                                                break;
                                }
                        }
                }
        }

        sqlite3_finalize(stmt);
        sqlite3_free(query);

        return;
}

void headers(int argc, char **argv)
{
	char *sql = NULL, *header = NULL, *value = NULL;
	int result_size = 0, err_code = 0;

	if(argc == 1){
		show_headers(argc,argv);
		return;
	} else if(argc < 3){
		console_usage(argc,argv);
		return;
	}

	header = argv[2];

	if(argv[1][0] == 'a' && argc >= 4){
		value = concat_args(argc, argv, 3);
		sql = sqlite3_mprintf("INSERT INTO %s (header) VALUES ('%q: %q')",HEADERS_TABLE,header,value);
		if(value) free(value);
	} else if(argv[1][0] == 'd'){
		sql = sqlite3_mprintf("DELETE FROM %s WHERE header LIKE '%q%%'",HEADERS_TABLE,header);
	} else {
		return;
	}

	sql_exec(sql,&result_size,&err_code);
	if(err_code != SQLITE_OK){
		sql_log_error();
	}
	sqlite3_free(sql);

	return;
}

void show_config()
{
	char *query = NULL, *key = NULL, *value = NULL;
        int rc = 0, col_type = 0;
        sqlite3_stmt *stmt = NULL;

        /* Prepare the SQL query */
       query = sqlite3_mprintf("SELECT key,value FROM %s WHERE no_reconfig = 0 ORDER BY key",CONFIG_TABLE);
        rc = sqlite3_prepare_v2(globals.db,query,strlen(query),&stmt,NULL);
        if(rc != SQLITE_OK){
                sql_log_error();
                sqlite3_free(query);
                return;
        }

        /* Loop until the query has finished */
        while((rc = sqlite3_step(stmt)) != SQLITE_DONE){
                switch(rc){

                        case SQLITE_ERROR:
                                sql_log_error();
                                sqlite3_finalize(stmt);
                                sqlite3_free(query);
                                return;

                        case SQLITE_BUSY:
                                /* If the table is locked, wait then try again */
                                usleep(BUSY_WAIT_PERIOD);
                                break;

                        case SQLITE_ROW:
                        {
                                col_type = sqlite3_column_type(stmt,0);
                                switch(col_type)
                                {
                                        case SQLITE_TEXT:
                                                key = (void *) sqlite3_column_text(stmt,0);
                                                value = (void *) sqlite3_column_text(stmt,1);

                                                printf("%s %s%s\t\t%s%s\n",MESSAGE_LINE,DARK_GREY,key,value,COLOR_END);
                                                break;
                                }
                        }
                }
        }

        sqlite3_finalize(stmt);
        sqlite3_free(query);

        return;
}

void console_config(int argc, char **argv)
{
	char *sql = NULL, *key = NULL, *value = NULL;
	int result_size = 0, err_code = 0;

	if(argc == 1){
		show_config();
		return;
	} else if(argc < 3){
		console_usage(argc,argv);
		return;
	}

	key = argv[1];
	value = concat_args(argc, argv, 2);

	sql = sqlite3_mprintf("UPDATE %s SET value = %Q WHERE key = %Q",CONFIG_TABLE,value,key);
	sql_exec(sql,&result_size,&err_code);
	if(err_code != SQLITE_OK){
		sql_log_error();
	}
	if(value) free(value);
	sqlite3_free(sql);

	return;
}

void console_usage(int argc, char **argv)
{
	int i = 0;
	char *args = "";

	if(argc >= 1){
		for(i=0; commands[i].name != NULL; i++){
	                if(strncmp(commands[i].name,argv[0],strlen(commands[i].name)) == 0){
				if(commands[i].arguments != NULL){
	        	                args = commands[i].arguments;
				}
                	        break;
                	}
        	}
                printf("%sUsage: %s %s%s\n",RED,argv[0],args,COLOR_END);		
	}
}

void help(int argc, char **argv)
{
	int i = 0;
	char *name = NULL, *tab = NULL;
	
	while((name = commands[i].name)){
		if(strlen(name) > TAB_MAX){
			tab = SINGLE_TAB;
		} else {
			tab = DOUBLE_TAB;
		}

		printf("\e[00;34m%s\e[00m%s%s%s%s\n",commands[i].name,tab,DARK_GREY,commands[i].desc,COLOR_END);
		i++;
	}

	return;
}

/* Concatenates an array of strings beginning at a given offset */
char *concat_args(int argc, char *argv[], int start)
{
        int i = 0, new_str_size = 0, str_size = 0;
        char *new_str = NULL, *tmp = NULL;

        for(i=start; i<argc; i++){

                str_size = strlen(argv[i]);
                tmp = new_str;

                new_str = realloc(new_str,new_str_size+str_size+SPACE_SIZE+1);
                if(!new_str){
                        if(tmp) free(tmp);
                        new_str = NULL;
                        break;
                }
                tmp = NULL;
                memset(new_str+new_str_size,0,str_size+SPACE_SIZE+1);
                memcpy(new_str+new_str_size,argv[i],str_size);
                memset(new_str+new_str_size+str_size,SPACE,SPACE_SIZE);

                new_str_size += str_size + SPACE_SIZE;
        }

	if(new_str[new_str_size-1] == SPACE){
                memset(new_str+new_str_size-1,0,SPACE_SIZE);
        }

        return new_str;
}

void quit(int argc, char **argv)
{
	kill(globals.parent_pid, SIGINT);
	exit(EXIT_SUCCESS);
}
