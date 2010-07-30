/* Wrapper functions for common socket / network operations */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "socklib.h"
#include "sql.h"
#include "config.h"
#include "common.h"

/* Create a server socket */
int create_socket(char *ip, int port, int sock_type)
{
	int on = 1;
	int sock = 0;
	int proto = 0;
	int addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in serveraddr;

	memset((void *) &serveraddr,0,sizeof(struct sockaddr_in));

	/* Use the right protocol type, if known */
	if(sock_type == SOCK_STREAM){
		proto = IPPROTO_TCP;
	} else if(sock_type == SOCK_DGRAM){
		proto = IPPROTO_UDP;
	}

        if((sock = socket(AF_INET,sock_type,proto)) < 0){
                glog("Socklib: Failed to create socket",LOG_ERROR_TYPE);
                return SOCK_FAIL;
        }

        /* Set this to make sure we don't have problems re-binding the port if the application is
	 * shut down and then re-started in quick succession. 
	 */
        if(setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(int)) < 0){
                glog("Socklib: Failed to set socket option SO_REUSEADDR",LOG_ERROR_TYPE);
		close_socket(sock);
                return SOCK_FAIL;
        }

	/* Set up receive structure for the bind call */
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = inet_addr(ip);
	serveraddr.sin_port = htons(port);

	/* Bind socket to specified port */
	if(bind(sock,(struct sockaddr *) &serveraddr,addrlen) < 0){
		glog("Socklib: Failed to bind port",LOG_ERROR_TYPE);
		close_socket(sock);
		return SOCK_FAIL;
	}

	/* Set TCP socket as a listener */
	if(sock_type == SOCK_STREAM){
		if(listen(sock,MAX_CONNECTIONS) < 0){
			glog("Socklib: Failed to set socket as a listener",LOG_ERROR_TYPE);
			close_socket(sock);
			return SOCK_FAIL;
		}
	}

	return sock;
}

/* Listen for and receive data from a client connection. */
char *receive(int lsock, int sock_type, int *rx_bytes, int csock, struct sockaddr_in *clientaddr)
{
	int recv_size = 0;
	int clen = 0, header_offset = 0;
	int addrlen = sizeof(struct sockaddr_in);
	char *buffer = NULL, *tmp_ptr = NULL, *data_ptr = NULL;
	char *clen_ptr = NULL, *line_end_ptr = NULL;

	*rx_bytes = 0;

	if(sock_type == SOCK_STREAM){

		/* All TCP traffic is HTTP, so receive in a loop until we get to the end of the HTTP data */
		while(1) {

			/* Allocate memory for the incoming data */
			tmp_ptr = buffer;
			if((buffer = realloc(buffer,*rx_bytes+TCP_RECV_SIZE+1)) == NULL){
                        	perror("Realloc failed");
				if(tmp_ptr) free(tmp_ptr);
                        	return NULL;
                	}
                	memset(buffer+*rx_bytes,0,TCP_RECV_SIZE+1);

			/* Receive client request */
			if((recv_size = recv(csock,buffer+*rx_bytes,TCP_RECV_SIZE,0)) < 0){
				glog("Socklib: Failed to read data from TCP socket",LOG_ERROR_TYPE);
				if(buffer) free(buffer);
				return NULL;
			}
			*rx_bytes += recv_size;

			/* Check for Content-Length HTTP header (only needed for POST requests) */
			if((strstr(buffer,HTTP_POST) == buffer) && clen == 0){
				if((clen_ptr = strstr(buffer,HTTP_CONTENT_LENGTH)) != NULL){
			
					/* Point clen_ptr past the CONTENT_LENGTH header */
					clen_ptr += strlen(HTTP_CONTENT_LENGTH);
					/* Skip any trailing white space */
					while(memcmp(clen_ptr,SPACE_STR,SPACE_SIZE) == 0){
						clen_ptr++;
					}

					/* clen_ptr is now pointing at the the CONTENT_LENGTH header value.
					 * Find the line ending and NULL it out to do the strtol() call.
					 */
					if((line_end_ptr = strstr(clen_ptr,CRLF)) != NULL){
						memset(line_end_ptr,0,strlen(CRLF));
						clen = strtol(clen_ptr,NULL,10);
						if(errno == ERANGE){
							glog("Socklib: Failed to convert Content-Length header to an integer",LOG_ERROR_TYPE);
						}
						/* Restore the line ending */
						memcpy(line_end_ptr,CRLF,strlen(CRLF));
					}
				}
			}

			/* Check to see if we've gotten all the HTTP data */
			if((data_ptr = strstr(buffer,HTTP_END_HEADERS)) != NULL){
				if(clen > 0){
					data_ptr += HTTP_END_HEADERS_SIZE;
					header_offset = (int) (data_ptr - buffer);

					/* If we've gotten Content-Length bytes of payload data, then we're done */
					if((*rx_bytes-header_offset) >= clen){
						break;
					}
				} else {
					/* If there was no Content-Length header and we've reached the end of the HTTP headers, then we're done */
					break;
				}
			}
		}

	} else if(sock_type == SOCK_DGRAM) {

		/* Malloc space for the buffer */
		if((buffer = malloc(UDP_RECV_SIZE+1)) == NULL){
                	perror("Malloc failed");
                	return NULL;
        	}
        	memset(buffer,0,UDP_RECV_SIZE+1);

		/* Read in UDP data. We only receive up to UDP_RECV_SIZE, which is sufficient for DNS requests. */
		if((*rx_bytes = recvfrom(lsock,buffer,UDP_RECV_SIZE,0,(struct sockaddr *) clientaddr, (socklen_t *) &addrlen)) < 0){
			glog("Socklib: Failed to read data from UDP socket",LOG_ERROR_TYPE);
			if(buffer) free(buffer);
			return NULL;
		}
	}
	
	/* Return received data */
	return buffer;
}

/* Send an HTTP response to the client socket */
int send_http_response(int csock, char *data, int data_len)
{
	/* Send the headers first */
	if(send_http_response_headers(csock, data_len) == SOCK_OK){

		/* If the headers were sent successfully, send the data */
		if(write(csock,data,(size_t) data_len) != (ssize_t) data_len){
			glog("Socklib: Failed to write HTTP response to client",LOG_ERROR_TYPE);
		} else {
			return SOCK_OK;
		}
	}

	return SOCK_FAIL;
}

/* Send HTTP headers back to client */
int send_http_response_headers(int csock, int clen)
{
	char *headers = NULL;
	char content_length[MAX_CONTENT_LENGTH];
	int headers_len = 0;
	size_t write_len = 0, clen_str_size = 0;

	/* Convert clen to a string */
	memset((void *) &content_length,0,MAX_CONTENT_LENGTH);
	sprintf((char *) &content_length,"%d",clen);
	clen_str_size = strlen(content_length);

	/* Allocate memory for headers */
	headers_len = 	HTTP_OK_SIZE + 
			CRLF_SIZE + 
			XDOMAIN_HEADER_SIZE + 
			CRLF_SIZE + 
			XDOMAIN_METHODS_SIZE + 
			CRLF_SIZE + 
			ALLOWED_METHODS_SIZE + 
			CRLF_SIZE + 
			HTTP_CONTENT_LENGTH_SIZE + 
				SPACE_SIZE + 
				clen_str_size + 
			CRLF_SIZE + 
			HTTP_CONTENT_TYPE_SIZE + 
			CRLF_SIZE + 
			HTTP_NO_CACHE_SIZE + 
			CRLF_SIZE + 
			HTTP_CONNECTION_CLOSE_SIZE +
			HTTP_END_HEADERS_SIZE;

	if((headers = malloc(headers_len+1)) == NULL){
		perror("Malloc failure");
		return SOCK_FAIL;
	}
	memset(headers,0,headers_len+1);
	
	/* Build headers */
	strncpy(headers,HTTP_OK,HTTP_OK_SIZE);
	strncat(headers,CRLF,CRLF_SIZE);
	strncat(headers,XDOMAIN_HEADER,XDOMAIN_HEADER_SIZE);
	strncat(headers,CRLF,CRLF_SIZE);
	strncat(headers,XDOMAIN_METHODS,XDOMAIN_METHODS_SIZE);
	strncat(headers,CRLF,CRLF_SIZE);
	strncat(headers,ALLOWED_METHODS,ALLOWED_METHODS_SIZE);
	strncat(headers,CRLF,CRLF_SIZE);
	strncat(headers,HTTP_CONTENT_LENGTH,HTTP_CONTENT_LENGTH_SIZE);
	strncat(headers,SPACE_STR,SPACE_SIZE);
	strncat(headers,(char *) &content_length,clen_str_size);
	strncat(headers,CRLF,CRLF_SIZE);
	strncat(headers,HTTP_CONTENT_TYPE,HTTP_CONTENT_TYPE_SIZE);
	strncat(headers,CRLF,CRLF_SIZE);
	strncat(headers,HTTP_NO_CACHE,HTTP_NO_CACHE_SIZE);
	strncat(headers,CRLF,CRLF_SIZE);
	strncat(headers,HTTP_CONNECTION_CLOSE,HTTP_CONNECTION_CLOSE_SIZE);
	strncat(headers,HTTP_END_HEADERS,HTTP_END_HEADERS_SIZE);

	/* Write headers back to client */
	write_len = strlen(headers);
	if(write(csock,headers,write_len) != (ssize_t) write_len){
		glog("Socklib: Failed to write HTTP headers to client",LOG_ERROR_TYPE);
		if(headers) free(headers);
		return SOCK_FAIL;
	}

	if(headers) free(headers);
	return SOCK_OK;
}

/* Redirect clients to a random sub-domain of the fqdn */
int send_http_redirect(int csock, char *domain, char *page)
{
        char *three_oh_two = NULL;
        char *headers = "HTTP/1.1 302 Found\r\nLocation: http://";
	char *port = config_get_attack_port();
        int data_len = 0;
	int port_len = 0;
        int headers_len = 0;
	int domain_len = 0;
	int page_len = 0;
        size_t write_len = 0;

	if(port){
		port_len = strlen(port);
	}
	if(headers){
		headers_len = strlen(headers);
	}
	if(domain){
		domain_len = strlen(domain);
	}
	if(page){
		page_len = strlen(page);
	}

        /* Allocate memory for the 302 redirect message buffer */
        data_len = headers_len + HTTP_END_HEADERS_SIZE + page_len + domain_len + COLON_SIZE + port_len;
        if((three_oh_two = malloc(data_len + 1)) == NULL){
                perror("Malloc Failure");
		if(port) free(port);
                return SOCK_FAIL;
        }
        memset(three_oh_two,0,data_len + 1);

        /* Create 302 redirect HTTP message */
        strncpy(three_oh_two,headers,headers_len);
	strncat(three_oh_two,domain,domain_len);
	strncat(three_oh_two,COLON_STR,COLON_SIZE);
	strncat(three_oh_two,port,port_len);
        strncat(three_oh_two,page,page_len);
        strncat(three_oh_two,HTTP_END_HEADERS,HTTP_END_HEADERS_SIZE);

	if(port) free(port);

        /* Write the redirect header to the client socket */
        write_len = strlen(three_oh_two);
        if(write(csock,three_oh_two,write_len) != (ssize_t) write_len){
                glog("Socklib: Failed to send 302 redirect",LOG_ERROR_TYPE);
        	if(three_oh_two) free(three_oh_two);
		return SOCK_FAIL;
        }

        if(three_oh_two) free(three_oh_two);
        return SOCK_OK;
}

/* Obtain the IP address of the given interface */
char *get_interface_ip(char *iface)
{
	int fd = 0;
	struct ifreq ifr;
	char *ip_address = NULL;

	memset((void *) &ifr,0,sizeof(struct ifreq));

	if((fd = socket(AF_INET,SOCK_DGRAM,0)) < 0){
		glog("Socklib: Failed to create socket for ioctl call",LOG_ERROR_TYPE);
		return NULL;
	}

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name,iface,IFNAMSIZ-1);

	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);

	ip_address = strdup(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	if(memcmp(ip_address,NULL_IP_ADDRESS,NULL_IP_ADDRESS_SIZE) == 0){
		if(ip_address) free(ip_address);
		return NULL;
	}
	
	return ip_address;
}

/* Shutdown the specified socket */
int close_socket(int sock)
{
	shutdown(sock,SHUT_RDWR);
	return close(sock);
}
