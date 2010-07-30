#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sql.h"
#include "common.h"

/* Replace first instance of replace in buff with replace_with */
char *str_replace(char *buff, char *replace, char *replace_with)
{
        char *ptr = NULL, *tmp = NULL;
        int bsize = 0, psize = 0, msize = 0, rsize = 0, wsize = 0;

	if(!buff || !replace){
		return buff;
	}

        rsize = strlen(replace);
	if(replace_with){
        	wsize = strlen(replace_with);
	}

        ptr = strstr(buff,replace);
        if(ptr){
                memset(ptr,0,rsize);
                ptr += rsize;
                ptr = strdup(ptr);

                bsize = strlen(buff);
                psize = strlen(ptr);
                msize = bsize + psize + wsize;

                tmp = buff;
                buff = realloc(buff,msize+1);
                if(!buff){
                        perror("Malloc failure");
                        if(tmp) free(tmp);
                        return NULL;
                }
                memset(buff+bsize,0,(msize-bsize)+1);

                strncat(buff,replace_with,wsize);
                strncat(buff,ptr,psize);

                if(ptr) free(ptr);
        }

        return buff;
}

/* Simple function to log messages and errors to the database */
void glog(char *message, int type)
{
	char *query = sqlite3_mprintf("INSERT INTO %s (message,priority) VALUES (%Q,'%d')",LOG_TABLE,message,type);
	int response_size = 0, err_code = 0;

	sql_exec(query,&response_size,&err_code);
	sqlite3_free(query);

	return;
}

/* JavaScript doesn't like newlines, so replace CRLF delimiters with '%%'.
 * Double-percent signs will be converted back into CRLF characters by the
 * client-side JavaScript.
 */
void js_format_headers(char *headers)
{
        int i = 0, hlen = 0;

        hlen = strlen(headers);

        for(i=0; i<hlen; i++){
                if(headers[i] == '\r' || headers[i] == '\n'){
                        headers[i] = PERCENT_SIGN;
                }
        }

        return;
}

/* URL encode characters that might cause JS syntax errors */
char *url_encode(char *buffer)
{
	if(buffer != NULL){
	        while(strstr(buffer,"\r")){
	                buffer = str_replace(buffer,"\r","%0D");
	        }

	        while(strstr(buffer,"\n")){
	                buffer = str_replace(buffer,"\n","%0A");
	        }

	        while(strstr(buffer,"'")){
	                buffer = str_replace(buffer,"'","%27");
	        }

	        while(strstr(buffer,"\"")){
	                buffer = str_replace(buffer,"\"","%22");
	        }
	}

        return buffer;
}

