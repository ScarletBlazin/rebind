/* When a page is requested via the proxy server, the proxy server holds that connection open until it gets a response.
 * To ensure a timely response, the proxy server is notified that the response has arrived via a fifo write, performed
 * by the callback server. These are helper functions just for FIFO creation and use.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sqlite3/sqlite3.h>
#include "sql.h"
#include "fifo.h"
#include "common.h"

/* Create a unique FIFO file to pass the response data back from the client browser to the requestor */
char *create_fifo(char *host_name)
{
        char *fname = NULL, *ret_name = NULL;

        /* Let SQLite handle the memory allocation on this one...we'll just strdup() it so we can use a normal free() later */
        fname = sqlite3_mprintf("%s.%s.%d",FIFO_FILE,host_name,(int) getpid());
        ret_name = strdup(fname);
        sqlite3_free(fname);

        if(!ret_name){
                perror("Malloc failure");
                return NULL;
        }

        if(mkfifo(ret_name,0) < 0){
		if(ret_name) free(ret_name);
                return NULL;
        }

        return ret_name;
}

/* Open fifo file */
FILE *open_fifo(char *fifo, char *mode)
{
	FILE *fd = NULL;

	fd = fopen(fifo,mode);
	if(!fd){
		glog("Failed to open fifo",LOG_ERROR_TYPE);
		return NULL;
	}

	return fd;
}

/* Close fifo file */
void close_fifo(FILE *fd)
{
	fclose(fd);
	return;
}

/* Write ID value to fifo */
void write_to_fifo(int id)
{
	FILE *fd = NULL;
	char *fifo = NULL;
	char *data = NULL;
	char *message = NULL;
	size_t data_size = 0;
	int err_code = 0, response_size = 0;
	char *query = sqlite3_mprintf("SELECT fifo FROM %s WHERE id = '%d'",QUEUE_TABLE,id);

	/* Get the name of the fifo file associated with this id */
	fifo = sql_exec(query,&response_size,&err_code);
	sqlite3_free(query);
	if(err_code != SQLITE_OK || fifo == NULL){
		sql_log_error();
		message = sqlite3_mprintf("Failed to get fifo associated with request id #%d",id);
		glog(message,LOG_ERROR_TYPE);
		sqlite3_free(message);
		return;
	}

	fd = open_fifo(fifo,"w");
	if(!fd){
		message = sqlite3_mprintf("Failed to open fifo %Q",fifo);
		glog(message,LOG_ERROR_TYPE);
		sqlite3_free(message);
		return;
	}

	data = sqlite3_mprintf("%d",id);
	data_size = strlen(data);

	if(fwrite(data,1,data_size,fd) != (size_t) data_size){
		message = sqlite3_mprintf("Failed to write to fifo %Q",fifo);
		glog(message,LOG_ERROR_TYPE);
		sqlite3_free(message);
	}

	close_fifo(fd);
	sqlite3_free(data);
	if(fifo) free(fifo);
	return;
}

/* Read data from FIFO */
int read_from_fifo(char *fifo)
{
        FILE *fd = NULL;
        int bytes_read = 0, id = 0;
        char buffer[MAX_READ_SIZE] = { 0 };

        /* Open fifo */
	fd = open_fifo(fifo,"r");
        if(!fd){
                return 0;
        }

        /* Read id value from fifo */
	bytes_read = fread((char *) &buffer,1,MAX_READ_SIZE,fd);
        if(bytes_read > 0){
		id = atoi((const char *) &buffer);
        }


        close_fifo(fd);
        return id;
}

/* Delete all fifo files */
void fifo_cleanup()
{
        int rc = 0, col_type = 0;
        sqlite3_stmt *stmt = NULL;
        char *fifo = NULL;
	char *query = sqlite3_mprintf("SELECT fifo FROM %s",QUEUE_TABLE);

        /* Prepare the SQL query */
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
                                                fifo = (void *) sqlite3_column_text(stmt,0);
						destroy_fifo(fifo);
                                                break;
                                }
                        }
                }
        }

        sqlite3_finalize(stmt);
	sqlite3_free(query);
        return;
}

/* Delete fifo file */
void destroy_fifo(char *fifo)
{
        unlink(fifo);
}

