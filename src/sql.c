/* Wrapper functions for common SQLite queries */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sqlite3/sqlite3.h>
#include "common.h"
#include "sql.h"

/* Initialize the sqlite database */
int sql_init()
{
	int result_size = 0;
	int err_code = 0;

	/* Delete the database, if it already exists */
	unlink(SQLITE_DB_NAME);

	/* Open database */
        if(sqlite3_open(SQLITE_DB_NAME,&globals.db)){
                return err_code;
        }

	/* Create DNS table for storing DNS IP addresses */
	sql_exec(SQLITE_CREATE_DNS_TABLE,&result_size,&err_code);
	if(err_code != SQLITE_OK){
		return err_code;
	}

	/* Create queue table for queued browser requests */
	sql_exec(SQLITE_CREATE_QUEUE_TABLE,&result_size,&err_code);
	if(err_code != SQLITE_OK){
		return err_code;
	}

	/* Create the clients table to hold information on active and inactive clients */
	sql_exec(SQLITE_CREATE_CLIENTS_TABLE,&result_size,&err_code);
	if(err_code != SQLITE_OK){
		return err_code;
	}

	/* Create the targets table for holding all of the target IP addresses specified on the command line */
        sql_exec(SQLITE_CREATE_TARGETS_TABLE,&result_size,&err_code);
        if(err_code != SQLITE_OK){
                return err_code;
        }

	/* Create the extension filter table which tells the proxy server which file extensions to ignore */
	sql_exec(SQLITE_CREATE_FILTER_TABLE,&result_size,&err_code);
	if(err_code != SQLITE_OK){
		return err_code;
	}

	/* Create the headers table that will hold user-defined request headers */
	sql_exec(SQLITE_CREATE_HEADERS_TABLE,&result_size,&err_code);
        if(err_code != SQLITE_OK){
                return err_code;
        }

	/* Create the logs table for holding error and message logs */
        sql_exec(SQLITE_CREATE_LOG_TABLE,&result_size,&err_code);
        if(err_code != SQLITE_OK){
                return err_code;
        }

	/* Create the config table for holding configuration data */
        sql_exec(SQLITE_CREATE_CONFIG_TABLE,&result_size,&err_code);
        if(err_code != SQLITE_OK){
                return err_code;
        }

        return SQLITE_OK;
}

/* Execute given SQL query. Will only return the FIRST row of the FIRST column of data. Caller must free the returned pointer. */
void *sql_exec(char *query, int *result_size, int *err_code)
{
	sqlite3_stmt *stmt = NULL;
	int rc = 0, col_type = 0;
	void *result = NULL, *tmp_result = NULL;

	*result_size = 0;

	/* Prepare the SQL query */
	rc = sqlite3_prepare_v2(globals.db,query,strlen(query),&stmt,NULL);
	if(rc != SQLITE_OK){
		*err_code = sqlite3_errcode(globals.db);
		return NULL;
	}

	/* Loop until the query has finished */
	while(((rc = sqlite3_step(stmt)) != SQLITE_DONE) && (result == NULL)){
		switch(rc){

			case SQLITE_ERROR:
				*err_code = sqlite3_errcode(globals.db);
				sqlite3_finalize(stmt);
				return NULL;
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
					case SQLITE_INTEGER:
						tmp_result = (void *) sqlite3_column_text(stmt,0);
						break;
					
					case SQLITE_BLOB:
						tmp_result = (void *) sqlite3_column_blob(stmt,0);
						break;
					
					default:
						continue;
				}

				/* Get the size of the data we just received from the database */
				*result_size = sqlite3_column_bytes(stmt,0);

				/* Create a copy of tmp_result to pass back to the caller */
        			if((tmp_result != NULL) && (*result_size > 0)){
        			        if((result = malloc(*result_size+1)) == NULL){
        			                perror("Malloc failure");
        			                return NULL;
        			        }
        			        memset(result,0,*result_size+1);
        			        memcpy(result,tmp_result,*result_size);
       				}
				break;
			}
		}
	}

	sqlite3_finalize(stmt);
	*err_code = sqlite3_errcode(globals.db);	

	return result;
}

/* Log last SQLite error message */
void sql_log_error()
{
	char *err_msg = sqlite3_mprintf("SQL Error: %s",(char *) sqlite3_errmsg(globals.db));

	glog(err_msg,LOG_ERROR_TYPE);

	sqlite3_free(err_msg);
	return;
}

/* Clean up after ourselves... */
void sql_cleanup()
{
        sqlite3_close(globals.db);
	unlink(SQLITE_DB_NAME);
}
