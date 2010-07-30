/* By default the rebind.c code blocks any request that ends with a common image file extension. This is done using
 * these helper functions, which store and lookup file extensions in the database. Blocking image requests greatly
 * decreases network bandwidth and page load time.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sqlite3/sqlite3.h>
#include "common.h"
#include "sql.h"

/* Add the extension to the list of extensions to filter. These extensions will not be proxied through the client browser. */
void filter_ext(char *ext)
{
        char *query = sqlite3_mprintf("INSERT INTO %s (extension) VALUES (%Q)",FILTER_TABLE,ext);
	char *message = NULL;
        int result_size = 0, err_code = 0;

        sql_exec(query,&result_size,&err_code);
        sqlite3_free(query);
	if(err_code != SQLITE_OK){
		message = sqlite3_mprintf("Failed to add extension filter for file extension '%s'",ext);
		glog(message,LOG_ERROR_TYPE);
		sqlite3_free(message);
	}

        return;
}

/* Check to see if the requested file type has been marked as filtered in the filter table */
int is_url_filtered(char *url)
{
        char *id = NULL, *query = NULL, *requested_file = NULL, *ext_ptr = NULL;
        int result_size = 0, err_code = 0;

        /* Make a copy of the request */
        requested_file = strdup(url);
        if(!requested_file){
                perror("Malloc failure");
                return 0;
        }

        /* Point ext_ptr to the end of the file name */
        if((ext_ptr = strstr(requested_file,QUESTION_MARK)) == NULL){
                ext_ptr = (requested_file + strlen(requested_file));
        }
        memset(ext_ptr,0,1);

        /* Work backwards from the end of the file name to the first period. That's the extension. */
        while(ext_ptr > requested_file){
                if(memcmp(ext_ptr,PERIOD,PERIOD_SIZE) == 0){
                        break;
                }
                ext_ptr--;
        }

        /* Build and execute the query */
        query = sqlite3_mprintf("SELECT id FROM %s WHERE extension = %Q LIMIT 1",FILTER_TABLE,ext_ptr);
        id = sql_exec(query,&result_size,&err_code);
	if(err_code != SQLITE_OK){
		sql_log_error();
	}

        /* Free memory */
        if(requested_file) free(requested_file);
        if(id) free(id);
        sqlite3_free(query);

        /* Determine result */
        if(result_size != 0){
                return 1;
        }

        return 0;
}
