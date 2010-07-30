#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "sql.h"
#include "common.h"

void config_set_cookie(char *cookie)
{
	char *sql = NULL;
	int result_size = 0, err_code = 0;

	sql = sqlite3_mprintf("INSERT OR REPLACE INTO %s (key,value) VALUES  (%Q, %Q)",CONFIG_TABLE,COOKIE_NAME,cookie);
        sql_exec(sql,&result_size,&err_code);
        sqlite3_free(sql);
        if(err_code != SQLITE_OK){
                sql_log_error();
        }

	return;
}

char *config_get_cookie()
{
	char *sql = NULL, *cookie = NULL;
        int result_size = 0, err_code = 0;

        sql = sqlite3_mprintf("SELECT value FROM %s WHERE key = %Q LIMIT 1",CONFIG_TABLE,COOKIE_NAME);
        cookie = sql_exec(sql,&result_size,&err_code);
        sqlite3_free(sql);
        if(err_code != SQLITE_OK){
                sql_log_error();
		cookie = NULL;
        }

        return cookie;
}

void config_set_attack_port(char *port)
{
	char *sql = NULL;
        int result_size = 0, err_code = 0;

        sql = sqlite3_mprintf("INSERT OR REPLACE INTO %s (key,value,no_reconfig) VALUES (%Q,%Q,1)",CONFIG_TABLE,ATTACK_PORT_NAME,port);
        sql_exec(sql,&result_size,&err_code);
        sqlite3_free(sql);
        if(err_code != SQLITE_OK){
                sql_log_error();
        }

        return;
}

char *config_get_attack_port()
{
        char *sql = NULL, *port = NULL;
        int result_size = 0, err_code = 0;

        sql = sqlite3_mprintf("SELECT value FROM %s WHERE key = %Q LIMIT 1",CONFIG_TABLE,ATTACK_PORT_NAME);
        port = sql_exec(sql,&result_size,&err_code);
        sqlite3_free(sql);
        if(err_code != SQLITE_OK){
                sql_log_error();
                port = NULL;
	}

        return port;
}

void config_set_callback_port(char *port)
{
        char *sql = NULL;
        int result_size = 0, err_code = 0;

        sql = sqlite3_mprintf("INSERT OR REPLACE INTO %s (key,value,no_reconfig) VALUES (%Q,%Q,1)",CONFIG_TABLE,CALLBACK_PORT_NAME,port);
        sql_exec(sql,&result_size,&err_code);
        sqlite3_free(sql);
        if(err_code != SQLITE_OK){
                sql_log_error();
        }

        return;
}

char *config_get_callback_port()
{
        char *sql = NULL, *port = NULL;
        int result_size = 0, err_code = 0;

        sql = sqlite3_mprintf("SELECT value FROM %s WHERE key = %Q LIMIT 1",CONFIG_TABLE,CALLBACK_PORT_NAME);
        port = sql_exec(sql,&result_size,&err_code);
        sqlite3_free(sql);
        if(err_code != SQLITE_OK){
                sql_log_error();
                port = NULL;
	}

        return port;
}

void config_set_server_ip(char *ip)
{
	char *sql = NULL;
        int result_size = 0, err_code = 0;

        sql = sqlite3_mprintf("INSERT OR REPLACE INTO %s (key,value,no_reconfig) VALUES (%Q,%Q,1)",CONFIG_TABLE,SERVER_IP_NAME,ip);
        sql_exec(sql,&result_size,&err_code);
        sqlite3_free(sql);
        if(err_code != SQLITE_OK){
                sql_log_error();
        }

        return;
}

char *config_get_server_ip()
{
	char *sql = NULL, *ip = NULL;
        int result_size = 0, err_code = 0;

        sql = sqlite3_mprintf("SELECT value FROM %s WHERE key = %Q LIMIT 1",CONFIG_TABLE,SERVER_IP_NAME);
        ip = sql_exec(sql,&result_size,&err_code);
        sqlite3_free(sql);
        if(err_code != SQLITE_OK){
                sql_log_error();
                ip = NULL;
        }

        return ip;
}

void config_set_path(char *path)
{
	char *sql = NULL;
        int result_size = 0, err_code = 0;

	if(path[0] == '/'){
	        sql = sqlite3_mprintf("INSERT OR REPLACE INTO %s (key,value) VALUES (%Q,%Q)",CONFIG_TABLE,PATH_NAME,path);
	} else {
	        sql = sqlite3_mprintf("INSERT OR REPLACE INTO %s (key,value) VALUES (%Q,'/%q')",CONFIG_TABLE,PATH_NAME,path);
	}
        sql_exec(sql,&result_size,&err_code);
        sqlite3_free(sql);
        if(err_code != SQLITE_OK){
                sql_log_error();
        }

        return;
}

char *config_get_path()
{
        char *sql = NULL, *path = NULL;
        int result_size = 0, err_code = 0;

        sql = sqlite3_mprintf("SELECT value FROM %s WHERE key = %Q LIMIT 1",CONFIG_TABLE,PATH_NAME);
        path = sql_exec(sql,&result_size,&err_code);
        sqlite3_free(sql);
        if(err_code != SQLITE_OK){
                sql_log_error();
                path = NULL;
        }

        return path;
}

void config_set_interval(char *interval)
{
	char *sql = NULL;
        int result_size = 0, err_code = 0;

        sql = sqlite3_mprintf("INSERT OR REPLACE INTO %s (key,value) VALUES (%Q,%Q)",CONFIG_TABLE,INTERVAL_NAME,interval);
        sql_exec(sql,&result_size,&err_code);
        sqlite3_free(sql);
        if(err_code != SQLITE_OK){
                sql_log_error();
        }

        return;
}

char *config_get_interval()
{
	char *sql = NULL, *interval = NULL;
        int result_size = 0, err_code = 0;

        sql = sqlite3_mprintf("SELECT value FROM %s WHERE key = %Q LIMIT 1",CONFIG_TABLE,INTERVAL_NAME);
        interval = sql_exec(sql,&result_size,&err_code);
        sqlite3_free(sql);
        if(err_code != SQLITE_OK){
                sql_log_error();
                interval = NULL;
        }

        return interval;
}

int config_get_connection_timeout()
{
	int connection_timeout = 0;
	char *interval = config_get_interval();

	/* If the client misses three callbacks, assume the client is no longer calling back. 
         * The interval is given in milliseconds, but sqlite is used to check the callback time
         * in seconds, so divide by 1000.
         */
	connection_timeout = ((atoi(interval)/1000) * MAX_MISSED_CALLBACKS);
        if(connection_timeout == 0){
                connection_timeout = DEFAULT_CONNECTION_TIMEOUT;
        }

	return connection_timeout;
}

void config_set_pass(char *pass)
{
	char *sql = NULL;
        int result_size = 0, err_code = 0;

        sql = sqlite3_mprintf("INSERT OR REPLACE INTO %s (key,value) VALUES (%Q,%Q)",CONFIG_TABLE,PASS_NAME,pass);
        sql_exec(sql,&result_size,&err_code);
        sqlite3_free(sql);
        if(err_code != SQLITE_OK){
                sql_log_error();
        }

        return;
}

char *config_get_pass()
{
	char *sql = NULL, *pass = NULL;
        int result_size = 0, err_code = 0;

        sql = sqlite3_mprintf("SELECT value FROM %s WHERE key = %Q LIMIT 1",CONFIG_TABLE,PASS_NAME);
        pass = sql_exec(sql,&result_size,&err_code);
        sqlite3_free(sql);
        if(err_code != SQLITE_OK){
                sql_log_error();
                pass = NULL;
        }

        return pass;
}

void config_set_user(char *user)
{
        char *sql = NULL;
        int result_size = 0, err_code = 0;

        sql = sqlite3_mprintf("INSERT OR REPLACE INTO %s (key,value) VALUES (%Q,%Q)",CONFIG_TABLE,USER_NAME,user);
        sql_exec(sql,&result_size,&err_code);
        sqlite3_free(sql);
        if(err_code != SQLITE_OK){
                sql_log_error();
        }

        return;
}

char *config_get_user()
{
        char *sql = NULL, *user = NULL;
        int result_size = 0, err_code = 0;

        sql = sqlite3_mprintf("SELECT value FROM %s WHERE key = %Q LIMIT 1",CONFIG_TABLE,USER_NAME);
        user = sql_exec(sql,&result_size,&err_code);
        sqlite3_free(sql);
        if(err_code != SQLITE_OK){
                sql_log_error();
                user = NULL;
        }

        return user;
}

void config_set_fqdn(char *fqdn)
{
        char *sql = NULL;
        int result_size = 0, err_code = 0;

        sql = sqlite3_mprintf("INSERT OR REPLACE INTO %s (key,value,no_reconfig) VALUES (%Q,%Q,1)",CONFIG_TABLE,FQDN_NAME,fqdn);
        sql_exec(sql,&result_size,&err_code);
        sqlite3_free(sql);
        if(err_code != SQLITE_OK){
                sql_log_error();
        }

        return;
}

char *config_get_fqdn()
{
        char *sql = NULL, *fqdn = NULL, *tmp = NULL;
        int result_size = 0, err_code = 0, fqdn_size = 0;

        sql = sqlite3_mprintf("SELECT value FROM %s WHERE key = %Q LIMIT 1",CONFIG_TABLE,FQDN_NAME);
        fqdn = sql_exec(sql,&result_size,&err_code);
        sqlite3_free(sql);
        if(err_code != SQLITE_OK){
                sql_log_error();
                fqdn = NULL;
        } else if(fqdn){
		tmp = fqdn;
		fqdn_size = strlen(fqdn) + 2;

		fqdn = realloc(fqdn,fqdn_size);
		if(!fqdn){
			perror("Malloc failure");
			if(tmp) free(tmp);
		} else {
			memset((fqdn+fqdn_size-2),'.',1);
			memset((fqdn+fqdn_size-1),'\0',1);
		}
	}

        return fqdn;
}

char *config_get_fqdn_np()
{
        char *sql = NULL, *fqdn = NULL;
        int result_size = 0, err_code = 0;

        sql = sqlite3_mprintf("SELECT value FROM %s WHERE key = %Q LIMIT 1",CONFIG_TABLE,FQDN_NAME);
        fqdn = sql_exec(sql,&result_size,&err_code);
        sqlite3_free(sql);
        if(err_code != SQLITE_OK){
                sql_log_error();
                fqdn = NULL;
        }

        return fqdn;
}
