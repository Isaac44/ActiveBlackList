#include <sys_defs.h>
#include <sys/socket.h>
#include <netinet/in.h>
/*
 * Created by Pablo Marques de Oliveira
 * Year: 2015
 */

#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <netdb.h>
#include <setjmp.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

/* Start of additional includes */
#include <mysql/mysql.h>
#include <stdio.h>
#include <string.h>
/* End of additional includes */

// ... <original code omitted> ... //

/* Start of function that checks if the sender's address is in the spam table */
static int check_spam(char *acount id, char *endSpam)
{
	// create the following query: "select endereco from Spam where account id = 'destinatario' and endSpam = 'remetente'"
	char sql [ ] = "select endereco from Spam where account id = '";
	strcat(sql, acount id );
	strcat(sql, "' and endSpam = '");
	strcat(sql, endSpam);
	strcat(sql, "'");

	// DB connection
	MYSQL DBCon; 		// connection var
	MYSQL RES * result; // result var
	MYSQLROW dados; 	// data var

	mysql_init(&DBCon); // init the connection
	
	// Connect to the DB
	mysql_real_connect(&DBCon, 	"hostIP", "user ", "password", "db ", 0, NULL, 0);
	
	// Query
	mysql_query(&DBCon, sql);

	// Retrieve
	result = mysql_store_result(&DBCon);
	
	// If found...
	if (result) {
		// Free memory
		mysql_free_result(result);
	
		// Close the connection
		mysql_close(&DBCon);
		return 1; // is SPAM
	}
	
	// ... if not...
	// Free memory
	mysql_free_result(result);
	
	// Close the connection
	mysql close(&DBCon);
	return 0; // is HAM (valid)
}
/* End of function that checks if the sender's address is in the spam table */


static int reject_unknown_address(SMTPD_STATE *state, const char *addr, const char *reply_name, const char *reply_class)
{
	const char *myname = "reject unknown address ";
	const RESOLVE REPLY *reply;
	const char *domain;

	const char *account_to_check;   // added
	account_to_check = state−>sender; // added
	if (msg_verbose)
		msg_info("%s : %s ", myname, addr);
	
	/*
	 * Resolve the address.
	 */
	reply = smtpd_resolve_addr(addr);
	if (reply−>flags & RESOLVE_FLAG_FAIL)
		reject_dict_retry(state, addr);
	
	/*
 	 * Skip local destinations and non−DNS forms.
	 */
	if ((domain = strrchr(CONST_STR(reply−>recipient), '@')) == 0)
		return (SMTPD_CHECK_DUNNO);
	
	domain += 1;

	if (reply−>flags & RESOLVE_CLASS_FINAL)
		return (SMTPD_CHECK_DUNNO);
	
	if (domain [0] == '[' && domain[strlen(domain) − 1] == ']')
		return (SMTPD_CHECK_DUNNO);
	
	// Added code
	if (check_spam(account_to_check, addr) == 1)
		return (SMTPD_CHECK_DUNNO);
	
	/*
	 * Look up the name in the DNS.
	 */
	return reject_unknown_mailhost(state, domain, reply name, reply_class);
}