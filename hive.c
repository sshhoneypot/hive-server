#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libpq-fe.h>
#include <time.h>

#include <stdarg.h>
#include <signal.h>

#define BUFSIZE 4096

/* TODO: Sort out proper app structure in memory in a nice tidy pointer to
 * pass around to each function
 */
typedef struct srvinfo {
	char* logfile;
	char* pidfile;
	int port;
};


char default_logfile[]="/var/log/hive.log";
int default_port=9981;



char* logfile=default_logfile;

void error(char *msg) {
	perror(msg);
	exit(1);
}

void debug(char* msg,...) {
	struct tm *timeptr;
        time_t lt;
        char timestring[100];
	va_list ap;
	FILE *f=fopen(logfile,"a+");

	va_start(ap,msg);

	lt = time(NULL);
        timeptr = localtime(&lt);
        strftime(timestring, 100, "%D %r", timeptr);

	fprintf(f,"%-21s",timestring);

	vfprintf(f,msg,ap);
	fprintf(f,"\n");

	va_end(ap);
	fclose(f);
}

int run_server(int portno) {
	int parentfd; 
	int childfd; 
	int clientlen; 
	struct sockaddr_in serveraddr; 
	struct sockaddr_in clientaddr; 
	struct hostent *hostp; 
	char buf[BUFSIZE]; 
	char *hostaddrp; 
	int optval; 
	int n; 
	PGconn* conn;
	PGresult* res;
	long hostid;
	char qstr[BUFSIZE];
	struct tm *timePtr;
	time_t localTime;
	char timeString[100];
	char *user;
	char *pw;
	char *host;

	debug("Starting server on port %d",portno);

	parentfd=socket(AF_INET, SOCK_STREAM, 0);
	if(parentfd<0) error("ERROR opening socket");

	optval = 1;
	setsockopt(parentfd,SOL_SOCKET,SO_REUSEADDR,(const void *)&optval ,sizeof(int));

	bzero((char *)&serveraddr,sizeof(serveraddr));

	serveraddr.sin_family=AF_INET;
	serveraddr.sin_addr.s_addr=htonl(INADDR_ANY);
	serveraddr.sin_port=htons((unsigned short)portno);

	if(bind(parentfd,(struct sockaddr *)&serveraddr,sizeof(serveraddr))<0) error("ERROR on binding");

	if(listen(parentfd,5)<0) error("ERROR on listen");

 
	clientlen=sizeof(clientaddr);
	while(1) {

		childfd=accept(parentfd,(struct sockaddr *)&clientaddr,&clientlen);
		if(childfd<0) error("ERROR on accept");

		hostp=gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr,sizeof(clientaddr.sin_addr.s_addr),AF_INET);
		if(hostp==NULL) error("ERROR on gethostbyaddr");
		hostaddrp=inet_ntoa(clientaddr.sin_addr);
		if(hostaddrp==NULL) error("ERROR on inet_ntoa");


		hostid=0;
		conn=PQconnectdb("host=localhost dbname=honeypot");
		if(PQstatus(conn)!=CONNECTION_OK) {
			printf("%s\n",PQerrorMessage(conn));
			error("No database connection");
		}

		sprintf(qstr,"select id from ip where ip='%s'",hostaddrp);
                res=PQexec(conn,qstr);
                if(PQntuples(res)==0) {
                        PQclear(res);
                        sprintf(qstr,"select nextval('ipsequence')");
                        res=PQexec(conn,qstr);
			if(PQntuples(res)==0) error("Cannot get id sequence");
                        hostid=atol(PQgetvalue(res,0,0));
                        PQclear(res);
                        sprintf(qstr,"insert into ip(id,ip) values(%d,'%s')",hostid,hostaddrp);
                        res=PQexec(conn,qstr);
                        PQclear(res);

		} else {
                	hostid=atol(PQgetvalue(res,0,0));
			PQclear(res);
		}


		if(hostid==0) {
			debug("Not processing data for invalid host '%s'",hostaddrp);
			n=write(childfd,"0",strlen("0"));
		} else {
			debug("Established connection with host id:%d %s (%s)",hostid,hostp->h_name,hostaddrp);
			bzero(buf,BUFSIZE);
			n=read(childfd,buf,BUFSIZE);
			if(n<0) {
				error("ERROR no data from socket");
				n=write(childfd,"0",strlen("0"));
			} else if(n<10) {
				debug("ERROR packet too small");
				n=write(childfd,"0",strlen("0"));
			} else {
				if(buf[n-1]=='\n') buf[n-1]='\0';
				if(buf[0]==6 && buf[1]==5) {

					host=buf+2;
					user=strchr(host,5);
					if(user==NULL) {
						n=write(childfd,"0",strlen("0"));
						debug("ERROR cannot determine username");
					} else {
						user++;
						pw=strchr(user,5);
						if(pw==NULL) {
							n=write(childfd,"0",strlen("0"));
							debug("ERROR cannot determine password");
						} else {
							pw++;
							strchr(host,5)[0]='\0';
							strchr(user,5)[0]='\0';
							debug("Received %d bytes: %s %s %s",n,host,user,pw);
						        localTime = time(NULL);
		        		        	timePtr = localtime(&localTime);
			                		strftime(timeString, 100, "%D %r", timePtr);

			        	       		sprintf(qstr,
								"insert into attempt (server,ip,stamp,username,password) values (%d,'%s','%s','%s','%s')",
								hostid,host,timeString,user,pw);
							res=PQexec(conn,qstr);
							PQclear(res);

							n=write(childfd,"1",strlen("1"));
						} /* if(pw==NULL) */
					} /* if(user==NULL) */

				} /* if(buf[0]==6 && buf[1]==5) */
			} /* n>5 */
		} /* hostid==0 */
		if(n<0) 
			error("ERROR writing to socket");

		close(childfd);
		PQfinish(conn);
		debug("Connection closed");
	}
}

int usage(int argc,char* argv[]) {
	fprintf(stderr,"USAGE: %s [-d] [-p port]\n",argv[0]);
	fprintf(stderr,"  -d         run in demon mode\n");
	fprintf(stderr,"  -i         show server information\n");
	fprintf(stderr,"  -h         show help and exit\n");
	fprintf(stderr,"  -k         kill server\n");
	fprintf(stderr,"  -l file    log to file [%s]\n",default_logfile);
	fprintf(stderr,"  -p number  run on port number [%d]\n",default_port);
	
	fprintf(stderr,"\n");
	return 0;
}


int write_pid(int pid) {
	FILE* f=fopen("/var/run/beehive.pid","w");
	if(!f) error("Cannot write pid");
	fprintf(f,"%d",pid);
	fflush(f);
	fclose(f);
	return pid;
}

int get_pid() {
	int ret;
	FILE* f=fopen("/var/run/beehive.pid","r");
	if(!f) return 0;
	fscanf(f,"%d",&ret);
	fclose(f);
	return ret;
}

int info() {
	int pid;
	if((pid=get_pid())==0) {
		printf("ERROR: Server not running\n");
		return 1;
	}
	printf("Beehive running with process id [%d]\n",pid);
	printf("Beehive log file [%s]\n",logfile);

	return 0;
}

int kill_server() {
	int pid=get_pid();
	if(pid==0) {
		printf("ERROR: Server not running\n");
		return 1;
	}

	if(kill(pid,9)!=0) {
		printf("ERROR: Failed to kill process id [%d]\n",pid);
		return 1;
	}
	unlink("/var/run/beehive.pid");
	debug("Server process id [%d] dead\n",pid);
	printf("Server process id [%d] dead\n",pid);
	return 0;
}

int main(int argc,char* argv[]) {

	int ct=0;
	int d=0;
	int p=default_port;
	int pid;
	int ret;

	while(++ct<argc) {
		switch(argv[ct][1]) {
			case 'd': d=1; break;
			case 'h': return usage(argc,argv); break;
			case 'k': return kill_server(); break;
			case 'p': p=atoi(argv[++ct]); break;
			case 'l': logfile=argv[++ct]; break;
			case 'i': return info(); break;
		}
	}

	if(get_pid()>0) {
		printf("ERROR: Server already running with process id [%d]\n",get_pid());
		exit(1);
	}

	if(d==0) return run_server(p);
	
	pid=fork();
	if(pid==0) return run_server(p);
	
	debug("Beehive process started with process id [%d]\n",pid);
	return write_pid(pid);
	
}
