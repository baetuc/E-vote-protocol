#include "Server.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PORT 2022
extern int errno;

using namespace std;

int main ()
{
    struct sockaddr_in server;
    struct sockaddr_in from;
    int sd;

    if ((sd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror ("Error at creating socket.\n");
        return errno;
    }

    bzero (&server, sizeof (server));
    bzero (&from, sizeof (from));

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl (INADDR_ANY);
    server.sin_port = htons (PORT);

    if (bind (sd, (struct sockaddr *) &server, sizeof (struct sockaddr)) == -1)
    {
        perror ("Error at binding address.\n");
        return errno;
    }
    int on = 1;
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    Server::initialize();
    if (listen (sd, 5) == -1)
    {
        perror ("Error at listening to port.\n");
        return errno;
    }

    while (1)
    {
        int client;
        int length = sizeof (from);

        printf ("We wait at port %d\n", PORT);
        fflush (stdout);

        client = accept (sd, (struct sockaddr *) &from, (socklen_t*)&length);

        if (client < 0)
        {
            perror ("Error at accepting client.\n");
            continue;
        }
        Server::execute(client);
        close (client);
    }
}
