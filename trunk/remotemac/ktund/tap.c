#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h> 
#include <netinet/in.h>
#include <errno.h>
#include "ktund.h"

#define USE_TCP
//#define USE_UDP

#define PORT         4321

#define BUF_SIZE 4096
static char *buf;
static int rx_leftover_bytes;

void
print_bytes(char *b, int n)
{
    int i;
    for (i=0; i<n; i++)
	printf("%02hhx",b[n]);
    printf("\n");
    fflush(0);
}

int
server(int sock, int tap, struct sockaddr_in *client_addr)
{
    int i, maxfd, ret;
    int pkt_len, len;
    fd_set readset, set;
    struct ktund_packet_hdr *pkt_hdr;

    buf = malloc(BUF_SIZE);
    if (!buf) {
	perror("malloc");
	exit(EXIT_FAILURE);
    }

#ifdef USE_TCP
    printf("connected to %s:%d\n", 
	   inet_ntoa(client_addr->sin_addr),
	   ntohs(client_addr->sin_port));
#endif

    if (sock > tap)
	maxfd = sock + 1;
    else
	maxfd = tap + 1;

    FD_ZERO(&set);
    FD_SET(sock, &set);
    FD_SET(tap, &set);

    if(fcntl(sock, F_SETFL, O_NONBLOCK) < 0 )
	perror("fcntl");

    rx_leftover_bytes = 0;
    ret = 1;
    while (1) {
	readset = set;

	if (select(maxfd, &readset, NULL,NULL,NULL) < 0) {
	    perror("select");
	    goto out;
	}
	
	/* tap -> sock */
	if (FD_ISSET(tap, &readset)) {

#if 1
	    pkt_hdr = (struct ktund_packet_hdr *)buf;
	    pkt_hdr->sync = KTUND_SYNC;
	    pkt_hdr->ctl_len = 0;

	    /* read from the tap, leave room for header */
	    len = read(tap, 
		       buf + sizeof(struct ktund_packet_hdr) + pkt_hdr->ctl_len,
		       BUF_SIZE - sizeof(struct ktund_packet_hdr) - pkt_hdr->ctl_len);

	    if (len < 0) {
		if (errno != EAGAIN && errno != EINTR) {
		    perror("read");
		    goto out;
		} else
		    continue;
	    }
	    pkt_hdr->data_len = len;

	    /* length of packet including header, control and data */
	    len = sizeof(struct ktund_packet_hdr) 
		+ pkt_hdr->ctl_len 
		+ pkt_hdr->data_len;
#else
	    len = read(tap, buf, BUF_SIZE);
	    if (len < 0) {
		if (errno != EAGAIN && errno != EINTR) {
		    perror("read");
		    goto out;
		} else
		    continue;
	    }
#endif
#if 0
	    pkt_hdr->data_len = len;
#endif
	    /* write everything to the socket */
	    len = write(sock, buf, len);
	    if (len < 0) {
		if (errno != EAGAIN && errno != EINTR) {
		    perror("write");
		    goto out;
		}
	    }
	}

	/* sock -> tap */
	if (FD_ISSET(sock, &readset)) {

	    /* read from the socket */
	    len = read(sock, buf + rx_leftover_bytes, BUF_SIZE - rx_leftover_bytes);
	    if (!len) break;
	    if (len < 0) {
		if (errno != EAGAIN && errno != EINTR) {
		    perror("read");
		    goto out;
		} else
		    continue;
	    }

	    /* always eat leftovers, else they go bad */
	    len += rx_leftover_bytes;
	    rx_leftover_bytes = 0;

	    /* decode packets.. might get multiple packets */
	    char *bufp = buf;
	    int iter = 0;
	    while (len >= sizeof(struct ktund_packet_hdr)) {

		/* check that it's a valid packet header */
		pkt_hdr = (struct ktund_packet_hdr *)bufp;
		if (pkt_hdr->sync != KTUND_SYNC) {
		    fprintf(stderr, "tap: %d bad sync number %08x\n", iter, pkt_hdr->sync);
		    /* prevent eating bad leftovers (makes you sick) */
		    len = 0;
		    break;
		}
		
		/* check that we have all the data */
		pkt_len = sizeof(struct ktund_packet_hdr) + pkt_hdr->ctl_len + pkt_hdr->data_len;
		if (pkt_len > len) {
		    /*fprintf(stderr, "tap: %d incomplete packet %d > %d\n", iter, pkt_len, len);*/
		    break;
		}

		/* printf("tap: %d got %d bytes of control, %d bytes of data\n",
		   iter, pkt_hdr->ctl_len, pkt_hdr->data_len);*/
#if 1
		/* successfully received a packet, write it to the tap, strip header */
		if ( write(tap,
			   bufp + sizeof(struct ktund_packet_hdr) + pkt_hdr->ctl_len,
			   pkt_hdr->data_len) < 0 ) {
#else
		/* successfully received a packet, write it to the tap */
		/* keep header */
		if ( write(tap, bufp, pkt_len) < 0 ) {
#endif
		    if (errno != EAGAIN && errno != EINTR) {
			perror("write");
			goto out;
		    }
		}

		bufp += pkt_len;
		len -= pkt_len;
		iter++;
		
	    }
	    
	    if (len) {
		/* put away the leftovers */
		if (bufp != buf)
		    memmove(buf, bufp, len);
		rx_leftover_bytes = len;
	    }
	    
	} // if FD_ISSET
    } // while (1)
    ret = 0;    

 out:
    printf("connection closed\n");

    /* clean up */
    close(sock);
    close(tap);

    return ret;
}

main(int argc, char *argv[])
{
    int i, len;
    int tap, sock;
    int port = PORT;
    struct ifreq ifr;
    struct sockaddr_in addr;

    if (argc > 1)
	port = atoi(argv[1]);

    /* open the ethernet tap */
    tap = open("/dev/net/tun", O_RDWR);
    if (tap < 0) {
	perror("open tap");
	exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (ioctl(tap, TUNSETIFF, (void *) &ifr) < 0) {
	perror("ioctl tap");
	exit(1);
    }

    if(fcntl(tap, F_SETFL, O_NONBLOCK) < 0 )
	perror("fcntl");

    /* open the socket */

#ifdef USE_TCP
    sock = socket(PF_INET, SOCK_STREAM, 0);
#else/* USE_UDP */
    sock = socket(PF_INET, SOCK_DGRAM, 0);
#endif
    if (sock < 0) {
	perror("socket");
	exit(1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    i = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)) == -1)
	perror("setsockopt");

    if(fcntl(sock, F_SETFL, O_NONBLOCK) < 0 )
	perror("fcntl");

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
	perror("bind");
	exit(1);
    }
#ifdef USE_TCP
    if (listen(sock, 10) < 0) {
	perror("listen");
	exit(1);
    }
    /* listen for connections */
    printf("listening for TCP connections on port %d...\n", port);
#else /* USE_UDP */
    printf("listening for UDP packets on port %d...\n", port);
#endif
    while (1) {
	struct sockaddr_in client_addr;
	int s;

	sleep(1);
#ifdef USE_TCP
	len = sizeof(client_addr);
	s = accept(sock, (struct sockaddr *)&client_addr, &len);
	if (s == -1)
	    continue;
	switch (fork()) {
	case 0:
	    /* be a server */
	    close(sock);
	    if (server(s, tap, &client_addr)) {
		perror("server");
		exit(-1);
	    }
	    exit(0);	    
	    break;
	case -1:
	    perror("fork");
	default:
	    close(s);
	    break;
	}
#else /* USE_UDP */
        if (server(sock, tap, &client_addr)) {
		perror("server");
		exit(-1);
	}
#endif
    }
	
}

