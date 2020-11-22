struct in_addr;

#include <sys/types.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <sys/socket.h>

#include <errno.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "protocol.h"
#include "../include/network.h"

#include "pin.h"

static Connection sd = NULL;

static unsigned char msgbuf[16];

static void invoke(char cmd, int len, int rlen, char *dt, int dt_len){
  if (sd < 0) {
    fprintf(stderr, "Warning: command without connection\n");
    exit(2);
    return;
  }
  msgbuf[0] = cmd;
  Transmit(sd, msgbuf, len);
  if(dt){
    Transmit(sd, dt, dt_len);
  }
  ReceiveAll(sd, msgbuf, rlen);
  if(msgbuf[0] != (cmd | PIN_FLAG_CLIENT)){
    fprintf(stderr, "Fatal: invalid response\n");
    exit(2);
  }
}

void open_connection(char *server_id, int *diff1, int *diff2)
{
	if (sd != NULL) {
		fprintf(stderr, "Fatal: Tried to open connection twice\n");
		exit(2);
	}
	char *name = MakeNetName(NULL);
	sd = ConnectTo(name, "Pin_Daemon");
	free(name);

	memset(msgbuf, 0, 16);
	invoke(CMD_CONN, 1, 5, NULL, 0);
	*diff1 = ntohs(*((short *)(msgbuf+1)));
	*diff2 = ntohs(*((short *)(msgbuf+3)));
}

int try_pins(int pin[], int npin)
{
	char *pinbuf;
	int i;

	pinbuf = malloc(npin*2);
	if (!pinbuf) {
		fprintf(stderr, "Fatal: out of memory\n");
		exit(2);
	}
	for (i = 0; i < npin; i++) {
		*((short *)(pinbuf+2*i)) = htons(pin[i]);
	}
	*((int *)(msgbuf+1)) = htonl(npin);
	invoke(CMD_TRY, 5, 2, pinbuf, 2*npin);
	free(pinbuf);
	if (msgbuf[1] == 0)
		return (-1);
	else if (msgbuf[1] == 1) {
	  ReceiveAll(sd, msgbuf, 4);
	  return ntohl(*((int *)msgbuf));
	} else if (msgbuf[1] == 2) {
	  ReceiveAll(sd, msgbuf, 4);
	  return -1;
	} else {
		fprintf(stderr, "Fatal: invalid response\n");
		exit(2);
	}
}

int try_pin(int pin)
{
	return (1+(try_pins(&pin, 1)));
}

int try_max(void)
{
	invoke(CMD_TRYMAX, 1, 5, NULL, 0);
	return ntohl(*((int *)(msgbuf+1)));
}

void close_connection(void)
{
	invoke(CMD_CLOSE, 1, 1, NULL, 0);
	DisConnect(sd);
	sd = NULL;
}
