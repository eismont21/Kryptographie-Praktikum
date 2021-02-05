/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Proktikum "Kryptographie und Datensicherheitstechnik"   *
 **                                                           *
 ** Versuch 7: El-gamal-Signatur                              *
 **                                                           *
 **************************************************************
 **
 ** daemon.c: Signatur-Daemon
 **/

#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include "sign.h"

static mpz_t p;
static mpz_t w;
static int Debug = 1;


/*
 * Verify_Sign(mdc,r,s,y) :
 *
 *  überprüft die El-Gamal-Signatur R/S zur MDC. Y ist der öffentliche
 *  Schlüssel des Absenders der Nachricht
 *
 * RETURN-Code: 1, wenn Signatur OK, 0 sonst.
 */

static int Verify_Sign(mpz_t mdc, mpz_t r, mpz_t s, mpz_t y)
{
	/* Der Rumpf dieser Prozedur wird absichtlich nicht gezeigt! */
}

/*
 * Generate_Sign(m,r,s,x) : Erzeugt zu der MDC M eine El-Gamal-Signatur 
 *    in R und S. X ist der private Schlüssel
 */

static void Generate_Sign(mpz_t mdc, mpz_t r, mpz_t s, mpz_t x)
{
	gmp_randstate_t state;
	gmp_randinit_default(state);
	gmp_randseed_ui(state, time(NULL));
	/* Der Rumpf dieser Prozedur wird absichtlich nicht gezeigt! */
}

static int is_hex(char c){
	return (c>='A' && c<='F') || (c>='a' && c<='f') || (c>='0' && c<='9');
}
static int check_hex_or_space(const char* hex, int max_len){
	while(max_len--){
		if(!is_hex(*hex) && *hex!=' '){
			return *hex=='\0';
		}
		++hex;
	}
	return 0;
}

int DestroySign = 1;

void incrementState(void){
  DestroySign = !DestroySign;
}

/* ----------------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
	char c;
	const char *datafile,*name,*other,*now,*root;
	Connection con;
	PortConnection port;
	Message msg,reply;
	mpz_t Daemon_x, Daemon_y, y, mdc, sign_r, sign_s;
	int i;

	if (!(root=getenv("PRAKTROOT"))) root="";
	datafile =concatstrings(root,"/loesungen/sign_schein/SignSch_Daemon.data",NULL);

	name = DAEMON_NAME;
	Debug = 0;
	setvbuf(stdout,NULL,_IOLBF,0);
	setvbuf(stderr,NULL,_IOLBF,0);

	while ( (c=getopt(argc,argv,"df:n:"))!=-1 ) {
		switch (c) {
			case 'd' :
				Debug = 1;
				break;
			case 'f':
				datafile = optarg;
				break;
			case 'n':
				name = optarg;
				break;
			default:
				fprintf(stderr,"USAGE: signdaemon [-d] [-f datafile]\n");
				exit(5);
				break;
		}
	}

	if (!Get_Private_Key(datafile,p,w,Daemon_x)) {
		fprintf(stderr,"Kann die geheimen Dämon-Daten aus %s nicht lesen.\n",datafile);
		exit(20);
	}
	if (!Get_Public_Key(DAEMON_NAME,Daemon_y)) {
		fprintf(stderr,"Kann die öffentlichen Dämon-Daten nicht lesen.\n");
		exit(20);
	}

	/***************  Globales Port eröffnen  ***************/
	if (!(port=OpenPort(name))) {
		fprintf(stderr,"SIGN_DAEMON: Kann das Dämon-Port \"%s\" nicht erzeugen: %s\n",name,NET_ErrorText());
		exit(20);
	}

	/**************  Auf Verbindung auf dem Port warten  ****************/
	con = WaitAtPort_inc(port, incrementState);
	other = PeerName(con);
	now = Now();

	while(1){
	  /***************  Nachricht entgegennehmen  *****************/
	  ReceiveAll(con,&msg,sizeof(msg));
	  if (msg.typ == ReportRequest) {
	    reply.typ = ReportResponse;
	    if(!check_hex_or_space(msg.sign_r, sizeof(msg.sign_r)) || !check_hex_or_space(msg.sign_s, sizeof(msg.sign_s))){
	      fprintf(stderr, "%s <%s>: Ungültige Zeichen in Signatur\n",now,other);
	      strcpy(reply.body.ReportResponse.Report[0], "Ungültige zeichen in der Signatur");
	      reply.body.ReportResponse.NumLines = 1;
	    } else {
	      Generate_MDC(&msg,p,mdc);
	      mpz_set_str(sign_r, msg.sign_r, 16);
	      mpz_set_str(sign_s, msg.sign_s, 16);
	      if (!Get_Public_Key(msg.body.ReportRequest.Name,y)) {
		printf("%s <%s>: Unbekannter Benutzer \"%s\"\n",now,other,msg.body.ReportRequest.Name);
		sprintf(reply.body.ReportResponse.Report[0],"Benutzer %s ist unbekannt",
			msg.body.ReportRequest.Name);
		reply.body.ReportResponse.NumLines = 1;
	      }
	      // else if (NBITS(&msg.sign_r)!=NBITS(&y) || NBITS(&msg.sign_s)!=NBITS(&y)) {
	      /* TODO: do we even need this any more?
		 else if (mpz_sizeinbase(msg.sign_r, 2) != mpz_sizeinbase(y, 2) || mpz_sizeinbase(msg.sign_s, 2) != mpz_sizeinbase(y, 2)) {
		 printf("%s <%s>: R oder S keine gültige Langzahl\n",now,other);
		 strcpy(reply.body.ReportResponse.Report[0],"R oder S ist keine gültige Langzahl!");
		 reply.body.ReportResponse.NumLines = 1;
		 }
	      */
	      else if (!Verify_Sign(mdc,sign_r,sign_s,y)) {
		printf("%s <%s>: Ungültige Signatur über %s\n",now,other,msg.body.ReportRequest.Name);
		printf("\tR = %s\n",msg.sign_r);
		printf("\tS = %s\n",msg.sign_s);
		strcpy(reply.body.ReportResponse.Report[0],"Signatur ist nicht gültig!");
		reply.body.ReportResponse.NumLines = 1;
	      } else {
		fprintf(stderr, "%s <%s>: Signatur OK, Reply mit %sgültiger Signatur wird erzeugt\n",
			now,other,DestroySign?"un":"");
		strcpy(reply.body.ReportResponse.Report[0],"  **********************************************");
		strcpy(reply.body.ReportResponse.Report[1],"  * Auskunft über den Punktestand im Praktikum *");
		strcpy(reply.body.ReportResponse.Report[2],"  *  Kryptographie und Datensicherheitstechnik *");
		strcpy(reply.body.ReportResponse.Report[3],"  **********************************************");
		strcpy(reply.body.ReportResponse.Report[4]," ");
		sprintf(reply.body.ReportResponse.Report[5]," Stand: %s",now);
		sprintf(reply.body.ReportResponse.Report[6],"Der Teilnehmer %s hat in den Versuchen",
			msg.body.ReportRequest.Name);
		strcpy(reply.body.ReportResponse.Report[7],"1 bis 7 noch NICHT die erforderliche Punkte-");
		strcpy(reply.body.ReportResponse.Report[8],"zahl erreicht. Ein Schein kann daher nicht");
		strcpy(reply.body.ReportResponse.Report[9],"gewährt werden.");
		reply.body.ReportResponse.NumLines = 10;
		
		if (!DestroySign) {
		  strcpy(reply.body.ReportResponse.Report[10]," ");
		  strcpy(reply.body.ReportResponse.Report[11],"Diese Auskunft ist elektronisch unterschrieben und");
		  strcpy(reply.body.ReportResponse.Report[12],"daher gültig --- gez. Sign_Daemon");
		  reply.body.ReportResponse.NumLines = 13;
		}
	      }
	    }
	  } /* of 'if (msg.typ == ReportRequest)' */
	  else if (msg.typ == VerifyRequest) {
	    reply.typ = VerifyResponse;
	    if(!check_hex_or_space(msg.sign_r, sizeof(msg.sign_r)) || !check_hex_or_space(msg.sign_s, sizeof(msg.sign_s))){
	      fprintf(stderr, "%s <%s>: Ungültige Zeichen in Signatur\n",now,other);
	      strcpy(reply.body.VerifyResponse.Res, "Ungültige zeichen in der Signatur");
	    } else if(msg.body.VerifyRequest.NumLines < 0 || msg.body.VerifyRequest.NumLines > MaxLines){
	      fprintf(stderr, "%s <%s>: Ungültige Zeilenanzahl\n",now,other);
	      strcpy(reply.body.VerifyResponse.Res, "Ungültige Zeilenanzahl");
	    } else {
	      Generate_MDC(&msg,p,mdc);
	      mpz_set_str(sign_r, msg.sign_r, 16);
	      mpz_set_str(sign_s, msg.sign_s, 16);
	      if (Verify_Sign(mdc, sign_r, sign_s, Daemon_y)) {
		strcpy(reply.body.VerifyResponse.Res,"Reply:  Die Daemon-Signatur ist gültig.");
		printf("%s <%s>: Verify-Request mit gültiger Dämon-Signatur:\n",now,other);
		if (msg.body.VerifyRequest.NumLines==0)
		  printf("aber die Nachricht hat die Laenge 0\n");
		for (i=0; i<msg.body.VerifyRequest.NumLines; i++) {
		  fprintf(stderr, "\t\"");
		  msg.body.VerifyRequest.Report[i][STRINGLEN-1] = '\0';
		  printstring_escaped(stderr, msg.body.VerifyRequest.Report[i], strlen(msg.body.VerifyRequest.Report[i]));
		  fprintf(stderr, "\"\n");
		}
	      } else {
		strcpy(reply.body.VerifyResponse.Res,"Reply:  Die Daemon-Signatur ist UNGÜLTIG!");
		printf("%s <%s>: Verify-Request mit UNGÜLTIGER Dämon-Signatur:\n",now,other);
	      }
	    }
	  } /* of 'else if (msg.typ == VerifyRequest)' */
	  else {
	    reply.typ = ReportResponse;
	    sprintf(reply.body.ReportResponse.Report[0], "Unbekannter Pakettyp von Benutzer %s",
		    msg.body.ReportRequest.Name);
	    reply.body.ReportResponse.NumLines = 1;
	  }
	  
	  /*****************  Reply unterschreiben und zurückschicken  ******************/
	  Generate_MDC(&reply, p, mdc);
	  Generate_Sign(mdc, sign_r, sign_s, Daemon_x);
	  strcpy(reply.sign_r, mpz_get_str(NULL, 16, sign_r));
	  if (DestroySign) mpz_set_ui(sign_s, (mpz_get_ui(sign_s) ^ 0xffffffff));
	  strcpy(reply.sign_s, mpz_get_str(NULL, 16, sign_s));
	  
	  Transmit(con,&reply,sizeof(reply));
	}

	mpz_clears(Daemon_x, Daemon_y, y, mdc, sign_s, sign_r, NULL);
	return 0;
}
