/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Proktikum "Kryptographie und Datensicherheitstechnik"   *
 **                                                           *
 ** Versuch 7: El-gamal-Signatur                              *
 **                                                           *
 **************************************************************
 **
 ** getreport.c: Rahmenprogramm für den Signatur-Versuch
 **/

#include "sign.h"
#include <unistd.h>
#include <getopt.h>
#include <time.h>

static mpz_t p;
static mpz_t w;

void getRegOfMDC(Message *msg, DES_data reg, int is_new) {
    static const DES_key key = {0x7f, 0x81, 0x5f, 0x92, 0x1a, 0x97, 0xaf, 0x18};
    DES_data desout;
    DES_ikey ikey;
    int i, j, len;
    const uint8_t *ptr;

    switch (msg->typ) {
        case ReportRequest:
            ptr = (const uint8_t *) &msg->body.ReportRequest;
            len = sizeof(msg->body.ReportRequest.Name);
            break;
        case ReportResponse:
            ptr = (const uint8_t *) &msg->body.ReportResponse.Report;
            len = sizeof(String) * msg->body.ReportResponse.NumLines;
            break;
        case VerifyRequest:
            ptr = (const uint8_t *) &msg->body.VerifyRequest.Report;
            len = sizeof(String) * msg->body.VerifyRequest.NumLines;
            break;
        case VerifyResponse:
            ptr = (const uint8_t *) &msg->body.VerifyResponse.Res;
            len = sizeof(msg->body.VerifyResponse.Res);
            break;
        default :
            fprintf(stderr, "GENERATE_MDC: Illegaler Typ von Nachricht!\n");
            exit(20);
            break;
    }

    DES_GenKeys(key, 0, ikey);
    for (i = 0; i < DES_DATA_WIDTH; i++) reg[i] = 0;

    /***************   MDC berechnen   ***************/
    while (len >= DES_DATA_WIDTH) {
        DES_Cipher(ikey, reg, desout);
        for (j = 0; j < DES_DATA_WIDTH; j++)
            reg[j] = desout[j] ^ *ptr++;
        len -= DES_DATA_WIDTH;
        if (len == DES_DATA_WIDTH && is_new) {
            return;
        }
    }

}

void toFitMDC(Message *msg, DES_data msg_mdc_reg, DES_data old_msg_mdc_reg) {
    static const DES_key key =
            { 0x7f, 0x81, 0x5f, 0x92, 0x1a, 0x97, 0xaf, 0x18 };
    DES_ikey ikey;
    DES_data desout, last8Bytes;
    int i;

    printf("Beginnen den bestimmten MDC zu erzeugen.\n");

    DES_GenKeys(key, 0, ikey);
    DES_Cipher(ikey, msg_mdc_reg, desout);
    for (i = 0; i < DES_DATA_WIDTH; i++) {
        last8Bytes[i] = old_msg_mdc_reg[i] ^ desout[i];
    }

    int len = msg->body.VerifyRequest.NumLines;
    memcpy((uint8_t*) &(msg->body.VerifyRequest.Report[len]) - DES_DATA_WIDTH,
           last8Bytes, DES_DATA_WIDTH);

}


/*
 * Verify_Sign(mdc,r,s,y) :
 *
 *  überprüft die El-Gamal-Signatur R/S zur MDC. Y ist der öffentliche
 *  Schlüssel des Absenders der Nachricht
 *
 * RETURN-Code: 1, wenn Signatur OK, 0 sonst.
 */
static int Verify_Sign(mpz_t mdc, mpz_t r, mpz_t s, mpz_t y) {
    /*>>>>                                               <<<<*
     *>>>> AUFGABE: Verifizieren einer El-Gamal-Signatur <<<<*
     *>>>>                                               <<<<*/

    mpz_t tmp;
    mpz_init_set_ui(tmp, 0);
    mpz_powm(tmp, y, r, p);

    mpz_t tmp2;
    mpz_init_set_ui(tmp2, 0);
    mpz_powm(tmp2, r, s, p);

    mpz_mul(tmp, tmp, tmp2);
    mpz_mod(tmp, tmp, p);

    mpz_powm(tmp2, w, mdc, p);

    if (mpz_cmp(tmp, tmp2) == 0) {
        mpz_clear(tmp);
        mpz_clear(tmp2);
        return 1;
    }
    mpz_clear(tmp);
    mpz_clear(tmp2);
    return 0;
}

/*
 * Generate_Sign(mdc,r,s,x) : Erzeugt zu der MDC eine El-Gamal-Signatur 
 *    in R und S. X ist der private Schlüssel
 */

static void Generate_Sign(mpz_t mdc, mpz_t r, mpz_t s, mpz_t x) {
    /*>>>>                                           <<<<*
     *>>>> AUFGABE: Erzeugen einer El-Gamal-Signatur <<<<*
     *>>>>                                           <<<<*/
    mpz_t p_1;
    mpz_init_set_ui(p_1, 1);
    mpz_sub(p_1, p, p_1); // p_1 = p - 1

    mpz_t i;
    mpz_init_set_ui(i, 2);

    mpz_t t;
    mpz_init(t);
    mpz_gcd(t, i, p_1);
    while ((mpz_cmp_ui(t, 1) != 0) && (mpz_cmp(i, p_1) < 0)) {
        mpz_add_ui(i, i, 1);
        mpz_gcd(t, i, p_1);
    } // find i with i < p - 1 and gcd(i, p - 1) == 1

    mpz_powm(r, w, i, p); //r = w^k mod p

    mpz_mul(t, r, x);
    mpz_mod(t, t, p_1);
    mpz_sub(t, mdc, t);
    mpz_invert(i, i, p_1); // i = i^(-1) mod p_1
    mpz_mul(t, t, i),
            mpz_mod(s, t, p_1);

    mpz_clear(p_1),
            mpz_clear(i);
    mpz_clear(t);
}

void generateOurMsg(Message *msg) {
    strcpy(msg->body.VerifyRequest.Report[7], "1 bis 7 die erforderliche Punktezahl");
    strcpy(msg->body.VerifyRequest.Report[8], "erreicht. Ein Schein kann daher gewährt");
    strcpy(msg->body.VerifyRequest.Report[9], "werden.");
    strcpy(msg->body.VerifyRequest.Report[11], "\t\t#freeNavalny");
    strcpy(msg->body.VerifyRequest.Report[12], "");
    strcpy(msg->body.VerifyRequest.Report[13], "Diese Auskunft ist elektronisch unterschrieben und");
    strcpy(msg->body.VerifyRequest.Report[14], "daher gültig --- gez. Sign_Daemon");
    msg->body.VerifyRequest.NumLines += 2;
}

int main(int argc, char **argv) {
    Connection con;
    int cnt, ok;
    Message msg;
    mpz_t x, Daemon_y, mdc, sign_r, sign_s;
    const char *OurName;

    mpz_init(x);
    mpz_init(Daemon_y);
    mpz_init(mdc);
    const char *keyfile = NULL;
    char c;
    while ((c = getopt(argc, argv, "f:")) != -1) {
        switch (c) {
            case 'f':
                keyfile = optarg;
                break;
        }
    }

    /**************  Laden der öffentlichen und privaten Daten  ***************/
    if (!Get_Private_Key(keyfile, p, w, x) || !Get_Public_Key(DAEMON_NAME, Daemon_y))
        exit(0);
    /********************  Verbindung zum Dämon aufbauen  *********************/
    OurName = "dmal";
    if (!(con = ConnectTo(OurName, DAEMON_NAME))) {
        fprintf(stderr, "Kann keine Verbindung zum Daemon aufbauen: %s\n", NET_ErrorText());
        exit(20);
    }
    /***********  Message vom Typ ReportRequest initialisieren  ***************/
    msg.typ = ReportRequest;                      /* Typ setzten */
    strcpy(msg.body.ReportRequest.Name, OurName); /* Gruppennamen eintragen */
    Generate_MDC(&msg, p, mdc);                      /* MDC generieren ... */
    Generate_Sign(mdc, sign_r, sign_s, x);          /* ... und Nachricht unterschreiben */
    strcpy(msg.sign_r, mpz_get_str(NULL, 16, sign_r));
    strcpy(msg.sign_s, mpz_get_str(NULL, 16, sign_s));

    /*************  Machricht abschicken, Antwort einlesen  *******************/
    Transmit(con, &msg, sizeof(msg));
    ReceiveAll(con, &msg, sizeof(msg));

    /******************  Überprüfen der Dämon-Signatur  ***********************/
    printf("Nachricht vom Dämon:\n");
    for (cnt = 0; cnt < msg.body.ReportResponse.NumLines; cnt++) {
        printf("\t%s\n", msg.body.ReportResponse.Report[cnt]);
    }

    Generate_MDC(&msg, p, mdc);
    mpz_set_str(sign_r, msg.sign_r, 16);
    mpz_set_str(sign_s, msg.sign_s, 16);
    ok = Verify_Sign(mdc, sign_r, sign_s, Daemon_y);
    if (ok) {
        printf("Dämon-Signatur ist ok!\n");
    } else {
        printf("Dämon-Signatur ist FEHLERHAFT!\n");
    }

    /*>>>>                                      <<<<*
     *>>>> AUFGABE: Fälschen der Dämon-Signatur <<<<*
     *>>>>                                      <<<<*/
    if (!(con = ConnectTo(OurName, DAEMON_NAME))) {
        fprintf(stderr, "Kann keine Verbindung zum Daemon aufbauen: %s\n", NET_ErrorText());
        exit(20);
    }

    DES_data msg_mdc_reg, old_msg_mdc_reg;
    getRegOfMDC(&msg, old_msg_mdc_reg, 0);

    msg.typ = VerifyRequest;
    generateOurMsg(&msg);

    getRegOfMDC(&msg, msg_mdc_reg, 1);
    toFitMDC(&msg, msg_mdc_reg, old_msg_mdc_reg);
    Generate_MDC(&msg, p, mdc);

    printf("Nachricht von mir:\n");
    for (int i = 0; i < msg.body.VerifyRequest.NumLines; i++) {
        printf("\t%s\n", msg.body.VerifyRequest.Report[i]);
    }

    //Generate_MDC_wo_Convert(&msg, p, mdc);
    //strcpy(msg.sign_r, "0");
    //strcpy(msg.sign_s, "0");

    Transmit(con, &msg, sizeof(msg));
    ReceiveAll(con, &msg, sizeof(msg));

    printf("Nachricht vom Dämon:\n");
    printf("\t%s\n", msg.body.VerifyResponse.Res);

    Generate_MDC(&msg, p, mdc);
    mpz_set_str(sign_r, msg.sign_r, 16);
    mpz_set_str(sign_s, msg.sign_s, 16);
    ok = Verify_Sign(mdc, sign_r, sign_s, Daemon_y);
    if (ok) {
        printf("Dämon-Signatur ist ok!\n");
    } else {
        printf("Dämon-Signatur ist FEHLERHAFT!\n");
    }


    mpz_clears(x, Daemon_y, mdc, sign_r, sign_s, NULL);
    return 0;
}
