#include <praktikum.h>
#include <network.h>

#include <protocol.h>

Connection con;

const int local = 0;
struct rsa_key k;

// returns 1 if the padding is valid and 0 otherwise
int padding_oracle(mpz_t c){
    if(local) {
        mpz_t m;
        mpz_init(m);
        mpz_powm(m, c, k.d, k.N);
        int ret = calc_padding_oracle(m, NULL) != NULL;
        mpz_clear(m);
        return ret;
    }
    oracle_req req;
    enum message_type type = ORACLE_REQ;
    store_mpz(req.c, sizeof(req.c), c);
    Transmit(con, &type, sizeof(type));
    Transmit(con, &req, sizeof(req));
    oracle_rep m;
    ReceiveAll(con, &m, sizeof(m));
    return m.rep;
}

void submit_solution(mpz_t m){
    if(local){
        printf("Skipping submition, because running in offline mode.\n");
        return;
    } else {
        solution sol;
        store_mpz(sol.m, sizeof(sol.m), m);
        enum message_type type = SOLUTION;
        Transmit(con, &type, sizeof(type));
        Transmit(con, &sol, sizeof(sol));
        solution_rep m;
        ReceiveAll(con, &m, sizeof(m));
        if(m.state == 0){
            printf("Solution was accepted\n");
            const char *now = Now();
            printf("Solution submitted at %s\n", now);
        }else{
            printf("Solution was rejected\n");
        }
    }
}

int main (int argc, char *argv[]){
    mpz_t N, e, c;
    mpz_init(N); mpz_init(e); mpz_init(c);

    if(local){
        genkey(&k);
        mpz_t m;
        mpz_init(m);
        pad_and_import(m, "This is the secret test message");
        mpz_set(N, k.N);
        mpz_set(e, k.e);
        mpz_powm(c, m, k.e, k.N);
        mpz_clear(m);
    } else {
        con = ConnectTo(MakeNetName(NULL), "RSA_Padding_Daemon");
        challenge chall;
        ReceiveAll(con, &chall, sizeof(chall));
        mpz_import(N, sizeof(chall.N), 1,1,1,0, chall.N);
        mpz_import(e, sizeof(chall.e), 1,1,1,0, chall.e);
        mpz_import(c, sizeof(chall.c), 1,1,1,0, chall.c);
    }
    fprintf(stderr, "N: %s\n",  mpz_get_str(NULL, 10, N));
    fprintf(stderr, "e: %s\n",  mpz_get_str(NULL, 10, e));
    fprintf(stderr, "c: %s\n",  mpz_get_str(NULL, 10, c));

    mpz_t B;
    mpz_init_set_ui(B, 2);
    mpz_pow_ui(B, B, RSA_BITS - 16);

    mpz_t m1;
    mpz_init_set_ui(m1, 2);
    mpz_mul(m1, m1, B);

    mpz_t m2;
    mpz_init_set_ui(m2, 3);
    mpz_mul(m2, m2, B);
    mpz_sub_ui(m2, m2, 1);

    mpz_t s_i_1;
    mpz_init_set_ui(s_i_1, 1);

    mpz_t s_i;
    mpz_init_set_ui(s_i, 1);

    int i = 1;

    mpz_t r_i;
    mpz_init_set_ui(r_i, 0);

    while (mpz_cmp(m1,m2) != 0) {
        if (i == 1) {
            mpz_t lower;
            mpz_init_set_ui(lower, 3);
            mpz_mul(lower, lower, B);
            mpz_cdiv_q(lower, N, lower);

            mpz_set(s_i, lower);
            mpz_t c_i;
            mpz_init_set_ui(c_i, 0);
            mpz_powm(c_i, s_i, e, N);
            mpz_mul(c_i, c, c_i);
            mpz_mod(c_i, c_i, N);
            while (!(padding_oracle(c_i))) {
                mpz_add_ui(s_i, s_i, 1);
                mpz_powm(c_i, s_i, e, N);
                mpz_mul(c_i, c, c_i);
                mpz_mod(c_i, c_i, N);
            }
            mpz_clear(c_i);
            mpz_clear(lower);
        } else {
            mpz_set_ui(r_i, 2);
            mpz_mul(r_i, B, r_i);
            mpz_t tmp;
            mpz_init_set_ui(tmp, 0);
            mpz_mul(tmp, m2, s_i_1);
            mpz_sub(r_i, tmp, r_i);
            mpz_mul_ui(r_i, r_i, 2);
            mpz_cdiv_q(r_i, r_i, N);
            mpz_clear(tmp);

            char searching = 1;
            while (searching == 1){
                mpz_t lower;
                mpz_init_set_ui(lower, 2);
                mpz_mul(lower, lower, B);
                mpz_t tmp1;
                mpz_init_set_ui(tmp1, 0);
                mpz_mul(tmp1, r_i, N);
                mpz_add(lower, lower, tmp1);
                mpz_cdiv_q(lower, lower, m2);

                mpz_t upper;
                mpz_init_set_ui(upper, 3);
                mpz_mul(upper, upper, B);
                mpz_sub_ui(upper, upper, 1);
                mpz_add(upper, upper, tmp1);
                mpz_fdiv_q(upper, upper, m1);
                mpz_clear(tmp1);

                mpz_set(s_i, lower);

                while(mpz_cmp(s_i, upper) <= 0){
                    mpz_t c_i;
                    mpz_init_set_ui(c_i, 0);
                    mpz_powm(c_i, s_i, e, N);
                    mpz_mul(c_i, c, c_i);
                    mpz_mod(c_i, c_i, N);
                    if (padding_oracle(c_i)){
                        searching = 0;
                        break;
                    }
                    mpz_add_ui(s_i, s_i, 1);
                    mpz_clear(c_i);
                }
                if (searching == 1){
                    mpz_add_ui(r_i, r_i, 1);
                }
                mpz_clear(lower);
                mpz_clear(upper);
            }
        }
        mpz_t tmp;
        mpz_init_set_ui(tmp, 0);
        if (i > 1){
            mpz_mul(tmp, r_i, N);
        } else {
            mpz_t low_r;
            mpz_init_set_ui(low_r, 3);
            mpz_mul(low_r, low_r, B);
            mpz_mul(tmp, m1, s_i);
            mpz_sub(low_r, tmp, low_r);
            mpz_add_ui(low_r, low_r, 1);
            mpz_cdiv_q(low_r, low_r, N);
            mpz_mul(tmp, low_r, N);
            mpz_clear(low_r);
        }
        mpz_t tmp2;
        mpz_init_set_ui(tmp2, 2);
        mpz_mul(tmp2, tmp2, B);
        mpz_add(tmp2, tmp, tmp2);
        mpz_cdiv_q(m1, tmp2, s_i);

        mpz_mul_ui(tmp2, B, 3);
        mpz_sub_ui(tmp2, tmp2, 1);
        mpz_add(tmp2, tmp2, tmp);
        mpz_fdiv_q(m2, tmp2, s_i);

        mpz_clear(tmp2);
        mpz_clear(tmp);
        mpz_set(s_i_1, s_i);
        i += 1;
    }

    submit_solution(m1);

    mpz_clear(B);
    mpz_clear(m1);
    mpz_clear(m2);
    mpz_clear(s_i);
    mpz_clear(s_i_1);
    mpz_clear(r_i);

    if(!local) {
        DisConnect (con);
    }
    exit(0);

    return 0;
}
