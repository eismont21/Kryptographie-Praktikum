#include <praktikum.h>
#include <network.h>

#include <protocol.h>

Connection con;

int main (int argc, char *argv[]){
    con = ConnectTo(MakeNetName(NULL), "Small_Exp");
    message m;
    ReceiveAll(con, &m, sizeof(m));
    if(m.type != CHALLENGE){
        printf("Invalid message type from daemon");
        exit(1);
    }
    mpz_t N[3];
    mpz_t c[3];
    mpz_init(N[0]);
    mpz_init(N[1]);
    mpz_init(N[2]);
    mpz_init(c[0]);
    mpz_init(c[1]);
    mpz_init(c[2]);

    mpz_import(N[0], sizeof(m.challenge.key[0]), -1,1,1,0, m.challenge.key[0]);
    mpz_import(N[1], sizeof(m.challenge.key[1]), -1,1,1,0, m.challenge.key[1]);
    mpz_import(N[2], sizeof(m.challenge.key[2]), -1,1,1,0, m.challenge.key[2]);
    mpz_import(c[0], sizeof(m.challenge.ch[0]), -1,1,1,0, m.challenge.ch[0]);
    mpz_import(c[1], sizeof(m.challenge.ch[1]), -1,1,1,0, m.challenge.ch[1]);
    mpz_import(c[2], sizeof(m.challenge.ch[2]), -1,1,1,0, m.challenge.ch[2]);

    // Chinese remainder theorem
    mpz_t product;
    mpz_init(product);
    mpz_set_ui(product, 1);
    for (int i = 0; i < 3; i++){
        mpz_mul(product, product, N[i]);
    }
    mpz_t s;
    mpz_init(s);
    mpz_set_ui(s, 0);
    mpz_t sum;
    mpz_init(sum);
    mpz_set_ui(sum, 0);
    for (int i = 0; i < 3; i++){
        mpz_div(s, product, N[i]);
        mpz_t a;
        mpz_init(a);
        mpz_set_ui(a, 0);
        mpz_add_ui(a, s, 0);
        mpz_t b;
        mpz_init(b);
        mpz_set_ui(b, 0);
        mpz_add_ui(b, N[i], 0);
        mpz_t d;
        mpz_init(d);
        mpz_set_ui(d, 0);
        mpz_add_ui(d, b, 0);
        mpz_t f;
        mpz_init(f);
        mpz_set_ui(f, 0);
        mpz_t j;
        mpz_init(j);
        mpz_set_ui(j, 0);
        mpz_t h;
        mpz_init(h);
        mpz_set_ui(h, 0);
        mpz_t k;
        mpz_init(k);
        mpz_set_ui(k, 1);
        char flag = 0;
        if (mpz_cmp_ui(b, 1) == 0){
            flag = 1;
        }
        while ((mpz_cmp_ui(a, 1) > 0) && (flag == 0)){
            mpz_div(j, a, b);
            mpz_add_ui(f, b, 0);
            mpz_mod(b, a, b);
            mpz_add_ui(a, f, 0);
            mpz_add_ui(f, h, 0);
            mpz_t tmp;
            mpz_init(tmp);
            mpz_set_ui(tmp, 0);
            mpz_mul(tmp, j, h);
            mpz_sub(h, k, tmp);
            mpz_clear(tmp);
            mpz_add_ui(k, f, 0);
        }
        mpz_clear(a);
        mpz_clear(b);
        mpz_clear(f);
        mpz_clear(j);
        mpz_clear(h);
        if (mpz_cmp_ui(k, 0) < 0){
            mpz_add(k, k, d);
        }
        mpz_clear(d);
        mpz_t tmp;
        mpz_init(tmp);
        mpz_set_ui(tmp, 0);
        mpz_mul(tmp, k, s);
        mpz_mul(tmp, tmp, c[i]);
        mpz_add(sum, sum, tmp);
        mpz_clear(k);
        mpz_clear(tmp);
    }
    mpz_t x;
    mpz_init(x);
    mpz_set_ui(x, 0);
    mpz_mod(x, sum, product);
    mpz_clear(product);
    mpz_clear(s);
    mpz_clear(sum);

    // the 3'th root of x
    char flag = 0;
    mpz_t mid;
    mpz_init(mid);
    mpz_set_ui(mid, 0);
    if (mpz_cmp_ui(x, 1) == 0){
        flag = 1;
        mpz_set_ui(mid, 1);
    }
    mpz_t high;
    mpz_init(high);
    mpz_set_ui(high, 1);
    mpz_t tmp;
    mpz_init(tmp);
    mpz_set_ui(tmp, 0);
    mpz_mul(tmp, high, high);
    mpz_mul(tmp, tmp, high);
    while (mpz_cmp(tmp, x) < 0){
        mpz_mul_ui(high, high, 2);
        mpz_mul(tmp, high, high);
        mpz_mul(tmp, tmp, high);
    }
    mpz_t low;
    mpz_init(low);
    mpz_set_ui(low, 0);
    mpz_div_ui(low, high, 2);
    while ((mpz_cmp(low, high) < 0) && (flag == 0)){
        mpz_add(tmp, low, high);
        mpz_div_ui(mid, tmp, 2);
        mpz_mul(tmp, mid, mid);
        mpz_mul(tmp, tmp, mid);
        if ((mpz_cmp(low, mid) < 0) && (mpz_cmp(tmp, x) < 0)){
            mpz_add_ui(low, mid, 0);
        }
        else if ((mpz_cmp(high, mid) > 0) && (mpz_cmp(tmp, x) > 0)){
            mpz_add_ui(high, mid, 0);
        }
        else{
            flag = 1;
        }
    }
    mpz_clear(x);
    mpz_clear(high);
    mpz_clear(low);
    mpz_clear(tmp);
    mpz_t v;
    mpz_init(v);
    mpz_set_ui(v, 0);
    if (flag == 1){
        mpz_add_ui(v, mid, 0);
    }
    else{
        mpz_add_ui(v, mid, 1);
    }
    mpz_clear(mid);

    message sol;
    memset(&sol, 0, sizeof(sol));
    sol.type = SOLUTION;
    mpz_export(sol.solution.m, NULL, -1,1,1,0, v);
    mpz_clear(v);

    Transmit(con, &sol, sizeof(sol));
    ReceiveAll(con, &m, sizeof(m));
    if(m.type != SOLUTION_REP){
        printf("Invalid message type from daemon");
        exit(1);
    }
    if(m.solution_rep.rep){
        printf("Loesung ist falsch.\n");
    } else {
        printf("Loesung ist korrekt.\n");
    }
    DisConnect (con);
    exit(0);

    return 0;
}
