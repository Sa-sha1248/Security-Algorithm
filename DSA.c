#include <stdio.h>
#include <gmp.h>
#include <openssl/sha.h>
#include <time.h>
#include <string.h>

void select_q(mpz_t q){
    
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    printf("q 고르는중\n");

    mpz_urandomb(q, state, 160);
    mpz_setbit(q, 159);

    printf("q 고르기 완료\n");
}

void select_p(mpz_t p, mpz_t q){
    mpz_t p_1;
    mpz_init(p_1);
    gmp_randstate_t state;
    gmp_randinit_default(state);
    
    printf("p 고르는중\n");\
    mpz_t rem;
    mpz_init(rem);
    while (1)
    {  
        gmp_randseed_ui(state, time(NULL));
        mpz_urandomb(rem, state, 512);
        mpz_mul(p_1, q, rem);
        mpz_add_ui(p, p_1, 1);
        int result = mpz_probab_prime_p(p, 25);
            if (result != 0) 
                break;
    }
   
    printf("p 고르기 완료\n");
}
void select_g(mpz_t p, mpz_t q, mpz_t g){
    mpz_t h, e;
    mpz_init(h);
    mpz_init(e);

    for (mpz_set_ui(h, 0);mpz_cmp(h, p)< 0; mpz_add_ui(h, h, 1))
    {
        mpz_sub_ui(e, p, 1);
        mpz_div(e, e, q);
        mpz_powm(g, h, e, p);
        if(mpz_cmp_ui(g, 1)> 0)
            break;
    }
    
    
}

void secret_key(mpz_t x, mpz_t q){
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    mpz_urandomm(x, state, q);
}

void system_parameter(mpz_t p, mpz_t q, mpz_t g, mpz_t x, mpz_t y){
    //select p, q
    int bits;

    printf("q 고르는중\n");
    select_q(q);
    printf("p 고르는중\n");
    select_p(p, q);
    bits= mpz_sizeinbase(p,2);
    gmp_printf("p: %Zd \t bits : %d\n", p, bits);
    bits= mpz_sizeinbase(q,2);
    gmp_printf("q: %Zd \t bits : %d\n", q, bits);

    //select g
    select_g(p,q,g);
    bits= mpz_sizeinbase(g,2);
    gmp_printf("g: %Zd\t bits : %d\n", g, bits);

    //secret key
    secret_key(x, q);
    bits= mpz_sizeinbase(x,2);
    gmp_printf("secret_key: %Zd\t bits : %d\n", x, bits);

    //public key
    mpz_powm(y, g, x, p);
    bits= mpz_sizeinbase(y,2);
    gmp_printf("public_key: %Zd\t bits : %d\n", y, bits);
}

void sha_hash(char M[], mpz_t H){
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA_CTX sha;
    SHA1_Init(&sha);
    SHA1_Update(&sha, M, strlen(M));
    SHA1_Final(digest, &sha);
    mpz_import(H, SHA_DIGEST_LENGTH, 1, sizeof(digest[0]), 0, 0, digest);
}

void Signature(char M[], mpz_t S, mpz_t p, mpz_t q, mpz_t g, mpz_t x, mpz_t r){
    //랜덤 k값 선택
    mpz_t k, k_inv, H, S_inv;
    mpz_inits(k, k_inv, H, S_inv, NULL);
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    while (1)
    {
        while (1)
        {
            mpz_urandomm(k, state, q);

            //r 값 계산
            mpz_powm(r, g, k, p);
            mpz_mod(r, r, q);

            //k의 역원 구하기
            if(mpz_invert(k_inv, k, q) == 1){
                mpz_invert(k_inv, k, q);
                break;
            }
        }

        //평문 M 해쉬
        sha_hash(M, H);
        
        //서명
        mpz_mul(S, x, r);
        mpz_add(S, S, H);
        mpz_mul(S, S, k_inv);
        mpz_mod(S, S, q);

        if(mpz_invert(S_inv, S, q) == 1 ){
            gmp_printf("S_inv: %Zd\n", S_inv);
            mpz_invert(S_inv, S, q);
            break;
        }
    }
    gmp_printf("r: %Zd\n", r);
    gmp_printf("H(M): %Zd\n", H);
    gmp_printf("S: %Zd\n", S);
    gmp_printf("S_inv: %Zd\n", S_inv);
}

void Verification(char M[], mpz_t S, mpz_t p, mpz_t q, mpz_t g, mpz_t y, mpz_t r){
    mpz_t S_inv, H, a, b, V;
    mpz_inits(S_inv, H, a, b, V, NULL);
    //S의 역원
    mpz_invert(S_inv, S, q);
    gmp_printf("s_inv: %Zd\n", S_inv);

    //평문 해시
    sha_hash(M, H);
    gmp_printf("H(M): %Zd\n", H);

    mpz_mul(a, H, S_inv);
    gmp_printf("a: %Zd\n", a);

    mpz_mul(b, r, S_inv);
    gmp_printf("b: %Zd\n", b);
    
    mpz_powm(g, g, a, p);
    gmp_printf("g: %Zd\n", g);

    mpz_powm(y, y, b, p);
    gmp_printf("y: %Zd\n", y);

    mpz_mul(V, g, y);
    mpz_mod(V, V, p);
    mpz_mod(V, V, q);
    gmp_printf("V: %Zd\n", V);

    if(mpz_cmp(r, V) == 0)
        printf("검증이 완료되었습니다.\n");
    else printf("검증이 제대로 이루어지지 않았습니다.\n");
}

void DSA(char M[], mpz_t S){
    mpz_t p, q, g, x, y, r;
    mpz_inits(p, q, g, x, y, r, NULL);
    printf("system parameters\n");
    system_parameter(p, q, g, x, y);
    printf("\n");

    printf("\nSignature\n");
    Signature(M, S, p, q, g, x, r);


    //공격자의 공격 - 메세지 바꿔치기
    M = "10000원";
    printf("\n\nVerification\n");
    Verification(M, S, p, q, g, y, r);
}

int main(void)
{
    char M[] = "1000원";
    mpz_t S;
    mpz_init(S);
    DSA(M, S);

    return 0;
}

