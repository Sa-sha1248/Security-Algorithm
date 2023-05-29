#include <assert.h>
#include <stdio.h>

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>

void print_symetric_key(unsigned char *key, size_t len)
{
    printf("공유키 : \n");
    for (size_t i = 0; i < len; i++) {
        printf("%02X", key[i]);
    }
    printf("\n");
}


EC_KEY *create_key(void)
{
	EC_KEY *key;
    //EC_KEY 구조체 생성
	if (NULL == (key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))) {
		printf("Failed to create key curve\n");
		return NULL;
	}
    //개인키와 공개키 생성
	if (1 != EC_KEY_generate_key(key)) {
		printf("Failed to generate key\n");
		return NULL;
	}
	return key;
}

//공유키 계산
unsigned char *get_symetric(EC_KEY *key, const EC_POINT *peer_pub_key,
			size_t *symetric_len)
{
	int field_size;
	unsigned char *symetric;

	field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key)); //타원 곡선 그룹 비트
	*symetric_len = (field_size + 7) / 8; //공유 키 길이

	if (NULL == (symetric = OPENSSL_malloc(*symetric_len))) {
		printf("Failed to allocate memory for symetric");
		return NULL;
	}

	*symetric_len = ECDH_compute_key(symetric, *symetric_len,
					peer_pub_key, key, NULL);

	if (*symetric_len <= 0) {
		OPENSSL_free(symetric);
		return NULL;
	}
	return symetric;
}

int main(int argc, char *argv[])
{
    //Alice 비밀키, 공개키 생성
	EC_KEY *alice = create_key();
    //Bob 비밀키, 공개키 생성
	EC_KEY *bob = create_key();

    //alice 객체 안에 든 공개키 추출
	const EC_POINT *alice_public = EC_KEY_get0_public_key(alice);
    //bob 객체 안에 든 공개키 추출
	const EC_POINT *bob_public = EC_KEY_get0_public_key(bob);

	size_t alice_symetric_len;//공유키 길이
	size_t bob_symetric_len;

    //alice가 bob_public을 통해 공유키 생성
	unsigned char *alice_symetric = get_symetric(alice, bob_public, &alice_symetric_len);
	//bob이 alice_public을 통해 공유키 생성
    unsigned char *bob_symetric = get_symetric(bob, alice_public, &bob_symetric_len);

    printf("Alice가 가진 ");
    print_symetric_key(alice_symetric, alice_symetric_len);
    printf("Bob이 가진 ");
    print_symetric_key(bob_symetric, bob_symetric_len);

	EC_KEY_free(alice);
	EC_KEY_free(bob);
	OPENSSL_free(alice_symetric);
	OPENSSL_free(bob_symetric);

	return 0;
}
