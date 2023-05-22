#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>

typedef struct PrimNumber {
	int p;
	int q;
}PrimNumber;

int isPrim(int n) {
	if (n < 2) { // 2 미만의 수는 소수가 아님
		return 0;
	}
	for (int i = 2; i <= sqrt(n); i++) {
		if (n % i == 0) { // 나누어 떨어지는 수가 있으면 소수가 아님
			return 0;
		}
	}
	return 1; // 나누어 떨어지는 수가 없으면 소수
}

int GCD(long a, long b) { //최대공약수 계산
	long r1 = a, r2 = b, r;
	while (r2) {
		r = r1 % r2;
		r1 = r2;
		r2 = r;
	}
	return r1;
}
long mod(long n, long e, long m) { //mod 계산을 위한 함수
	long i;
	unsigned long long res = 1;

	for (i = 1; i <= e; i++) {
		res *= n;
		res %= m;
	}

	return res;
}

void selectPrimNumber(PrimNumber* primNumber) {

	printf("selectPrimNumber\n");
	
	srand((unsigned int)time(NULL));
	primNumber->p = rand() % 1000;
	while (1)
	{
		if (!isPrim(primNumber->p))
			primNumber->p++;
		else break;
	}

	primNumber->q = primNumber->p + 1;
	while (1)
	{
		if (!isPrim(primNumber->q))
			primNumber->q++;
		else break;
	}
	

	printf("p: %d, q: %d\n", primNumber->p, primNumber->q);
}

int len;

unsigned long long enc(char* M,long* C, int e, int N) {
	printf("\n<Encription>\n");

	len = strlen(M);
	int i;

	for (i = 0; i < len; i++) {
		C[i] = (long)mod(M[i], e, N);
	}
	C[i] = '\0';
	printf("암호화 완료! \n");

	printf("암호문 : ");
	for (i = 0; i < len; i++)
		printf("%ld ", C[i]);
	printf("\n");
}

void dec(long* C, char* D, int d, int N) {
	printf("\n<Decription>\n");

	int i;
	for (i = 0; i < len; i++) {
		D[i] = (char)mod(C[i], d, N);
	}

	printf("복호화 완료! \n");

	printf("복호화된 문장 : ");
	for (i = 0; i < len; i++)
		printf("%c", D[i]);
	printf("\n");
}

void RSA(char* M, long* C, char* D) {


	PrimNumber primNumber;
	selectPrimNumber(&primNumber);

	long e, N;
	long d = 0;

	long phi = (primNumber.p - 1) * (primNumber.q - 1);

	N = primNumber.p * primNumber.q;


	while (1)
	{
		e = rand() % 100; 
		if (GCD(e, N) == 1 && e < phi)
			break;
	}
	printf("e값 설정 완료\n");

	while (1) {
		if ((e * d) % phi == 1) { // ed ≡ 1 mod (p-1)(q-1)를 만족하는 d 찾기
			break;
		}
		d++;
	}
	printf("d값 설정 완료\n");

	printf("<System Parameters>\n공개\ne = %d\nN = %d\n비공개\np = %d\nq = %d\nd = %d\n", e, N, primNumber.p, primNumber.q, d);

	printf("암호화 할 원문을 입력하세요 : ");
	gets(M);

	enc(M, C, e, N);
	dec(C, D, d, N);
}



int main() {

	char M[501];
	long C[501];
	char D[501];

	
	
	RSA(&M, &C, &D);
}