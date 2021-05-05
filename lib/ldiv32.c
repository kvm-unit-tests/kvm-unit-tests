#include <inttypes.h>

extern uint64_t __udivmoddi4(uint64_t num, uint64_t den, uint64_t *p_rem);
extern int64_t __moddi3(int64_t num, int64_t den);
extern int64_t __divdi3(int64_t num, int64_t den);
extern uint64_t __udivdi3(uint64_t num, uint64_t den);
extern uint64_t __umoddi3(uint64_t num, uint64_t den);

uint64_t __udivmoddi4(uint64_t num, uint64_t den, uint64_t *p_rem)
{
	uint64_t quot = 0;

	/* Trigger a division by zero at run time (trick taken from iPXE).  */
	if (den == 0)
		return 1/((unsigned)den);

	if (num >= den) {
		/* Align den to num to avoid wasting time on leftmost zero bits.  */
		int n = __builtin_clzll(den) - __builtin_clzll(num);
		den <<= n;

		do {
			quot <<= 1;
			if (num >= den) {
				num -= den;
				quot |= 1;
			}
			den >>= 1;
		} while (n--);
	}

	if (p_rem)
		*p_rem = num;

	return quot;
}

int64_t __moddi3(int64_t num, int64_t den)
{
	uint64_t mask = num < 0 ? -1 : 0;

	/* Compute absolute values and do an unsigned division.  */
	num = (num + mask) ^ mask;
	if (den < 0)
		den = -den;

	/* Copy sign of num into result.  */
	return (__umoddi3(num, den) + mask) ^ mask;
}

int64_t __divdi3(int64_t num, int64_t den)
{
	uint64_t mask = (num ^ den) < 0 ? -1 : 0;

	/* Compute absolute values and do an unsigned division.  */
	if (num < 0)
		num = -num;
	if (den < 0)
		den = -den;

	/* Copy sign of num^den into result.  */
	return (__udivdi3(num, den) + mask) ^ mask;
}

uint64_t __udivdi3(uint64_t num, uint64_t den)
{
	uint64_t rem;
	return __udivmoddi4(num, den, &rem);
}

uint64_t __umoddi3(uint64_t num, uint64_t den)
{
	uint64_t rem;
	__udivmoddi4(num, den, &rem);
	return rem;
}

#ifdef TEST
#include <assert.h>
#define UTEST(a, b, q, r) assert(__udivdi3(a, b) == q && __umoddi3(a, b) == r)
#define STEST(a, b, q, r) assert(__divdi3(a, b) == q && __moddi3(a, b) == r)
int main()
{
	UTEST(1, 1, 1, 0);
	UTEST(2, 2, 1, 0);
	UTEST(5, 3, 1, 2);
	UTEST(10, 3, 3, 1);
	UTEST(120, 3, 40, 0);
	UTEST(120, 1, 120, 0);
	UTEST(0x7FFFFFFFFFFFFFFFULL, 17, 0x787878787878787, 8);
	UTEST(0x7FFFFFFFFFFFFFFFULL, 0x787878787878787, 17, 8);
	UTEST(0x8000000000000001ULL, 17, 0x787878787878787, 10);
	UTEST(0x8000000000000001ULL, 0x787878787878787, 17, 10);
	UTEST(0, 5, 0, 0);

	STEST(0x7FFFFFFFFFFFFFFFULL, 17, 0x787878787878787, 8);
	STEST(0x7FFFFFFFFFFFFFFFULL, -17, -0x787878787878787, 8);
	STEST(-0x7FFFFFFFFFFFFFFFULL, 17, -0x787878787878787, -8);
	STEST(-0x7FFFFFFFFFFFFFFFULL, -17, 0x787878787878787, -8);
	STEST(33, 5, 6, 3);
	STEST(33, -5, -6, 3);
	STEST(-33, 5, -6, -3);
	STEST(-33, -5, 6, -3);
}
#endif
