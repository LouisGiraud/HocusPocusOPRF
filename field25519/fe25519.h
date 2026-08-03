#ifndef FE25519_H
#define FE25519_H


// This requires to build the full NaCl lib. Instead: Use sodium uint32_t and pray
// #include "crypto_uint32.h"
#include <sodium.h>
#include <iostream>

typedef uint32_t crypto_uint32;

struct fe25519
{
    public:
    crypto_uint32 v[32];
    fe25519 operator+(fe25519 const &op) const;
    fe25519 operator-(fe25519 const &op) const ;
    fe25519 operator*(fe25519 const &op) const;
    fe25519 operator/(fe25519 const &op) const;
    fe25519& operator+=(fe25519 const &op);
    fe25519& operator-=(fe25519 const &op);
    fe25519& operator*=(fe25519 const &op);
    bool operator==(fe25519 const &op);
    bool operator!=(fe25519 const &op);
    void unpack(const unsigned char x[32]);
    void pack(unsigned char x[32]);
    void setone();
    void setzero();
    void neg();
    void freeze();
    int iszero();
    void reduce_add_sub();
    char legendre_symbol(); 
    
    // returns the legendre symbol (x/p), which is (0,1, or -1)
    // and writes s such that x*s^2 = 0,1 or 2 if (x/p) is 0,1 or 255 respectively
    char legendre_symbol_with_s(fe25519 &s);
};

std::ostream &operator<<(std::ostream &os, const fe25519 &e);

int fe25519_issquare(const fe25519 *x);

void fe25519_unpack(fe25519 *r, const unsigned char x[32]);

void fe25519_pack(unsigned char r[32], const fe25519 *x);

void fe25519_cmov(fe25519 *r, const fe25519 *x, unsigned char b);

void fe25519_setone(fe25519 *r);

void fe25519_setzero(fe25519 *r);

void fe25519_neg(fe25519 *r, const fe25519 *x);

unsigned char fe25519_getparity(const fe25519 *x);

void fe25519_add(fe25519 *r, const fe25519 *x, const fe25519 *y);

// No reduction mod p
void fe25519_add_lazy(fe25519 *r, const fe25519 *x, const fe25519 *y);

void fe25519_sub(fe25519 *r, const fe25519 *x, const fe25519 *y);

// No reduction mod p
void fe25519_sub_lazy(fe25519 *r, const fe25519 *x, const fe25519 *y);

void fe25519_mul(fe25519 *r, const fe25519 *x, const fe25519 *y);

void fe25519_square(fe25519 *r, const fe25519 *x);

void fe25519_pow(fe25519 *r, const fe25519 *x, const unsigned char *e);

int fe25519_sqrt_vartime(fe25519 *r, const fe25519 *x, unsigned char parity);

void fe25519_invert(fe25519 *r, const fe25519 *x);

void fe25519_reduce_add_sub(fe25519 *r);

void fe25519_freeze(fe25519 *r);

int fe25519_iszero(const fe25519 *x);

// --- QuickSilver Helper Functions ---

// 1. Inline Exponentiation
inline fe25519 pow2(const fe25519& x) { return x * x; }
inline fe25519 pow3(const fe25519& x) { return x * x * x; }
inline fe25519 pow4(const fe25519& x) { fe25519 x2 = x * x; return x2 * x2; }
inline fe25519 pow5(const fe25519& x) { fe25519 x2 = x * x; return x2 * x2 * x; }

// 2. Small Integer to fe25519 Converter (For generating constants like 5, 10, etc.)
inline fe25519 int_to_fe(unsigned int v) {
    fe25519 res; res.setzero();
    fe25519 one; one.setone();
    for(unsigned int i = 0; i < v; i++) {
        res = res + one;
    }
    return res;
}

#endif
