"""
LEGAL NOTICE:
This tool is intended for educational use only.
The author is not responsible for any misuse of this tool.
"""
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <cuda_runtime.h>

#define MAX_LEN 8
#define HASH_LEN_MD5 16
#define HASH_LEN_SHA1 20
#define HASH_LEN_SHA256 32
#define CHARSET "abcdefghijklmnopqrstuvwxyz0123456789"
#define CHARSET_LEN 36

__device__ __constant__ char d_charset[CHARSET_LEN];
__device__ __constant__ uint8_t d_target_hash[HASH_LEN_SHA256];
__device__ __constant__ int d_hash_len;
__device__ __constant__ int d_pass_len;
__device__ __constant__ int d_hash_mode;
__device__ char d_result[MAX_LEN + 1];
__device__ int d_found = 0;

enum HashMode {
    HASH_MD5 = 0,
    HASH_SHA1 = 1,
    HASH_SHA256 = 2
};

// --- ROTL and ROTR ---
__device__ uint32_t ROTL(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}
__device__ uint32_t ROTR(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

// --- MD5 Implementation ---
__device__ uint32_t md5_rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

__device__ void md5(const char* msg, int len, uint8_t* digest) {
    uint32_t a0 = 0x67452301;
    uint32_t b0 = 0xefcdab89;
    uint32_t c0 = 0x98badcfe;
    uint32_t d0 = 0x10325476;

    const uint32_t k[] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
        0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
        0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,
        0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,
        0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
        0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,
        0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,
        0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
        0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
    };

    const int r[] = {
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
    };

    uint8_t data[64] = {0};
    for (int i = 0; i < len; ++i) data[i] = msg[i];
    data[len] = 0x80;
    uint64_t bit_len = len * 8;
    data[56] = bit_len & 0xFF;
    data[57] = (bit_len >> 8) & 0xFF;
    data[58] = (bit_len >> 16) & 0xFF;
    data[59] = (bit_len >> 24) & 0xFF;
    data[60] = (bit_len >> 32) & 0xFF;
    data[61] = (bit_len >> 40) & 0xFF;
    data[62] = (bit_len >> 48) & 0xFF;
    data[63] = (bit_len >> 56) & 0xFF;

    uint32_t M[16];
    for (int i = 0; i < 16; ++i)
        M[i] = (data[i*4]) | (data[i*4+1] << 8) | (data[i*4+2] << 16) | (data[i*4+3] << 24);

    uint32_t A = a0;
    uint32_t B = b0;
    uint32_t C = c0;
    uint32_t D = d0;

    for (int i = 0; i < 64; ++i) {
        uint32_t F, g;
        if (i < 16) {
            F = (B & C) | ((~B) & D);
            g = i;
        } else if (i < 32) {
            F = (D & B) | ((~D) & C);
            g = (5 * i + 1) & 15;
        } else if (i < 48) {
            F = B ^ C ^ D;
            g = (3 * i + 5) & 15;
        } else {
            F = C ^ (B | (~D));
            g = (7 * i) & 15;
        }
        uint32_t temp = D;
        D = C;
        C = B;
        B = B + md5_rotl(A + F + k[i] + M[g], r[i]);
        A = temp;
    }

    a0 += A;
    b0 += B;
    c0 += C;
    d0 += D;

    digest[0] = a0 & 0xff; digest[1] = (a0 >> 8) & 0xff; digest[2] = (a0 >> 16) & 0xff; digest[3] = (a0 >> 24) & 0xff;
    digest[4] = b0 & 0xff; digest[5] = (b0 >> 8) & 0xff; digest[6] = (b0 >> 16) & 0xff; digest[7] = (b0 >> 24) & 0xff;
    digest[8] = c0 & 0xff; digest[9] = (c0 >> 8) & 0xff; digest[10] = (c0 >> 16) & 0xff; digest[11] = (c0 >> 24) & 0xff;
    digest[12] = d0 & 0xff; digest[13] = (d0 >> 8) & 0xff; digest[14] = (d0 >> 16) & 0xff; digest[15] = (d0 >> 24) & 0xff;
}

// SHA1 device implementation
__device__ uint32_t ROTL32(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

__device__ void sha1(const char* msg, int len, uint8_t* digest) {
    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
    uint8_t data[64] = {0};

    for (int i = 0; i < len; ++i) data[i] = msg[i];
    data[len] = 0x80;
    data[63] = len * 8;

    uint32_t w[80];
    for (int i = 0; i < 16; ++i)
        w[i] = (data[4*i]<<24) | (data[4*i+1]<<16) | (data[4*i+2]<<8) | (data[4*i+3]);
    for (int i = 16; i < 80; ++i)
        w[i] = ROTL32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;

    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        uint32_t temp = ROTL32(a,5) + f + e + k + w[i];
        e = d;
        d = c;
        c = ROTL32(b,30);
        b = a;
        a = temp;
    }

    h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;

    digest[0] = (h0 >> 24) & 0xFF;
    digest[1] = (h0 >> 16) & 0xFF;
    digest[2] = (h0 >> 8) & 0xFF;
    digest[3] = h0 & 0xFF;

    digest[4] = (h1 >> 24) & 0xFF;
    digest[5] = (h1 >> 16) & 0xFF;
    digest[6] = (h1 >> 8) & 0xFF;
    digest[7] = h1 & 0xFF;

    digest[8] = (h2 >> 24) & 0xFF;
    digest[9] = (h2 >> 16) & 0xFF;
    digest[10] = (h2 >> 8) & 0xFF;
    digest[11] = h2 & 0xFF;

    digest[12] = (h3 >> 24) & 0xFF;
    digest[13] = (h3 >> 16) & 0xFF;
    digest[14] = (h3 >> 8) & 0xFF;
    digest[15] = h3 & 0xFF;

    digest[16] = (h4 >> 24) & 0xFF;
    digest[17] = (h4 >> 16) & 0xFF;
    digest[18] = (h4 >> 8) & 0xFF;
    digest[19] = h4 & 0xFF;
}

// SHA256 device implementation
__device__ uint32_t SIG0(uint32_t x) {
    return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
}
__device__ uint32_t SIG1(uint32_t x) {
    return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
}
__device__ uint32_t EP0(uint32_t x) {
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}
__device__ uint32_t EP1(uint32_t x) {
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}
__device__ void sha256(const char* msg, int len, uint8_t* digest) {
    const uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
        0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
        0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
        0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
        0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
        0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
        0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
        0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
        0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };

    uint8_t data[64] = {0};
    for (int i = 0; i < len; ++i) data[i] = msg[i];
    data[len] = 0x80;
    uint64_t bit_len = len * 8;
    data[63] = bit_len & 0xFF;
    data[62] = (bit_len >> 8) & 0xFF;

    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = (data[4*i]<<24) | (data[4*i+1]<<16) | (data[4*i+2]<<8) | (data[4*i+3]);
    for (int i = 16; i < 64; ++i)
        w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], h_ = h[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h_ + EP1(e) + ((e & f) ^ (~e & g)) + k[i] + w[i];
        uint32_t t2 = EP0(a) + ((a & b) ^ (a & c) ^ (b & c));
        h_ = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += h_;

    for (int i = 0; i < 8; ++i) {
        digest[i*4 + 0] = (h[i] >> 24) & 0xFF;
        digest[i*4 + 1] = (h[i] >> 16) & 0xFF;
        digest[i*4 + 2] = (h[i] >> 8) & 0xFF;
        digest[i*4 + 3] = h[i] & 0xFF;
    }
}

// indexToPassword
__device__ void indexToPassword(uint64_t index, char* output, int length) {
    for (int i = length - 1; i >= 0; --i) {
        output[i] = d_charset[index % CHARSET_LEN];
        index /= CHARSET_LEN;
    }
}

// kernel
__global__ void bruteForceKernel(uint64_t offset, uint64_t total) {
    uint64_t idx = offset + blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= total || d_found) return;

    char pwd[MAX_LEN + 1] = {0};
    uint8_t digest[HASH_LEN_SHA256] = {0};
    indexToPassword(idx, pwd, d_pass_len);

    switch (d_hash_mode) {
        case HASH_MD5:
            md5(pwd, d_pass_len, digest);
            break;
        case HASH_SHA1:
            sha1(pwd, d_pass_len, digest);
            break;
        case HASH_SHA256:
            sha256(pwd, d_pass_len, digest);
            break;
    }

    bool match = true;
    for (int i = 0; i < d_hash_len; ++i) {
        if (digest[i] != d_target_hash[i]) {
            match = false;
            break;
        }
    }

    if (match && atomicExch(&d_found, 1) == 0) {
        for (int i = 0; i < d_pass_len; ++i)
            d_result[i] = pwd[i];
        d_result[d_pass_len] = '\0';
    }
}

// hex to bytes helper
void hexToBytes(const char* hex, uint8_t* out, int len) {
    for (int i = 0; i < len; ++i)
        sscanf(&hex[i * 2], "%2hhx", &out[i]);
}

const char* getHashName(int mode) {
    switch (mode) {
        case HASH_MD5: return "MD5";
        case HASH_SHA1: return "SHA1";
        case HASH_SHA256: return "SHA256";
        default: return "UNKNOWN";
    }
}

// main
int main(int argc, char** argv) {
    if (argc != 4) {
        printf("Usage: %s <hash> <length> <md5|sha1|sha256>\\n", argv[0]);
        return 1;
    }

    const char* hashHex = argv[1];
    int passLen = atoi(argv[2]);
    int hashLen;
    int mode;

    if (strcmp(argv[3], "md5") == 0) {
        mode = HASH_MD5;
        hashLen = HASH_LEN_MD5;
    } else if (strcmp(argv[3], "sha1") == 0) {
        mode = HASH_SHA1;
        hashLen = HASH_LEN_SHA1;
    } else if (strcmp(argv[3], "sha256") == 0) {
        mode = HASH_SHA256;
        hashLen = HASH_LEN_SHA256;
    } else {
        printf("Unsupported hash mode: %s\\n", argv[3]);
        return 1;
    }

    uint8_t hashBin[HASH_LEN_SHA256] = {0};
    hexToBytes(hashHex, hashBin, hashLen);

    cudaMemcpyToSymbol(d_target_hash, hashBin, hashLen, 0, cudaMemcpyHostToDevice);
    cudaMemcpyToSymbol(d_charset, CHARSET, CHARSET_LEN, 0, cudaMemcpyHostToDevice);
    cudaMemcpyToSymbol(d_hash_len, &hashLen, sizeof(int), 0, cudaMemcpyHostToDevice);
    cudaMemcpyToSymbol(d_pass_len, &passLen, sizeof(int), 0, cudaMemcpyHostToDevice);
    cudaMemcpyToSymbol(d_hash_mode, &mode, sizeof(int), 0, cudaMemcpyHostToDevice);

    int zero = 0;
    cudaMemcpyToSymbol(d_found, &zero, sizeof(int), 0, cudaMemcpyHostToDevice);

    uint64_t total = 1;
    for (int i = 0; i < passLen; ++i) total *= CHARSET_LEN;

    printf("Starting %s brute-force (%llu keys)...\n", getHashName(mode), total);
    fflush(stdout);

    int threads = 256;
    int blocks = 256;

    for (uint64_t i = 0; i < total; i += threads * blocks) {
        bruteForceKernel<<<blocks, threads>>>(i, total);
        cudaDeviceSynchronize();

        int found;
        cudaMemcpyFromSymbol(&found, d_found, sizeof(int));
        if (found) break;
    }

    char result[MAX_LEN + 1] = {0};
    cudaMemcpyFromSymbol(result, d_result, MAX_LEN + 1);

    if (result[0])
        printf("Password found: %s\n", result);
    else
        printf("Password not found in keyspace.\n");

    return 0;
}
