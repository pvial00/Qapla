#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

uint64_t Q[2] = {
0x98d57011ef2469a7, 0x0c7e53dd9eb185bc,
};

struct qapla_state {
     uint64_t r[8];
     uint64_t o[4];
     int rounds;
};

void qapla_F(struct qapla_state *state) {
    int i;
    uint64_t temp;
    uint64_t y[8];
    for (i = 0; i < 8; i++) {
        y[i] = state->r[i];
    }
    for (i = 0; i < state->rounds; i++) {
        state->r[0] += state->r[7];
        state->r[1] = rotateleft64((state->r[1] ^ state->r[0]), 9);
        state->r[2] += state->r[5];
        state->r[3] = rotateleft64((state->r[3] ^ state->r[2]), 21);
        state->r[4] += state->r[3];
        state->r[5] = rotateleft64((state->r[5] ^ state->r[4]), 12);
        state->r[6] += state->r[1];
        state->r[7] = rotateleft64((state->r[7] ^ state->r[6]), 18);
        state->r[1] += state->r[0];
        state->r[2] = rotateleft64((state->r[2] ^ state->r[7]), 9);
        state->r[3] += state->r[2];
        state->r[4] = rotateleft64((state->r[4] ^ state->r[5]), 21);
        state->r[5] += state->r[4];
        state->r[6] = rotateleft64((state->r[6] ^ state->r[3]), 12);
        state->r[7] += state->r[6];
        state->r[0] = rotateleft64((state->r[0] ^ state->r[1]), 18);
    }
    for (i = 0; i < 8; i++) {
        state->r[i] = state->r[i] + y[i];
    }
    for (i = 0; i < 4; i++) {
        state->o[i] = state->r[i] ^ state->r[(i + 4) & 0x07];
    }
}

void qapla_keysetup(struct qapla_state *state, unsigned char *key, unsigned char *nonce) {
    memset(state->r, 0, 8*(sizeof(uint64_t)));
    uint64_t n[4];
    int i;
    int m = 0;
    int inc = 8;
    state->rounds = 2000000001;
    state->r[0] = Q[0];
    state->r[4] = Q[1];
    state->r[1] = ((uint64_t)(key[0]) << 56) + ((uint64_t)key[1] << 48) + ((uint64_t)key[2] << 40) + ((uint64_t)key[3] << 32) + ((uint64_t)key[4] << 24) + ((uint64_t)key[5] << 16) + ((uint64_t)key[6] << 8) + (uint64_t)key[7];
    state->r[3] = ((uint64_t)(key[8]) << 56) + ((uint64_t)key[9] << 48) + ((uint64_t)key[10] << 40) + ((uint64_t)key[11] << 32) + ((uint64_t)key[12] << 24) + ((uint64_t)key[13] << 16) + ((uint64_t)key[14] << 8) + (uint64_t)key[15];
    state->r[2] = ((uint64_t)(key[16]) << 56) + ((uint64_t)key[17] << 48) + ((uint64_t)key[18] << 40) + ((uint64_t)key[19] << 32) + ((uint64_t)key[20] << 24) + ((uint64_t)key[21] << 16) + ((uint64_t)key[22] << 8) + (uint64_t)key[23];
    state->r[5] = ((uint64_t)(key[24]) << 56) + ((uint64_t)key[25] << 48) + ((uint64_t)key[26] << 40) + ((uint64_t)key[27] << 32) + ((uint64_t)key[28] << 24) + ((uint64_t)key[29] << 16) + ((uint64_t)key[30] << 8) + (uint64_t)key[31];
   
    state->r[6] = ((uint64_t)nonce[0] << 56) + ((uint64_t)nonce[1] << 48) + ((uint64_t)nonce[2] << 40) + ((uint64_t)nonce[3] << 32) + ((uint64_t)nonce[4] << 24) + ((uint64_t)nonce[5] << 16) + ((uint64_t)nonce[6] << 8) + (uint64_t)nonce[7];
    state->r[7] = ((uint64_t)nonce[8] << 56) + ((uint64_t)nonce[9] << 48) + ((uint64_t)nonce[10] << 40) + ((uint64_t)nonce[11] << 32) + ((uint64_t)nonce[12] << 24) + ((uint64_t)nonce[13] << 16) + ((uint64_t)nonce[14] << 8) + (uint64_t)nonce[15];

    for (int i = 0; i < 64; i++) {
        qapla_F(state);
    }
}

void * qapla_crypt(unsigned char * data, unsigned char * key, unsigned char * nonce, long datalen) {
    struct qapla_state state;
    long c = 0;
    int i = 0;
    int l = 32;
    uint64_t output;
    int k[32] = {0};
    long blocks = datalen / 32;
    long extra = datalen % 32;
    if (extra != 0) {
        blocks += 1;
    }
    qapla_keysetup(&state, key, nonce);
    for (long b = 0; b < blocks; b++) {
        qapla_F(&state);
        k[0] = (state.o[0] & 0xFF00000000000000) >> 56;
        k[1] = (state.o[0] & 0x00FF000000000000) >> 48;
        k[2] = (state.o[0] & 0x0000FF0000000000) >> 40;
        k[3] = (state.o[0] & 0x000000FF00000000) >> 32;
        k[4] = (state.o[0] & 0x00000000FF000000) >> 24;
        k[5] = (state.o[0] & 0x0000000000FF0000) >> 16;
        k[6] = (state.o[0] & 0x000000000000FF00) >> 8;
        k[7] = (state.o[0] & 0x00000000000000FF);
        k[8] = (state.o[1] & 0xFF00000000000000) >> 56;
        k[9] = (state.o[1] & 0x00FF000000000000) >> 48;
        k[10] = (state.o[1] & 0x0000FF0000000000) >> 40;
        k[11] = (state.o[1] & 0x000000FF00000000) >> 32;
        k[12] = (state.o[1] & 0x00000000FF000000) >> 24;
        k[13] = (state.o[1] & 0x0000000000FF0000) >> 16;
        k[14] = (state.o[1] & 0x000000000000FF00) >> 8;
        k[15] = (state.o[1] & 0x00000000000000FF);
        k[16] = (state.o[2] & 0xFF00000000000000) >> 56;
        k[17] = (state.o[2] & 0x00FF000000000000) >> 48;
        k[18] = (state.o[2] & 0x0000FF0000000000) >> 40;
        k[19] = (state.o[2] & 0x000000FF00000000) >> 32;
        k[20] = (state.o[2] & 0x00000000FF000000) >> 24;
        k[21] = (state.o[2] & 0x0000000000FF0000) >> 16;
        k[22] = (state.o[2] & 0x000000000000FF00) >> 8;
        k[23] = (state.o[2] & 0x00000000000000FF);
        k[24] = (state.o[3] & 0xFF00000000000000) >> 56;
        k[25] = (state.o[3] & 0x00FF000000000000) >> 48;
        k[26] = (state.o[3] & 0x0000FF0000000000) >> 40;
        k[27] = (state.o[3] & 0x000000FF00000000) >> 32;
        k[28] = (state.o[3] & 0x00000000FF000000) >> 24;
        k[29] = (state.o[3] & 0x0000000000FF0000) >> 16;
        k[30] = (state.o[3] & 0x000000000000FF00) >> 8;
        k[31] = (state.o[3] & 0x00000000000000FF);
        if (b == (blocks - 1) && (extra != 0)) {
            l = extra;
        }

	for (i = 0; i < l; i++) {
            data[c] = data[c] ^ k[i];
	    c += 1;
	}
    }
}
