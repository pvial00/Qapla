Q = [0x98d57011ef2469a7, 0x0c7e53dd9eb185bc]

class QaplaState:
    def __init__(self):
        self.r = []
        for x in range(8):
            self.r.append(long(0))
        self.o = []
        for x in range(8):
            self.o.append(long(0))
        self.rounds = 20

def rotate(a, b):
    return ((a << b) | (a >> (32 - b)))

def F(state):
    y = []
    for i in range(8):
        y.append(state.r[i])
    for r in range(state.rounds):
        state.r[0] += state.r[7];
        state.r[1] = rotate((state.r[1] ^ state.r[0]), 9);
        state.r[2] += state.r[5];
        state.r[3] = rotate((state.r[3] ^ state.r[2]), 21);
        state.r[4] += state.r[3];
        state.r[5] = rotate((state.r[5] ^ state.r[4]), 12);
        state.r[6] += state.r[1];
        state.r[7] = rotate((state.r[7] ^ state.r[6]), 18);
        state.r[1] += state.r[0];
        state.r[2] = rotate((state.r[2] ^ state.r[7]), 9);
        state.r[3] += state.r[2];
        state.r[4] = rotate((state.r[4] ^ state.r[5]), 21);
        state.r[5] += state.r[4];
        state.r[6] = rotate((state.r[6] ^ state.r[3]), 12);
        state.r[7] += state.r[6];
        state.r[0] = rotate((state.r[0] ^ state.r[1]), 18);

    for i in range(8):
        state.r[i] = state.r[i] + y[i]
    for i in range(4):
        state.o[i] = state.r[i] ^ state.r[(i + 4) % 0x07]

def keysetup(state, key, nonce):
    state.r[0] = Q[0]
    state.r[4] = Q[1]
    state.r[1] = ((ord(key[0])) << 56) + (ord(key[1]) << 48) + (ord(key[2]) << 40) + (ord(key[3]) << 32) + (ord(key[4]) << 24) + (ord(key[5]) << 16) + (ord(key[6]) << 8) + ord(key[7]);
    state.r[3] = ((ord(key[8])) << 56) + (ord(key[9]) << 48) + (ord(key[10]) << 40) + (ord(key[11]) << 32) + (ord(key[12]) << 24) + (ord(key[13]) << 16) + (ord(key[14]) << 8) + ord(key[15]);
    state.r[2] = ((ord(key[16])) << 56) + (ord(key[17]) << 48) + (ord(key[18]) << 40) + (ord(key[19]) << 32) + (ord(key[20]) << 24) + (ord(key[21]) << 16) + (ord(key[22]) << 8) + ord(key[23]);
    state.r[5] = ((ord(key[24])) << 56) + (ord(key[25]) << 48) + (ord(key[26]) << 40) + (ord(key[27]) << 32) + (ord(key[28]) << 24) + (ord(key[29]) << 16) + (ord(key[30]) << 8) + ord(key[31]);
    state.r[6] = ((ord(nonce[0])) << 56) + (ord(nonce[1]) << 48) + (ord(nonce[2]) << 40) + (ord(nonce[3]) << 32) + (ord(nonce[4]) << 24) + (ord(nonce[5]) << 16) + (ord(nonce[6]) << 8) + ord(nonce[7]);
    state.r[7] = ((ord(nonce[8])) << 56) + (ord(nonce[9]) << 48) + (ord(nonce[10]) << 40) + (ord(nonce[11]) << 32) + (ord(nonce[12]) << 24) + (ord(nonce[13]) << 16) + (ord(nonce[14]) << 8) + ord(nonce[15]);

    for i in range(64):
        F(state)

def crypt(msg, key, nonce):
    if len(key) != 32 and len(nonce) != 16:
        return ""
    state = QaplaState()
    ctxt = []
    blocks = len(msg) / 32
    extra = len(msg) % 32
    l = 32
    c = 0
    if extra != 0:
        blocks += 1
    keysetup(state, key, nonce)
    for b in range(blocks):
        F(state)
        k = [0] * 32
        k[0] = (state.o[0] & 0xFF00000000000000) >> 56
        k[1] = (state.o[0] & 0x00FF000000000000) >> 48
        k[2] = (state.o[0] & 0x0000FF0000000000) >> 40
        k[3] = (state.o[0] & 0x000000FF00000000) >> 32
        k[4] = (state.o[0] & 0x00000000FF000000) >> 24
        k[5] = (state.o[0] & 0x0000000000FF0000) >> 16
        k[6] = (state.o[0] & 0x000000000000FF00) >> 8
        k[7] = (state.o[0] & 0x00000000000000FF) 
        k[8] = (state.o[1] & 0xFF00000000000000) >> 56
        k[9] = (state.o[1] & 0x00FF000000000000) >> 48
        k[10] = (state.o[1] & 0x0000FF0000000000) >> 40
        k[11] = (state.o[1] & 0x000000FF00000000) >> 32
        k[12] = (state.o[1] & 0x00000000FF000000) >> 24
        k[13] = (state.o[1] & 0x0000000000FF0000) >> 16
        k[14] = (state.o[1] & 0x000000000000FF00) >> 8
        k[15] = (state.o[1] & 0x00000000000000FF) 
        k[16] = (state.o[2] & 0xFF00000000000000) >> 56
        k[17] = (state.o[2] & 0x00FF000000000000) >> 48
        k[18] = (state.o[2] & 0x0000FF0000000000) >> 40
        k[19] = (state.o[2] & 0x000000FF00000000) >> 32
        k[20] = (state.o[2] & 0x00000000FF000000) >> 24
        k[21] = (state.o[2] & 0x0000000000FF0000) >> 16
        k[22] = (state.o[2] & 0x000000000000FF00) >> 8
        k[23] = (state.o[2] & 0x00000000000000FF) 
        k[24] = (state.o[3] & 0xFF00000000000000) >> 56
        k[25] = (state.o[3] & 0x00FF000000000000) >> 48
        k[26] = (state.o[3] & 0x0000FF0000000000) >> 40
        k[27] = (state.o[3] & 0x000000FF00000000) >> 32
        k[28] = (state.o[3] & 0x00000000FF000000) >> 24
        k[29] = (state.o[3] & 0x0000000000FF0000) >> 16
        k[30] = (state.o[3] & 0x000000000000FF00) >> 8
        k[31] = (state.o[3] & 0x00000000000000FF) 
        if b == (blocks -1) and extra != 0:
            l = extra
        for i in range(l):
            o = ord(msg[c]) ^ k[i]
            c += 1
            ctxt.append(chr(o))
    return "".join(ctxt)

class QaplaSafe:
    def __init__(self, key):
        self.key = key

    def encrypt(self, ptxt):
        import os
        nonce = os.urandom(16)
        ctxt = crypt(ptxt, self.key, nonce)
        return nonce+ctxt

    def decrypt(self, pack):
        nonce = pack[:16]
        ctxt = pack[16:len(pack)]
        ptxt = crypt(ctxt, self.key, nonce)
        return ptxt
