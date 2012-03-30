// Zhang-Kim ID-based blind signature scheme

#include "zk.h"
#include <string.h>

// Length functions

int zk_param_length_in_bytes(pairing_t pairing) {
    return pairing_length_in_bytes_compressed_G2(pairing) * 2;
}

int zk_master_length_in_bytes(pairing_t pairing) {
    return zk_param_length_in_bytes(pairing) + pairing_length_in_bytes_Zr(pairing);
}

int zk_private_length_in_bytes(pairing_t pairing) {
    return zk_param_length_in_bytes(pairing) + pairing_length_in_bytes_compressed_G2(pairing);
}

int zk_sign_init_length_in_bytes(pairing_t pairing) {
    return pairing_length_in_bytes_compressed_G1(pairing);
}

int zk_sign_init_factor_length_in_bytes(pairing_t pairing) {
    return pairing_length_in_bytes_Zr(pairing);
}

int zk_blinded_length_in_bytes(pairing_t pairing) {
    return pairing_length_in_bytes_Zr(pairing);
}

int zk_blinding_factor_length_in_bytes(pairing_t pairing) {
    return pairing_length_in_bytes_Zr(pairing)+pairing_length_in_bytes_G1(pairing);
}

int zk_blinded_signature_length_in_bytes(pairing_t pairing) {
    return pairing_length_in_bytes_compressed_G1(pairing);
}

int zk_signature_length_in_bytes(pairing_t pairing) {
    return 2*pairing_length_in_bytes_compressed_G1(pairing);
}


void zk_gen(zk_master_t master, pairing_t pairing) {
    master->param->pairing = pairing;
    element_init_G2(master->param->p, master->param->pairing);
    element_random(master->param->p);
    element_init_Zr(master->s, master->param->pairing);
    element_random(master->s);
    element_init_G2(master->param->sp, master->param->pairing);
    element_mul_zn(master->param->sp, master->param->p, master->s);
}

int zk_param_to_bytes(unsigned char *bytes, zk_param_t param) {
    int i = element_to_bytes_compressed(bytes, param->p);
    int j = element_to_bytes_compressed(bytes+i, param->sp);
    return i+j;
}

int zk_param_from_bytes(zk_param_t param, unsigned char *bytes, pairing_t pairing) {
    param->pairing = pairing;
    element_init_G2(param->p, pairing);
    int i = element_from_bytes_compressed(param->p, bytes);
    element_init_G2(param->sp, pairing);
    int j = element_from_bytes_compressed(param->sp, bytes+i);
    return i+j;
}

void zk_param_clear(zk_param_t param) {
    element_clear(param->p);
    element_clear(param->sp);
}

void zk_param_from_master(zk_param_t param, zk_master_t master) {
    unsigned char *copy = pbc_malloc(zk_param_length_in_bytes(master->param->pairing));
    zk_param_to_bytes(copy, master->param);
    zk_param_from_bytes(param, copy, master->param->pairing);
    pbc_free(copy);
}

int zk_master_to_bytes(unsigned char *bytes, zk_master_t master) {
    int i = zk_param_to_bytes(bytes, master->param);
    int j = element_to_bytes(bytes+i, master->s);
    return i+j;
}

int zk_master_from_bytes(zk_master_t master, unsigned char *bytes, pairing_t pairing) {
    int i = zk_param_from_bytes(master->param, bytes, pairing);
    element_init_G1(master->s, pairing);
    int j = element_from_bytes(master->s, bytes+i);
    return i+j;
}

void zk_master_clear(zk_master_t master) {
    zk_param_clear(master->param);
    element_clear(master->s);
}

int zk_private_to_bytes(unsigned char *bytes, zk_private_t private) {
    int i = zk_param_to_bytes(bytes, private->param);
    int j = element_to_bytes_compressed(bytes+i, private->sid);
    return i+j;
}

int zk_private_from_bytes(zk_private_t private, unsigned char *bytes, pairing_t pairing) {
    int i = zk_param_from_bytes(private->param, bytes, pairing);
    int j = element_from_bytes_compressed(private->sid, bytes+i);
    return i+j;
}

void zk_private_clear(zk_private_t private) {
    zk_param_clear(private->param);
    element_clear(private->sid);
}

void zk_extract(zk_private_t private, unsigned int idlen, unsigned char *id, zk_master_t master) {
    element_t qid;

    unsigned char *copy = pbc_malloc(zk_param_length_in_bytes(master->param->pairing));
    zk_param_to_bytes(copy, master->param);
    zk_param_from_bytes(private->param, copy, master->param->pairing);

    element_init_G1(qid, master->param->pairing);
    element_from_hash(qid, id, idlen);
    element_init_G1(private->sid, master->param->pairing);
    element_mul_zn(private->sid, qid, master->s);

    element_clear(qid);
    pbc_free(copy);
}

void zk_sign_init(unsigned char *u, unsigned char *r, zk_private_t private, int idlen, unsigned char *id) {
    element_t r1, u1, qid;
    element_init_Zr(r1, private->param->pairing);
    element_random(r1);
    element_init_G1(qid, private->param->pairing);
    element_from_hash(qid, id, idlen);
    element_init_G1(u1, private->param->pairing);
    element_mul_zn(u1, qid, r1);
    element_to_bytes_compressed(u, u1);
    element_to_bytes(r, r1);

    element_clear(r1);
    element_clear(u1);
    element_clear(qid);
}

void zk_blind(unsigned char *blinded, unsigned char *blinding_factor, unsigned char *init, zk_param_t param, int idlen, unsigned char *id, int datalen, unsigned char *data) {
    element_t a, b;
    element_init_Zr(a, param->pairing);
    element_init_Zr(b, param->pairing);
    element_random(a);
    element_random(b);

    element_t u;
    element_init_G1(u, param->pairing);
    element_from_bytes_compressed(u, init);

    element_t u1;
    element_init_G1(u1, param->pairing);
    element_from_hash(u1, id, idlen);
    element_mul_zn(u1, u1, b);
    element_add(u1, u1, u);
    element_mul_zn(u1, u1, a);

    element_t h;
    element_init_Zr(h, param->pairing);
    int hashdatalen = datalen+element_length_in_bytes(u1);
    unsigned char *hashdata = pbc_malloc(hashdatalen);
    memcpy(hashdata, data, datalen);
    element_to_bytes(hashdata+datalen, u1);
    element_from_hash(h, hashdata, hashdatalen);
    element_div(h, h, a);
    element_add(h, h, b);

    element_to_bytes(blinded, h);
    int i = element_to_bytes(blinding_factor, a);
    element_to_bytes_compressed(blinding_factor+i, u1);

    element_clear(a);
    element_clear(b);
    element_clear(u);
    element_clear(u1);
    element_clear(h);
    pbc_free(hashdata);
}

int zk_sign(unsigned char *signature, unsigned char *r, unsigned char *h, zk_private_t private) {
    element_t re, he, v;
    element_init_Zr(re, private->param->pairing);
    element_init_Zr(he, private->param->pairing);
    element_init_G1(v, private->param->pairing);

    element_from_bytes(re, r);
    element_from_bytes(he, h);
    element_add(re, re, he);
    element_mul_zn(v, private->sid, re);
    int i = element_to_bytes_compressed(signature, v);

    element_clear(re);
    element_clear(he);
    element_clear(v);

    return i;
}

int zk_unblind(unsigned char *output, unsigned char *signature, unsigned char *blinding_factor, zk_param_t param) {
    element_t a, v, u1;
    element_init_G1(v, param->pairing);
    element_from_bytes_compressed(v, signature);
    element_init_Zr(a, param->pairing);
    element_init_G1(u1, param->pairing);
    int i = element_from_bytes(a, blinding_factor);
    element_from_bytes_compressed(u1, blinding_factor+i);

    element_mul_zn(v, v, a);
    int j = element_to_bytes_compressed(output, u1);
    int k = element_to_bytes_compressed(output+j, v);

    element_clear(a);
    element_clear(u1);
    element_clear(v);

    return j+k;
}

int zk_verify(unsigned char *signature, int datalen, unsigned char *data, zk_param_t param, int idlen, unsigned char *id) {
    element_t u, v;
    element_init_G1(u, param->pairing);
    element_init_G1(v, param->pairing);
    int i = element_from_bytes_compressed(u, signature);
    element_from_bytes_compressed(v, signature+i);

    element_t h;
    element_init_Zr(h, param->pairing);
    int hashdatalen = datalen+element_length_in_bytes(u);
    unsigned char *hashdata = pbc_malloc(hashdatalen);
    memcpy(hashdata, data, datalen);
    element_to_bytes(hashdata+datalen, u);
    element_from_hash(h, hashdata, hashdatalen);

    element_t qid;
    element_init_G1(qid, param->pairing);
    element_from_hash(qid, id, idlen);
    element_mul_zn(qid, qid, h);

    element_add(u, u, qid);

    int is_valid = is_almost_coddh(u, v, param->p, param->sp, param->pairing);

    element_clear(u);
    element_clear(v);
    element_clear(h);
    element_clear(qid);
    pbc_free(hashdata);

    return is_valid;
}
