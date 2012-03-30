// Zhang-Kim ID-based blind signature scheme

#ifndef ZK_H
#define ZK_H
#ifdef __cplusplus
extern "C" {
#endif

#include <pbc/pbc.h>

// Parameters (i.e. KGC public key)
struct zk_param_s {
    pairing_ptr pairing;
    element_t p;
    element_t sp;
};

typedef struct zk_param_s zk_param_t[1];

int zk_param_to_bytes(unsigned char *bytes, zk_param_t param);
int zk_param_from_bytes(zk_param_t param, unsigned char *bytes, pairing_t pairing);
void zk_param_clear(zk_param_t param);

// Master key
struct zk_master_s {
    zk_param_t param;
    element_t s;
};

typedef struct zk_master_s zk_master_t[1];

int zk_master_to_bytes(unsigned char *bytes, zk_master_t master);
int zk_master_from_bytes(zk_master_t master, unsigned char *bytes, pairing_t pairing);
void zk_master_clear(zk_master_t master);

void zk_param_from_master(zk_param_t param, zk_master_t master);

// Private key
struct zk_private_s {
    zk_param_t param;
    element_t sid;
};

typedef struct zk_private_s zk_private_t[1];

int zk_private_to_bytes(unsigned char *bytes, zk_private_t private);
int zk_private_from_bytes(zk_private_t private, unsigned char *bytes, pairing_t pairing);
void zk_private_clear(zk_private_t private);

// Generate master key
void zk_gen(zk_master_t master, pairing_t pairing);

// Derive private key based on ID
void zk_extract(zk_private_t private, unsigned int idlen, unsigned char *id, zk_master_t master);

// Make commitment for signature
void zk_sign_init(unsigned char *init, unsigned char *init_factor, zk_private_t private, int idlen, unsigned char *id);

// Blind data for signing
void zk_blind(unsigned char *blinded, unsigned char *blinding_factor, unsigned char *init, zk_param_t param, int idlen, unsigned char *id, int datalen, unsigned char *data);

// Sign blinded data using value init_factor from commitment and blinded data blinded
int zk_sign(unsigned char *blinded_signature, unsigned char *init_factor, unsigned char *blinded, zk_private_t private);

// Unblind signature to obtain a valid signature
int zk_unblind(unsigned char *signature, unsigned char *blinded_signature, unsigned char *blinding_factor, zk_param_t param);

// Check validity of a signature
int zk_verify(unsigned char *signature, int datalen, unsigned char *data, zk_param_t param, int idlen, unsigned char *id);

// Length functions

int zk_param_length_in_bytes(pairing_t pairing);

int zk_master_length_in_bytes(pairing_t pairing);

int zk_private_length_in_bytes(pairing_t pairing);

int zk_sign_init_length_in_bytes(pairing_t pairing);

int zk_sign_init_factor_length_in_bytes(pairing_t pairing);

int zk_blinded_length_in_bytes(pairing_t pairing);

int zk_blinding_factor_length_in_bytes(pairing_t pairing);

int zk_blinded_signature_length_in_bytes(pairing_t pairing);

int zk_signature_length_in_bytes(pairing_t pairing);

#ifdef __cplusplus
}
#endif
#endif
