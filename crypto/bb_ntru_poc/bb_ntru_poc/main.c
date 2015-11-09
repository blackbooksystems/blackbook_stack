//
//  main.c
//  bb_ntru_poc
//
//  Created by Bruce Daniel on 11/9/15.
//  Copyright © 2015 Bruce Daniel. All rights reserved.
//

#include "ntru.h"
#include "encparams.h"
#include <stdio.h>

int main(int argc, const char * argv[]) {
    
    
    
    struct NtruEncParams params = NTRU_DEFAULT_PARAMS_128_BITS; /*see encparams.h for more*/
    NtruRandGen rng_def = NTRU_RNG_DEFAULT;
    NtruRandContext rand_ctx_def;
    if (ntru_rand_init(&rand_ctx_def, &rng_def) != NTRU_SUCCESS)
        printf("rng fail\n");
    NtruEncKeyPair kp;
    if (ntru_gen_key_pair(&params, &kp, &rand_ctx_def) != NTRU_SUCCESS)
        printf("keygen fail\n");
    
    /* deterministic key generation from password */
    uint8_t seed[17];
    strcpy(seed, "my test passwordd");
    NtruRandGen rng_igf2 = NTRU_RNG_IGF2;
    NtruRandContext rand_ctx_igf2;
    if (ntru_rand_init_det(&rand_ctx_igf2, &rng_igf2, seed, strlen(seed)) != NTRU_SUCCESS)
        printf("rng fail\n");
    if (ntru_gen_key_pair(&params, &kp, &rand_ctx_igf2) != NTRU_SUCCESS)
        printf("keygen fail\n");
    
    uint8_t pubK[170];
    ntru_export_priv(&kp.priv, pubK);
    printf("----------------------------\n");
    printf("%u",pubK);
    printf("----------------------------\n");
    
    /* encryption */
    uint8_t msg[60];
    strcpy(msg, "whateverr12345whateverr12345whateverr12345whateverr12345");
    uint8_t enc[ntru_enc_len(&params)];
    if (ntru_encrypt(msg, strlen(msg), &kp.pub, &params, &rand_ctx_def, enc) != NTRU_SUCCESS)
        printf("encrypt fail\n");
//    printf(enc);
    /* release RNG resources */
    if (ntru_rand_release(&rand_ctx_def) != NTRU_SUCCESS)
        printf("rng fail\n");
    if (ntru_rand_release(&rand_ctx_igf2) != NTRU_SUCCESS)
        printf("rng fail\n");
    
    /* decryption */
    uint8_t dec[ntru_max_msg_len(&params)];
    uint16_t dec_len;
    if (ntru_decrypt((uint8_t*)&enc, &kp, &params, (uint8_t*)&dec, &dec_len) != NTRU_SUCCESS)
        printf("decrypt fail\n");
    
    /* export key to uint8_t array */
    uint8_t pub_arr[ntru_pub_len(&params)];
    ntru_export_pub(&kp.pub, pub_arr);
    
    /* import key from uint8_t array */
    NtruEncPubKey pub;
    ntru_import_pub(pub_arr, &pub);
    
    
    
    
    
    return 0;
}


