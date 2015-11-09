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
    
//    printf("The argument supplied is %s\n", argv[1]);
    
    struct NtruEncParams params = NTRU_DEFAULT_PARAMS_128_BITS; /*see encparams.h for more*/
    NtruRandGen rng_def = NTRU_RNG_DEFAULT;
    NtruRandContext rand_ctx_def;
    if (ntru_rand_init(&rand_ctx_def, &rng_def) != NTRU_SUCCESS)
        printf("rng fail\n");
    NtruEncKeyPair kp;
    if (ntru_gen_key_pair(&params, &kp, &rand_ctx_def) != NTRU_SUCCESS)
        printf("keygen fail\n");
    
    /* deterministic key generation from password */
//    uint8_t seed[sizeof(argv[1])];
//    strcpy(seed, argv[1]);
    
    uint8_t seed[sizeof("testttsdsdfsfdfsdfsrrttrwwerwerwer34536")];
    strcpy(seed, "testttsdsdfsfdfsdfsrrttrwwerwerwer34536");
    
    
    NtruRandGen rng_igf2 = NTRU_RNG_IGF2;
    NtruRandContext rand_ctx_igf2;
    if (ntru_rand_init_det(&rand_ctx_igf2, &rng_igf2, seed, strlen(seed)) != NTRU_SUCCESS)
        printf("rng fail\n");
    if (ntru_gen_key_pair(&params, &kp, &rand_ctx_igf2) != NTRU_SUCCESS)
        printf("keygen fail\n");
    
    
    
    uint16_t pub_len=ntru_pub_len(&params);
    uint16_t priv_len=ntru_priv_len(&params);
    printf("pub len: %i\n",pub_len);
    printf("priv len: %i\n",priv_len);
    
    uint8_t pubK[pub_len];
    uint8_t privK[priv_len];
//
    ntru_export_pub(&kp.pub, pubK);
    ntru_export_priv(&kp.priv, privK);

//    printf("----------------------------\n");
//    pubK[0];
    
//    printf("%u\n",pubK[0]);
//    printf("%u\n",privK[1]);
//    printf("%u\n",pubK[2]);
//    printf("----------------------------\n");
    
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
//    
//    /* export key to uint8_t array */
//    uint8_t pub_arr[ntru_pub_len(&params)];
//    ntru_export_pub(&kp.pub, pub_arr);
//    
//    /* import key from uint8_t array */
//    NtruEncPubKey pub;
//    ntru_import_pub(pub_arr, &pub);
    
    
    FILE *privFile = fopen("priv.key", "w");
    
    for(int i;i<priv_len;i++){
        fprintf(privFile, "%d", privK[i]);
    }
    fclose(privFile);
    
    FILE *pubFile = fopen("pub.key", "w");
  
    for(int i;i<pub_len;i++){
        fprintf(pubFile, "%d", pubK[i]);
    }
    fclose(pubFile);
    
    
    
    return 0;
}


