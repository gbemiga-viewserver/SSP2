#include "adb_utils.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "adb.h"
#include "ch9.h"
#include "tusb.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/base64.h"
#define LANGUAGE_ID 0x0409
#define ADB_CLASS 0xff
#define ADB_SUBCLASS 0x42
#define ADB_PROTOCOL 0x1

adb_usbConfiguration NULL_CONFIGURATION;

#define BUF_COUNT   4


uint8_t buf_pool[BUF_COUNT][128];
uint8_t buf_owner[BUF_COUNT] = { 0 }; // device address that owns buffer

adb_usbConfiguration get_adb_handle_from_device_descriptor(uint8_t dev_addr, tusb_desc_configuration_t const* desc_cfg, adb_connection* adb_connection);
bool tuh_is_adb_interface(const tusb_desc_interface_t * interface);

bool is_default(adb_usbConfiguration* config){
  return config == &NULL_CONFIGURATION;
}
adb_usbConfiguration device_descriptor_is_adb(tuh_xfer_t* xfer, tusb_desc_device_t* desc_device, adb_connection* adb_connection)
{
  if ( XFER_RESULT_SUCCESS != xfer->result )
  {
    printf("Failed to get device descriptor\r\n");
    return NULL_CONFIGURATION;
  }

  uint8_t const daddr = xfer->daddr;

  printf("Device %u: ID %04x:%04x\r\n", daddr, desc_device->idVendor, desc_device->idProduct);
  printf("Device Descriptor:\r\n");
  printf("  bLength             %u\r\n"     , desc_device->bLength);
  printf("  bDescriptorType     %u\r\n"     , desc_device->bDescriptorType);
  printf("  bcdUSB              %04x\r\n"   , desc_device->bcdUSB);
  printf("  bDeviceClass        %u\r\n"     , desc_device->bDeviceClass);
  printf("  bDeviceSubClass     %u\r\n"     , desc_device->bDeviceSubClass);
  printf("  bDeviceProtocol     %u\r\n"     , desc_device->bDeviceProtocol);
  printf("  bMaxPacketSize0     %u\r\n"     , desc_device->bMaxPacketSize0);
  printf("  idVendor            0x%04x\r\n" , desc_device->idVendor);
  printf("  idProduct           0x%04x\r\n" , desc_device->idProduct);
  printf("  bcdDevice           %04x\r\n"   , desc_device->bcdDevice);

  // Get String descriptor using Sync API
  uint16_t temp_buf[128];

  printf("  iManufacturer       %u     "     , desc_device->iManufacturer);
  if (XFER_RESULT_SUCCESS == tuh_descriptor_get_manufacturer_string_sync(daddr, LANGUAGE_ID, temp_buf, sizeof(temp_buf)) )
  {
    print_utf16(temp_buf, TU_ARRAY_SIZE(temp_buf));
  }
  printf("\r\n");

  printf("  iProduct            %u     "     , desc_device->iProduct);
  if (XFER_RESULT_SUCCESS == tuh_descriptor_get_product_string_sync(daddr, LANGUAGE_ID, temp_buf, sizeof(temp_buf)))
  {
    print_utf16(temp_buf, TU_ARRAY_SIZE(temp_buf));
  }
  printf("\r\n");

  printf("  iSerialNumber       %u     "     , desc_device->iSerialNumber);
  if (XFER_RESULT_SUCCESS == tuh_descriptor_get_serial_string_sync(daddr, LANGUAGE_ID, temp_buf, sizeof(temp_buf)))
  {
    print_utf16(temp_buf, TU_ARRAY_SIZE(temp_buf));
  }
  printf("\r\n");

  printf("  bNumConfigurations  %u\r\n"     , desc_device->bNumConfigurations);

  //Get configuration descriptor with sync API
  if (XFER_RESULT_SUCCESS == tuh_descriptor_get_configuration_sync(daddr, 0, temp_buf, sizeof(temp_buf)))
  {
    return get_adb_handle_from_device_descriptor(daddr, (tusb_desc_configuration_t*) temp_buf, adb_connection);
  }
  return NULL_CONFIGURATION;
}

bool check_command_result(tuh_xfer_t* xfer) {

	if(xfer->result == XFER_RESULT_STALLED){
		printf("Stalled result.\n");
    	free(xfer->user_data);
		return false;
	}
	if(xfer->result == XFER_RESULT_FAILED){
		printf("Failed result.\n");
    	free(xfer->user_data);
		return false;
	}
	if(xfer->result == XFER_RESULT_INVALID){
		printf("Invalid result.\n");
    	free(xfer->user_data);
		return false;
	}

	if(xfer->result == XFER_RESULT_TIMEOUT){
		printf("Timeout result.\n");
    	free(xfer->user_data);
		return false;
	}
	if(xfer->result == XFER_RESULT_SUCCESS){
		printf("Success result.\n");
		return true;
	}
	free(xfer->user_data);
	return false;

	// printf("Getting language from the device\n");
	// char buf[4];
	// uint8_t rcode;

	// // rcode = tuh_get_string_descriptor(0, 0, 4, buf);
	// // if (rcode<0) {
	// // 	printf("Nah failed again bailing!!");
	// // 	return;
	// // }
    // // g_first_string_language = (buf[3] << 8) | buf[2];
	// printf("Finished setting language on the device = %d\n",g_first_string_language);
}


void check_command_result_cb(tuh_xfer_t* xfer){
	check_command_result(xfer);
  free(xfer->user_data);
}

const unsigned char SIGNATURE_PADDING[] = {
    0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
        0x04, 0x14
};

int sign_token3(const char *token, size_t token_len, const char *private_key,
               unsigned char *signature, size_t *signature_len) {
    int ret;
    mbedtls_pk_context pk;
    mbedtls_rsa_context *rsa;

    mbedtls_pk_init(&pk);

    // Parse the private key
    if ((ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)private_key,
                                    strlen(private_key) + 1, NULL, 0)) != 0) {
        mbedtls_pk_free(&pk);
        return ret;
    }

    rsa = mbedtls_pk_rsa(pk);

    // Apply the provided signature padding manually
    unsigned char padded_token[token_len + sizeof(SIGNATURE_PADDING)];
    memcpy(padded_token, SIGNATURE_PADDING, sizeof(SIGNATURE_PADDING));
    memcpy(padded_token + sizeof(SIGNATURE_PADDING), token, token_len);

    // Set the padding to none
    rsa->padding = MBEDTLS_RSA_PKCS_V15;
    rsa->hash_id = MBEDTLS_RSA_PKCS_V15;

    // Encrypt the padded token using the private key
    ret = mbedtls_rsa_private(rsa, NULL, NULL, padded_token, signature);

    if (ret == 0) {
        *signature_len = mbedtls_rsa_get_len(rsa);
    }

    mbedtls_pk_free(&pk);

    return ret;
}

// int sign_token(const char *token, size_t token_len, const char *private_key,
//                unsigned char *signature, size_t *signature_len) {
//     if (!RSA_sign(NID_sha1, token, token_len, signature, &signature_len, private_key)) {
//         return 0;
//     }

// }

int sign_token(const char *token, size_t token_len, const char *private_key,
               unsigned char *signature, size_t *signature_len) {

	  mbedtls_rsa_context rsa;
    int ret = 1;
    size_t i;

    mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );


    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    ret = mbedtls_pk_parse_key(&pk, (const unsigned char *) private_key,
                           strlen(private_key) + 1, NULL, 0);
    if (ret != 0) {
        printf("Problem parsing key!!\n=%d",ret);
        goto exit;
    }

    mbedtls_rsa_context * rsa2= mbedtls_pk_rsa(pk);

    mbedtls_mpi N = rsa2->N;
    mbedtls_mpi E = rsa2->E;
    mbedtls_mpi D = rsa2->D;
    mbedtls_mpi P = rsa2->P;
    mbedtls_mpi Q = rsa2->Q;
    mbedtls_mpi DP = rsa2->DP;
    mbedtls_mpi DQ = rsa2->DQ;
    mbedtls_mpi QP = rsa2->QP;

    if( ( ret = mbedtls_rsa_import( &rsa, &N, &P, &Q, &D, &E ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_rsa_import returned %d\n\n",
                        ret );
        goto exit;
    }
    if( ( ret = mbedtls_rsa_complete( &rsa ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_rsa_complete returned %d\n\n",
                        ret );
        goto exit;
    }
 
    printf("Checking the private key\n");

    if( ( ret = mbedtls_rsa_check_privkey( &rsa ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_rsa_check_privkey failed with -0x%0x\n", -ret );
        return  ret;
    }


    printf("Signing the hash\n");
    for( i = 0; i < 20; i++ )printf("%02X%s", token[i],( i + 1 ) % 16 == 0 ? "\r\n" : " " );
    if( ( ret = mbedtls_rsa_pkcs1_sign( &rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_NONE,
                                20, token,signature ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_rsa_pkcs1_sign returned -0x%0x\n\n", -ret );
    }

    printf("Printing signatue. Length =%d\n",rsa.len);
    for( i = 0; i < rsa.len; i++ )
        printf("%02X%s", signature[i],
                 ( i + 1 ) % 16 == 0 ? "\r\n" : " " );
    signature_len = rsa.len;

    exit:
      mbedtls_rsa_free( &rsa );
      mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
      mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
      mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
    return ret;
}

int sign_key(const unsigned char *key, size_t keylen, char *data, size_t datalen, unsigned char *output, size_t *outputlen)
{
    int ret;
    mbedtls_md_context_t hmac_ctx;
    const mbedtls_md_info_t *md_info;

    mbedtls_md_init(&hmac_ctx);

    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    if (md_info == NULL) {
        printf("Error: MD info not found\n");
        return -1;
    }

    ret = mbedtls_md_setup(&hmac_ctx, md_info, 1); // 1 for HMAC
    if (ret != 0) {
        printf("Error: mbedtls_md_setup returned -0x%04x\n", -ret);
        return ret;
    }

    ret = mbedtls_md_hmac_starts(&hmac_ctx, key, keylen);
    if (ret != 0) {
        printf("Error: mbedtls_md_hmac_starts returned -0x%04x\n", -ret);
        return ret;
    }

    ret = mbedtls_md_hmac_update(&hmac_ctx, data, datalen);
    if (ret != 0) {
        printf("Error: mbedtls_md_hmac_update returned -0x%04x\n", -ret);
        return ret;
    }

    ret = mbedtls_md_hmac_finish(&hmac_ctx, output);
    if (ret != 0) {
        printf("Error: mbedtls_md_hmac_finish returned -0x%04x\n", -ret);
        return ret;
    }

    *outputlen = mbedtls_md_get_size(md_info);

    mbedtls_md_free(&hmac_ctx);

    return 0;
}

void print_pem_error(int ret)
{
    switch (ret)
    {
        case -4144:
            printf("Error: No PEM header or footer found.\n");
            break;
        case -4352:
            printf("Error: PEM string is not as expected.\n");
            break;
        case -4480:
            printf("Error: Failed to allocate memory.\n");
            break;
        case -4608:
            printf("Error: RSA IV is not in hex-format.\n");
            break;
        case -4736:
            printf("Error: Unsupported key encryption algorithm.\n");
            break;
        case -4864:
            printf("Error: Private key password can't be empty.\n");
            break;
        case -4992:
            printf("Error: Given private key password does not allow for correct decryption.\n");
            break;
        case -5120:
            printf("Error: Unavailable feature, e.g. hashing/encryption combination.\n");
            break;
        case -5248:
            printf("Error: Bad input parameters to function.\n");
            break;
        default:
            printf("Unknown error.\n");
            break;
    }
}

#define KEY_LENGTH_WORDS 64
#define KEY_LENGTH_BYTES (KEY_LENGTH_WORDS * 4)

int convert_pub_key_pem_to_adb_format(const char *public_key_pem, uint8_t **adb_format) {
    mbedtls_pk_context pk;
    mbedtls_rsa_context *rsa;
    int ret;

    mbedtls_pk_init(&pk);

    ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char *)public_key_pem, strlen(public_key_pem) + 1);
    if (ret != 0) {
        printf("Unable to parse public key rt=%d", ret);
        mbedtls_pk_free(&pk);
        return -1;
    }

    rsa = mbedtls_pk_rsa(pk);

    if(rsa == NULL){
      printf("Unable to create RSA context\n");
      return -1;
    }

    int adb_format_size = convert_rsa_public_key_to_adb_format(rsa, adb_format);
    if (adb_format_size <= 0) {
        printf("Unable to convert public key to adb format=%d", adb_format_size);
        *adb_format = NULL;
    }

    mbedtls_pk_free(&pk);

    return adb_format_size;
}

#define KEY_LENGTH_WORDS 64
#define ADB_FORMAT_SIZE 524

int convert_rsa_public_key_to_adb_format(mbedtls_rsa_context *rsa, uint8_t **adb_format) {
    if (rsa == NULL) {
        printf("RSA is null bailing\n");
        return -1;
    }

    mbedtls_mpi n0inv, r32, r, rr;
    mbedtls_mpi_init(&n0inv);
    mbedtls_mpi_init(&r32);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&rr);

    mbedtls_mpi_set_bit(&r32, 32, 1);

    mbedtls_mpi_mod_mpi(&n0inv, &rsa->N, &r32);
    mbedtls_mpi_inv_mod(&n0inv, &n0inv, &r32);

    mbedtls_mpi_lset(&r, 1);
    mbedtls_mpi_shift_l(&r, KEY_LENGTH_WORDS * 32);
    mbedtls_mpi_exp_mod(&rr, &r, &rsa->N, &rsa->N, NULL);

    int myN[KEY_LENGTH_WORDS];
    int myRr[KEY_LENGTH_WORDS];

    mbedtls_mpi_write_binary(&rsa->N, (unsigned char *)myN, sizeof(myN));
    mbedtls_mpi_write_binary(&rr, (unsigned char *)myRr, sizeof(myRr));

    *adb_format = (uint8_t *)malloc(ADB_FORMAT_SIZE);
    if (*adb_format == NULL) {
        mbedtls_mpi_free(&n0inv);
        mbedtls_mpi_free(&r32);
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&rr);
        return -1;
    }

    uint8_t *buf = *adb_format;

    int32_t len = (int32_t)KEY_LENGTH_WORDS;
    memcpy(buf, &len, sizeof(int32_t));
    buf += sizeof(int32_t);

    uint32_t n0inv_uint32;
    mbedtls_mpi_write_binary(&n0inv, (unsigned char *)&n0inv_uint32, sizeof(uint32_t));
    int32_t n0inv_int = -(int32_t)n0inv_uint32;
    memcpy(buf, &n0inv_int, sizeof(int32_t));
    buf += sizeof(int32_t);

    for (int i = 0; i < KEY_LENGTH_WORDS; i++) {
        memcpy(buf, &myN[i], sizeof(int32_t));
        buf += sizeof(int32_t);
    }

    for (int i = 0; i < KEY_LENGTH_WORDS; i++) {
        memcpy(buf, &myRr[i], sizeof(int32_t));
        buf += sizeof(int32_t);
    }

    uint32_t exponent;
    mbedtls_mpi_write_binary(&rsa->E, (unsigned char *)&exponent, sizeof(uint32_t));
    int32_t exponent_int = (int32_t)exponent;
    memcpy(buf, &exponent_int, sizeof(int32_t));

    mbedtls_mpi_free(&n0inv);
    mbedtls_mpi_free(&r32);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&rr);

    return ADB_FORMAT_SIZE;
}

int sign_token2(const char *token,size_t token_len, const char *private_key,
               unsigned char *signature, size_t *signature_len)
{
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "mbedtls_pk_sign";
    int ret;

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers, strlen(pers))) != 0)
    {
        printf("Issue generating random seed = %d",ret);
        goto cleanup;
    }

    if ((ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)private_key,
                                    strlen(private_key) + 1, NULL, 0)) != 0)
    {
        printf("Issue parsing key = %d",ret);
        goto cleanup;
    }


    if ((ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA1, token, token_len,
                               signature, signature_len, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        printf("Issue signing token = %d",ret);
        goto cleanup;
    }

cleanup:
    mbedtls_pk_free(&pk);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return ret;
}

int sign_key2(const unsigned char *key, size_t keylen, char *data, size_t datalen, unsigned char *output, size_t *outputlen)
{

    mbedtls_pk_context pk;
    mbedtls_rsa_context *rsa;

    mbedtls_pk_init(&pk);
    int ret = mbedtls_pk_parse_key(&pk, key,
                                  keylen, NULL, 0);
    if (ret != 0) {
        printf("Unable to parse private key %s. Length is %d bailing return code is %d", key, keylen,ret);
        print_pem_error(ret);
        return ret;
        // handle error
    }

    rsa = mbedtls_pk_rsa(pk);

    // Set the padding mode to PKCS#1 v1.5
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, 0);

    ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, (const unsigned char*) data, datalen,
                          output, outputlen, NULL, NULL);
    if (ret != 0) {
      printf("Unable to sign token. Return code is %d Bailing", ret);
        return ret;
    }
    return 0;
}



uint16_t count_interface_total_len(tusb_desc_interface_t const* desc_itf, uint8_t itf_count, uint16_t max_len)
{
  uint8_t const* p_desc = (uint8_t const*) desc_itf;
  uint16_t len = 0;

  while (itf_count--)
  {
    // Next on interface desc
    len += tu_desc_len(desc_itf);
    p_desc = tu_desc_next(p_desc);

    while (len < max_len)
    {
      // return on IAD regardless of itf count
      if ( tu_desc_type(p_desc) == TUSB_DESC_INTERFACE_ASSOCIATION ) return len;

      if ( (tu_desc_type(p_desc) == TUSB_DESC_INTERFACE) &&
           ((tusb_desc_interface_t const*) p_desc)->bAlternateSetting == 0 )
      {
        break;
      }

      len += tu_desc_len(p_desc);
      p_desc = tu_desc_next(p_desc);
    }
  }

  return len;
}

/**
 * Performs ab out transfer to a USB device on an arbitrary endpoint.
 *
 * @param device USB bulk device.
 * @param device length number of bytes to read.
 * @param data target buffer.
 * @return number of bytes written, or error code in case of failure.
 */
int adb_usb_write(uint8_t daddr,uint8_t endpoint, uint16_t length, uint8_t * data,tuh_xfer_cb_t complete_cb, uintptr_t user_data)
{
	bool res = false;
	res =  usbh_edpt_xfer_with_callback(daddr,endpoint, data, length, complete_cb, user_data);
	if (res){
		return 0;
	}else{
		return -1;
	}
}

void adb_usb_writeMessage_complete(tuh_xfer_t* xfer){
	if(xfer->result == XFER_RESULT_STALLED){
		printf("Stalled result.\n");
		return;
	}
	if(xfer->result == XFER_RESULT_FAILED){
		printf("Failed result.\n");
		return;
	}
	if(xfer->result == XFER_RESULT_INVALID){
		printf("Invalid result.\n");
		return;
	}

	if(xfer->result == XFER_RESULT_TIMEOUT){
		printf("Timeout result.\n");
		return;
	}
	if(xfer->result == XFER_RESULT_SUCCESS){
		printf("Success result.\n");
		return;
	}
	printf("Done diggy done !!");
}

void adb_usb_writeMessage_secondary(tuh_xfer_t* xfer,tuh_xfer_cb_t complete_cb)
{
  printf("Sending second message\n");
  char * str = xfer->user_data;
  uint32_t length = strlen(str) + 1;
  uint8_t * data = (uint8_t*)str;
	adb_usb_write(xfer->daddr, xfer->ep_addr ,length,data, complete_cb, 0 );
}

void adb_usb_writeMessage_secondary_with_length(tuh_xfer_t* xfer,tuh_xfer_cb_t complete_cb,uint8_t * data, uint32_t length )
{
  printf("Sending second data message\n");

  // for(uint32_t i=0; i<length; i++)
  //   {
  //     if (i%16 == 0) printf("\r\n  ");
  //     printf("%02X ", data[i]);
  //   }

	adb_usb_write(xfer->daddr, xfer->ep_addr ,length,data, complete_cb, 0 );
}

static void adb_printMessage(adb_message * message)
{
	switch(message->command)
	{
	case A_OKAY:
		printf("OKAY message [%lx] %ld %ld\n", message->command, message->arg0, message->arg1);
		break;
	case A_CLSE:
		printf("CLSE message [%lx] %ld %ld\n", message->command, message->arg0, message->arg1);
		break;
	case A_WRTE:
		printf("WRTE message [%lx] %ld %ld, %ld bytes\n", message->command, message->arg0, message->arg1, message->data_length);
		break;
	case A_CNXN:
		printf("CNXN message [%lx] %ld %ld\n", message->command, message->arg0, message->arg1);
		break;
	case A_SYNC:
		printf("SYNC message [%lx] %ld %ld\n", message->command, message->arg0, message->arg1);
		break;
	case A_OPEN:
		printf("OPEN message [%lx] %ld %ld\n", message->command, message->arg0, message->arg1);
		break;
	case A_AUTH:
		printf("AUTH message [%lx] %ld %ld %ld bytes\n\n", message->command, message->arg0, message->arg1,message->data_length);
		break;
	default:
		printf("WTF message [%lx] %ld %ld\n", message->command, message->arg0, message->arg1);
		break;
	}
}


int adb_usb_writeStringMessageWithCallback(uint8_t daddr,uint8_t endpoint, uint32_t command, uint32_t arg0, uint32_t arg1, char * str,tuh_xfer_cb_t complete_cb)
{
  printf("Writing ADB USB string message to %d end point %d\n", daddr, endpoint);
  adb_message message;
	uint32_t length,count, sum = 0;
	uint8_t * x;
	uint8_t rcode;

	// Calculate data checksum
  length = strlen(str) + 1;
  count = length;
  x = (uint8_t*)str;
  while(count-- > 0) sum += *x++;

	// Fill out the message record.
	message.command = command;
	message.arg0 = arg0;
	message.arg1 = arg1;
	message.data_length = length;
	message.data_check = sum;
	message.magic = command ^ 0xffffffff;

	printf("OUT << "); adb_printMessage(&message);

  printf("Sending callback message\n");
	rcode = adb_usb_write(daddr, endpoint, sizeof(adb_message), (uint8_t*)&message, complete_cb, str);
	if (rcode) return rcode;
  //tuh_task();
 
	return rcode;
}


int adb_writeEmptyMessage(uint8_t daddr,uint8_t endpoint, uint32_t command, uint32_t arg0, uint32_t arg1,tuh_xfer_cb_t complete_cb)
{
	adb_message message;
uint8_t rcode;
	message.command = command;
	message.arg0 = arg0;
	message.arg1 = arg1;
	message.data_length = 0;
	message.data_check = 0;
	message.magic = command ^ 0xffffffff;

	printf("OUT << "); adb_printMessage(&message);

  printf("Sending callback message\n");
	rcode = adb_usb_write(daddr, endpoint, sizeof(adb_message), (uint8_t*)&message, complete_cb, 0);
	if (rcode) return rcode;
  //tuh_task();
 
	return rcode;
}

int adb_usb_writeDataMessageWithCallback(uint8_t daddr,uint8_t endpoint, uint32_t command, uint32_t arg0, uint32_t arg1,uint8_t * data, uint32_t length,tuh_xfer_cb_t complete_cb)
{
  printf("Writing ADB USB string message to %d end point %d\n", daddr, endpoint);
  adb_message message;
	uint32_t count, sum = 0;
	uint8_t * x;
	uint8_t rcode;

  count = length;
  x = (uint8_t*)data;
  while(count-- > 0) sum += *x++;

	// Fill out the message record.
	message.command = command;
	message.arg0 = arg0;
	message.arg1 = arg1;
	message.data_length = length;
	message.data_check = sum;
	message.magic = command ^ 0xffffffff;

//#ifdef DEBUG
	printf("OUT << "); adb_printMessage(&message);
//#endif

  printf("Sending callback message\n");
	rcode = adb_usb_write(daddr, endpoint, sizeof(adb_message), (uint8_t*)&message, complete_cb, length);
	if (rcode) return rcode;
  //tuh_task();
 
	return rcode;
}

int adb_usb_writeStringMessage(uint8_t daddr,uint8_t endpoint, uint32_t command, uint32_t arg0, uint32_t arg1, char * str){
  return adb_usb_writeStringMessageWithCallback(daddr, endpoint, command, arg0, arg1, str,adb_usb_writeMessage_secondary);
}

//--------------------------------------------------------------------+
// Buffer helper
//--------------------------------------------------------------------+

// get an buffer from pool
uint8_t* get_hid_buf(uint8_t daddr)
{

  for(size_t i=0; i<BUF_COUNT; i++)
  {
    if (buf_owner[i] == daddr)
    {
      return buf_pool[i];
    }
  }

  for(size_t i=0; i<BUF_COUNT; i++)
  {
    if (buf_owner[i] == 0)
    {
      buf_owner[i] = daddr;
      return buf_pool[i];
    }
  }

  // out of memory, increase BUF_COUNT
  return NULL;
}

// free all buffer owned by device
void free_hid_buf(uint8_t daddr)
{
  for(size_t i=0; i<BUF_COUNT; i++)
  {
    if (buf_owner[i] == daddr) buf_owner[i] = 0;
  }
}

void hid_report_received(tuh_xfer_t* xfer)
{
  // Note: not all field in xfer is available for use (i.e filled by tinyusb stack) in callback to save sram
  // For instance, xfer->buffer is NULL. We have used user_data to store buffer when submitted callback
  adb_connection* connection = (adb_connection*) xfer->user_data;
  uint8_t* buf = (uint8_t*) connection->buffer;
  bool should_rerequest_data = true;

  if (xfer->result == XFER_RESULT_SUCCESS)
  {
    printf("--------------------------[dev %u: ep %02x] Incoming data reciever:------------------------", xfer->daddr, xfer->ep_addr);

    should_rerequest_data = connection->eventHandler(connection, ADB_CONNECTION_RECEIVE,xfer->actual_len,buf);

    // for(uint32_t i=0; i<xfer->actual_len; i++)
    // {
    //   if (i%16 == 0) printf("\r\n  ");
    //   printf("%02X ", buf[i]);
    // }
    printf("\r\n");
  }else{
    printf("-------------------------Received incoming data call but status was not success =%d----------------------\n",xfer->result);
  }

  if (should_rerequest_data){
    // continue to submit transfer, with updated buffer
    // other field remain the same
    xfer->buflen = 128;
    xfer->buffer = buf;

    printf("------------------------- Now resubmitting buffer ----");
    tuh_edpt_xfer(xfer);
    printf("------------------------- Done resubmitting buffer ----");
  }else{
    printf("Not re requesting data as the event handler told us not to\n");
  }
}

bool clear_endpoint_feature(uint8_t hub_addr, uint8_t hub_port, uint8_t feature,
                            tuh_xfer_cb_t complete_cb, uintptr_t user_data)
{
  tusb_control_request_t const request =
  {
    .bmRequestType_bit =
    {
      .recipient = TUSB_REQ_RCPT_ENDPOINT,
      .type      = TUSB_REQ_TYPE_STANDARD,
      .direction = TUSB_DIR_OUT
    },
    .bRequest = USB_REQUEST_CLEAR_FEATURE,
    .wValue   = feature,
    .wIndex   = hub_port,
    .wLength  = 0
  };

  tuh_xfer_t xfer =
  {
    .daddr       = hub_addr,
    .ep_addr     = 0,
    .setup       = &request,
    .buffer      = NULL,
    .complete_cb = complete_cb,
    .user_data   = user_data
  };

  TU_LOG2("HUB Clear Feature: %s, addr = %u port = %u\r\n", feature, hub_addr, hub_port);
  TU_ASSERT( tuh_control_xfer(&xfer) );
  return true;
}
adb_usbConfiguration get_adb_interface_endpoints(uint8_t daddr, tusb_desc_interface_t const *desc_itf, uint16_t max_len,adb_connection *connection)
{
  adb_usbConfiguration handle;
  handle.address = daddr;
  uint8_t const *p_desc = (uint8_t const *) desc_itf;
  // Endpoint descriptor
  p_desc = tu_desc_next(p_desc);
  tusb_desc_endpoint_t const * desc_ep = (tusb_desc_endpoint_t const *) p_desc;

  for(int i = 0; i < desc_itf->bNumEndpoints; i++)
  {
    printf("Iterating end point !!\n");
    if (TUSB_DESC_ENDPOINT != desc_ep->bDescriptorType) return;
    if(tu_edpt_dir(desc_ep->bEndpointAddress) == TUSB_DIR_IN)
    {
      
      handle.inputEndPointAddress = desc_ep->bEndpointAddress;
      if ( tuh_edpt_open(daddr, desc_ep) ){
         listen_for_data_at_address(daddr, desc_ep->bEndpointAddress, connection, 128);
      }
      //tuh_edpt_open(daddr, desc_ep);
    }
    else{
       handle.outputEndPointAddress = desc_ep->bEndpointAddress; 
       if ( tuh_edpt_open(daddr, desc_ep) ){
        printf("Opened output endpoint\n");
      }
    }

    p_desc = tu_desc_next(p_desc);
    desc_ep = (tusb_desc_endpoint_t const *) p_desc;
  }
  return handle;
}

void listen_for_data_at_address(uint8_t daddr, uint8_t bEndpointAddress,adb_connection *connection, size_t buflen){
      printf("Now registering callback to handle any data for device %d\n", daddr);
      uint8_t* buf = get_hid_buf(daddr);
      if (!buf) {
        printf("Out of memory !!!");
        return; // out of memory
      }
      connection->buffer = buf;
      tuh_xfer_t xfer =
      {
        .daddr       = daddr,
        .ep_addr     = bEndpointAddress,
        .buflen      = buflen,
        .buffer      = buf,
        .complete_cb = hid_report_received,
        .user_data   = (uintptr_t) connection, // since buffer is not available in callback, use user data to store the buffer
      };
        printf("Finished registering callback to handle any data\n");
      // submit transfer for this EP
      tuh_edpt_xfer(&xfer);
}

void print_adb_usbConfiguration(const adb_usbConfiguration *config) {
	printf("adb_usbConfiguration {\n");
	printf("  address: 0x%02X\n", config->address);
	printf("  configuration: 0x%02X\n", config->configuration);
	printf("  interface: 0x%02X\n", config->interface);
	printf("  inputEndPointAddress: 0x%02X\n", config->inputEndPointAddress);
	printf("  outputEndPointAddress: 0x%02X\n", config->outputEndPointAddress);
	printf("}\n");
}

adb_usbConfiguration get_adb_handle_from_device_descriptor(uint8_t dev_addr, tusb_desc_configuration_t const* desc_cfg, adb_connection* adb_connection)
{
  uint8_t const* desc_end = ((uint8_t const*) desc_cfg) + tu_le16toh(desc_cfg->wTotalLength);
  uint8_t const* p_desc   = tu_desc_next(desc_cfg);

  // parse each interfaces
  while( p_desc < desc_end )
  {
    uint8_t assoc_itf_count = 1;

    // Class will always starts with Interface Association (if any) and then Interface descriptor
    if ( TUSB_DESC_INTERFACE_ASSOCIATION == tu_desc_type(p_desc) )
    {
      tusb_desc_interface_assoc_t const * desc_iad = (tusb_desc_interface_assoc_t const *) p_desc;
      assoc_itf_count = desc_iad->bInterfaceCount;

      p_desc = tu_desc_next(p_desc); // next to Interface
    }
    

    // must be interface from now
    if( TUSB_DESC_INTERFACE != tu_desc_type(p_desc) ) return NULL_CONFIGURATION;
    tusb_desc_interface_t const* desc_itf = (tusb_desc_interface_t const*) p_desc;

    uint16_t const drv_len = count_interface_total_len(desc_itf, assoc_itf_count, (uint16_t) (desc_end-p_desc));
             // probably corrupted descriptor

    if (tuh_is_adb_interface(desc_itf)){

        adb_usbConfiguration result = get_adb_interface_endpoints(dev_addr, desc_itf, drv_len, adb_connection);
        result.interface = desc_itf->bInterfaceNumber;
        result.configuration = desc_cfg->bConfigurationValue;
        print_adb_usbConfiguration(&result);
        return result;
    }
  
    if(drv_len < sizeof(tusb_desc_interface_t)) return NULL_CONFIGURATION;

    // next Interface or IAD descriptor
    p_desc += drv_len;
  }
  return NULL_CONFIGURATION;
}
bool tuh_is_adb_interface(const tusb_desc_interface_t * interface)
{

	// Check if the interface has exactly two endpoints.
	if (interface->bNumEndpoints!=2) {
		return false;
	}

	// Check if the endpoint supports bulk transfer.
	if (interface->bInterfaceProtocol != ADB_PROTOCOL){
		return false;
	} 
	if (interface->bInterfaceClass != ADB_CLASS){
		return false;
	} 
	if (interface->bInterfaceSubClass != ADB_SUBCLASS){
		return false;
	}

	return true;
}

/// Invoked when device is unmounted (bus reset/unplugged)
void tuh_umount_cb(uint8_t daddr)
{
  printf("Device removed, address = %d\r\n", daddr);
  //free_hid_buf(daddr);
}


//--------------------------------------------------------------------+
// String Descriptor Helper
//--------------------------------------------------------------------+

void _convert_utf16le_to_utf8(const uint16_t *utf16, size_t utf16_len, uint8_t *utf8, size_t utf8_len) {
    // TODO: Check for runover.
    (void)utf8_len;
    // Get the UTF-16 length out of the data itself.

    for (size_t i = 0; i < utf16_len; i++) {
        uint16_t chr = utf16[i];
        if (chr < 0x80) {
            *utf8++ = chr & 0xffu;
        } else if (chr < 0x800) {
            *utf8++ = (uint8_t)(0xC0 | (chr >> 6 & 0x1F));
            *utf8++ = (uint8_t)(0x80 | (chr >> 0 & 0x3F));
        } else {
            // TODO: Verify surrogate.
            *utf8++ = (uint8_t)(0xE0 | (chr >> 12 & 0x0F));
            *utf8++ = (uint8_t)(0x80 | (chr >> 6 & 0x3F));
            *utf8++ = (uint8_t)(0x80 | (chr >> 0 & 0x3F));
        }
        // TODO: Handle UTF-16 code points that take two entries.
    }
}

// Count how many bytes a utf-16-le encoded string will take in utf-8.
int _count_utf8_bytes(const uint16_t *buf, size_t len) {
    size_t total_bytes = 0;
    for (size_t i = 0; i < len; i++) {
        uint16_t chr = buf[i];
        if (chr < 0x80) {
            total_bytes += 1;
        } else if (chr < 0x800) {
            total_bytes += 2;
        } else {
            total_bytes += 3;
        }
        // TODO: Handle UTF-16 code points that take two entries.
    }
    return (int) total_bytes;
}

void print_utf16(uint16_t *temp_buf, size_t buf_len) {
    size_t utf16_len = ((temp_buf[0] & 0xff) - 2) / sizeof(uint16_t);
    size_t utf8_len = (size_t) _count_utf8_bytes(temp_buf + 1, utf16_len);
    _convert_utf16le_to_utf8(temp_buf + 1, utf16_len, (uint8_t *) temp_buf, sizeof(uint16_t) * buf_len);
    ((uint8_t*) temp_buf)[utf8_len] = '\0';

    printf((char*)temp_buf);
}

