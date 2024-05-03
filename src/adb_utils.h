#include "custom_lwip_opts.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "tusb.h"
#include "adb.h"

#ifndef _ADB_UTILS_H_
#define _ADB_UTILS_H_

#ifdef __cplusplus
 extern "C" {
#endif

void print_utf16(uint16_t *temp_buf, size_t buf_len);
void check_command_result_cb(tuh_xfer_t* xfer);
bool check_command_result(tuh_xfer_t* xfer);
adb_usbConfiguration device_descriptor_is_adb(tuh_xfer_t* xfer,tusb_desc_device_t* desc_device, adb_connection* adb_connection);
int adb_usb_writeStringMessage(uint8_t daddr,uint8_t endpoint, uint32_t command, uint32_t arg0, uint32_t arg1, char * str);
int adb_usb_writeStringMessageWithCallback(uint8_t daddr,uint8_t endpoint, uint32_t command, uint32_t arg0, uint32_t arg1, char * str,tuh_xfer_cb_t complete_cb);
int adb_writeEmptyMessage(uint8_t daddr,uint8_t endpoint, uint32_t command, uint32_t arg0, uint32_t arg1,tuh_xfer_cb_t complete_cb);
void adb_usb_writeMessage_secondary(tuh_xfer_t* xfer,tuh_xfer_cb_t complete_cb);
void adb_usb_writeMessage_secondary_with_length(tuh_xfer_t* xfer,tuh_xfer_cb_t complete_cb,uint8_t * data, uint32_t length );
void listen_for_data_at_address(uint8_t daddr, uint8_t  bEndpointAddress,adb_connection *connection, size_t buflen);

int adb_usb_writeDataMessageWithCallback(uint8_t daddr,uint8_t endpoint, uint32_t command, uint32_t arg0, uint32_t arg1,uint8_t * data, uint32_t length,tuh_xfer_cb_t complete_cb);
int adb_usb_writeRandomStartupMessage(uint8_t daddr,uint8_t endpoint,tuh_xfer_cb_t complete_cb);
bool clear_endpoint_feature(uint8_t hub_addr, uint8_t hub_port, uint8_t feature,
                            tuh_xfer_cb_t complete_cb, uintptr_t user_data);
bool is_default(adb_usbConfiguration* config);
int convert_pub_key_pem_to_adb_format(const char *public_key_pem, uint8_t **adb_format);
int sign_key(const unsigned char *key, size_t keylen, char *data, size_t datalen, unsigned char *output, size_t *outputlen);
int sign_token(const char *token,size_t token_len, const char *private_key,
               unsigned char *signature, size_t *signature_len);
// void parse_config_descriptor(uint8_t dev_addr, tusb_desc_configuration_t const* desc_cfg);

#ifdef __cplusplus
 }
#endif

#endif /* #define _ADB_UTILS_H_
*/