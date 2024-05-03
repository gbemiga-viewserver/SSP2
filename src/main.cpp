#include <string.h>
#include <stdlib.h>


#include "custom_lwip_opts.h"
#include "lwip/apps/httpd.h"
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "adb.h"
#include "lwipopts.h"
#include "cgi.h"
#include "ssi.h"
#include "bsp/board.h"
#include "tusb.h"
#include "adb.h"
#include "ch9.h"
#include "adb_utils.h"
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"

// GPIOs for Leds
#define LED1    22
#define LED2    21
#define LED3    27
#define LED4    28


// #define LED1	18
// #define LED2	19
// #define LED3	20
// #define LED4	21
#define AUTH_MESSAGE_SIZE	257


//usb_device * g_adb_device;
adb_usbConfiguration  g_config;
adb_connection g_adb_connection;

uint16_t g_first_string_language; // First supported lang§uage (for retrieving Strings)
uint8_t g_address;
uint8_t g_signed_auth_data[256];
//adb_connection * logcat, * connection;
tusb_desc_device_t desc_device;
bool has_connected = false;
bool has_attempted_auth = true;

const unsigned char * PUBLIC_KEY = (const unsigned char*) "-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCgKCAQEA0ZxBOxeZQWZ8T+4r6koR\n\
6UVixqDELLjeBxM9MZorDzV3jRkIiDFT9pPar2qh9SFpV548VGBAgS8g3ichQSi7\n\
qw3vxuB+dSKMOQJ4He+PLp+aEXEVvQyjoCXy4p2UqEfmZkpVFNmRsOjwzvJyBR13\n\
72Bi+QZg+wTNkntmdm6GMMrSEQlNFW/F6GUL2Ij419w04HoROHiVucwTZ8ErrHyo\n\
3m0q1OAPpXp+IdEWZnmTzc/E7df0mYj65yxfVRCsEb2mEeOaioEFBIL2VZHQDfSF\n\
VnD7PaNjXlcOW7XOV8I7/cCoc294SR0IF7uUypYdV5fih1FvyloNVdVRaq4C5s4J\n\
PwIDAQAB\n\
-----END RSA PUBLIC KEY-----";

const unsigned char * PUBLIC_KEY_ADB_FORMAT = (const unsigned char*) "QAAAAPcsuEs5q3Ot6J3HWEgUpMYhYZ+eCWrukDoUjm3+HawEd+wQAiV8/g41BjbXxuaA93KHBCQ0UniRuDCFLUWh/kwiyrVe4KMdmkh4BcBCtgS7/gO6pOYYhvBrhzTHJTdsrmWbnWm/qTsdDYsJe9UNjkHcKutQimzhKETmk4CZwWFoH7ToEqe4c+HTTYJYtYwRJtzwtsc8LVFcqxljNK2ELLORqaIuASXm+wdZ/ShcmcEpbGZvWVlc4K3KcqGGtw0bSK+NEUm8ogoChLOCZPgDyYAHJ+LqMYZgRZzeFoJ4wIdJTwne36XecKfKTI9YlFnAQ/BzldamUZFy2iz3Vi14UMJUkwGZlUx1H8a3BbessYB7TsMuyrODEXXpFSLLor6SsYobOQ+z6nkcdpf7NyabgZ2VbkFXporemlye1MjSBQJlXYnEMLTv74/2nP7+8lIJtXzo/6pCep7RZErffA8xmiOsqUOA6EoFInzBOa4IC8DosGJADR8NzcctR6lFlXWbAmcKY8u7hq8DfaAlOkPWytoPBMGplbn9qgEHXWTKDqbDG7wnk/HgAI8zQN25+xrnmZug4onajNWKj3JfGJk2LlMzZzZvyqDl/gvZ5SkRMqfkCnyiC5a1wfhA/gg9yHWgqx2Ka2sfxU+JA3jtcfu/dP21G/5gZ9/XL5kNCNHiC132ZFCrjAEAAQA= microcontroller@storystarter.local";


const unsigned char * PRIVATE_KEY = (const unsigned char*) "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEogIBAAKCAQEAmQGTVMJQeC1W9yzacpFRptaVc/BDwFmUWI9Myqdw3qXf3glP\
SYfAeIIW3pxFYIYx6uInB4DJA/hkgrOEAgqivEkRja9IGw23hqFyyq3gXFlZb2Zs\
KcGZXCj9WQf75iUBLqKpkbMshK00YxmrXFEtPMe28NwmEYy1WIJN0+FzuKcS6LQf\
aGHBmYCT5kQo4WyKUOsq3EGODdV7CYsNHTupv2mdm2WubDclxzSHa/CGGOakugP+\
uwS2QsAFeEiaHaPgXrXKIkz+oUUthTC4kXhSNCQEh3L3gObG1zYGNQ7+fCUCEOx3\
BKwd/m2OFDqQ7moJnp9hIcakFEhYx53orXOrOQIDAQABAoIBABg706X9ENm39Ko5\
hG/Y7GHMYud2CoUQqxpLuBHw60OYahi0yMYQpj9v+0dO4P4kwws8vonFsBDc6q54\
2FOqc5P2zrzuIjGGvqaoM5I+b+awkCXAxyjl7PBX3aiYRyFwgvtr8AePpWFuPXnk\
uutoQA38Y9FKTQ1CiAZ4vPLuJnH8ZWWS0j+qAwPdc4IwdbJfspHPh8dEF3Gdkiu7\
KZUIqCPIEmbo1X/cdV0ahcexpuoG0YH6SJxLZc12ogTY5Uafnw/7SnikEmvHV2Ll\
lNGciXEF8v46/1RSSfajqqtEe8XRqrnUEQGTq+zr62Ap9g3Ev9QP59vrU7Tc21Rg\
pWU2KXECgYEA2EbDVYZ5xAKVmGehiGrn386yVnuxHh5qj3ANEsJyUoiGkyooEYTF\
Dmt1DQjbnybThxC1ZSm9mtr8ViT/MADCjy9mKarBrmwrtX4nQKanOJYhFUKCCbk6\
LfwxEfCq5kC7N5p/gsKPYvXuWhFOkIaFY0EfJusscrEGpwKfW9xwg1cCgYEAtRve\
Px4TucUTP2AnHkWmxq+MvhyYwXpLKO21F3Owph/lWsUDsc0OuB8UiwEijOKLL5ij\
3o9N9f7J6aQb4kgqeYr/qKgd1WPqVYsCLN0SInUWEpT/Md27b+RzHYeX6QUemuzW\
PmdJezDynih5nC7NuTAHeu7N5TlqIv2e6cx8O+8CgYAWAT0mmoQRGWI3G3Qn+RiW\
gOVMP1GKCvY0meX6nqYbF6D5oDRrc+LI0M4cAWa3DrA+8chC/rg35Uf/S8xbCfjB\
sMToQGNsZ70avjcoMMyayUucaiPo8VumCh7EAISi4LsrsSCAIWONYhBaQaCIu+ce\
biXJQ+xFzxUqMO4d3pPkCQKBgB04h91LLweUIozhKK6bslLwVBcAai0dXC8YW1WT\
VvcWwlyo2PXBDhTq/teGsVpl2ustB5OLL5r3JwDJd65E0oWVxbYimd2qJ07yBMHU\
UW650XviCmKzUeC1zVUAYaQ5LTz15YNgCt0TgrG9+hEXBB5S/4H4McRART2sCg3S\
7mCFAoGAA1FPsk2/GsMkb/qmwfjSPyv2iDeIcFlcfE9MPMXqEEhTxZpR2gDbdazT\
s3c52s5xAp+si/QXt1gY5YbZ1KHDwhQ+jr4mSQDSk+kbCT/QqfeNpqDh5IC3gjXJ\
BgTfDUlIc3sYt0bywjazIgrgeRWL5XAvrbdckX6TG1VyBYNf9OI=\n\
-----END RSA PRIVATE KEY-----";
// const unsigned char * PRIVATE_KEY = (const unsigned char*) "-----BEGIN RSA PRIVATE KEY-----\n\
// MIIEowIBAAKCAQEA0ZxBOxeZQWZ8T+4r6koR6UVixqDELLjeBxM9MZorDzV3jRkI\n\
// iDFT9pPar2qh9SFpV548VGBAgS8g3ichQSi7qw3vxuB+dSKMOQJ4He+PLp+aEXEV\n\
// vQyjoCXy4p2UqEfmZkpVFNmRsOjwzvJyBR1372Bi+QZg+wTNkntmdm6GMMrSEQlN\n\
// FW/F6GUL2Ij419w04HoROHiVucwTZ8ErrHyo3m0q1OAPpXp+IdEWZnmTzc/E7df0\n\
// mYj65yxfVRCsEb2mEeOaioEFBIL2VZHQDfSFVnD7PaNjXlcOW7XOV8I7/cCoc294\n\
// SR0IF7uUypYdV5fih1FvyloNVdVRaq4C5s4JPwIDAQABAoIBABje0V6Rjj2US2uw\n\
// dsV1xGpJMU8gBCbKSI3OWpRoFnPXhDfZoImIUM4Q/QGTRWQwcq9StxXL1dt+HAg/\n\
// 3FI+4wWIwcp3GIoNb1XUVSw4IGUHyuAG6u1jcoat+gOpbtoIre21JCM1LXQwL2Je\n\
// oei5dmGQri2d9CPUjg+zVJT4yDNBpmUWo91YtGjf+BPT9fhPmXRb/oECUKBDc9nA\n\
// EZbBFriW0Hzm6PwUTtVEeV2/fDMsw+hI8wFR4FpiCbyQKpVFms/kGnvmy06F9P2g\n\
// sSt6F+36m6RI1EwpxgB7gc2jwv3fOL73si6e8U1WvKWMBmSl2/LPVmWsOIcCssz9\n\
// CGBMrQECgYEA8gNtDRWsJKfNV31njLAwrfDVItQRz8d+vN9o4/iRpQT5aDgPLV44\n\
// UnYmYDhpNDhfsNwq8jP5g1FKNdmpB6ssbcMcF5nJqz6wh7vbG00MHTvACEReTbwm\n\
// jZgdyB0Q6tj3WF/GNXu6LcNKL4+EUiU+J0phxa54gCYutEbJ9zvbZO0CgYEA3blt\n\
// mfEgzoAvYHpW1AwYgYnNZYk/NpX8nCfSHM+/YMPvxi1tqUqCEx/4MFAC4Iy29NMY\n\
// nwejbbNNe7Nw4252Wl2QY1XPWAR2qXpyy4el7JRJY7wFELp7wb5G1GnqtjnIkXQK\n\
// q/Gx3iO3pquCH/sqTepkTLWbBsI+hXJhwxBxrVsCgYAkY3t8IiwV/t0TMJnnP36y\n\
// SKnjaLuc4EQgJf9hd7h+dXcCwpsVmTsiuv0eLp0y6t8IerJCZKo5onlkC2ws6QHv\n\
// Jw0MR2VZSD3Gyuow+q69noRLOexsB8RMOfkQY75tcV4PfacR156wztJSwGOG7m6f\n\
// /cEhthAMRLF1DcfEUs20KQKBgHhgnPWwKUyT4aTypsN3UbK6my4eJpi/M6egIv4L\n\
// eG7T0hD5Rwlbb2VsvPWV6wn4u7gOB9cHcZ40c8PON2Ly7QTAuYyE4Q57VeVLmpmP\n\
// qvDXzUR9pw5fAKO+Z3wZiRmoI5F8u/KART5CjAnMIdi1J1GoCQ5wppszyHfxEsyx\n\
// 19XzAoGBAKGFNahGVwDcW0JTJBFEzs3gwWZCARiNgo4x/J97zdLc9QMtIIvC0ph/\n\
// npeM03v7kwz3maCBqiv0ewu3wnMyctEjTuAOBSIjDZa+7TJc6CV0G8dW8L6HCrWL\n\
// UXpYEPePQqbl7cD7m8zOS3YWj9zfFOnyq5GSoIWhgkBcvin6oF/b\n\
// -----END RSA PRIVATE KEY-----";



char* bytes_to_string(const uint8_t* byte_array, size_t byte_array_len)
{
    char* string = (char*) malloc(byte_array_len + 1); // +1 for the null-terminator
    if (string == NULL) return NULL; // Failed to allocate memory

    memcpy(string, byte_array, byte_array_len);
    string[byte_array_len] = '\0'; // Null-terminate the string

    return string;
}

void run_server() {

    tusb_init();

 	tuh_init(BOARD_TUH_RHPORT);
	// logcat = adb_addConnection("shell:exec logcat -s microbridge:*", true, adbEventHandler);
	// connection = adb_addConnection("tcp:4567", true, adbEventHandler);
	
    httpd_init();
    ssi_init(&g_adb_connection);
    cgi_init(&g_config, &g_adb_connection);
    printf("Http server initialized.\n");
    // infinite loop for now
    while (1)
 	{
        // printf("Adb polling loop\n");
		// 
		tuh_task();
		//adb_poll();
 	}

}

void set_io_port(int gpio){
	gpio_init(gpio);
	gpio_set_dir(gpio, GPIO_OUT);
	gpio_put(gpio, 0);
}

int main() {
	g_adb_connection.receiverStatus = ADB_DEVICE_DISCONNECTED;
    board_init();
    stdio_init_all();
    

    if (cyw43_arch_init()) {
        printf("failed to initialise\n");
        return 1;
    }
    cyw43_arch_enable_sta_mode();
    // this seems to be the best be can do using the predefined `cyw43_pm_value` macro:
    // cyw43_wifi_pm(&cyw43_state, CYW43_PERFORMANCE_PM);
    // however it doesn't use the `CYW43_NO_POWERSAVE_MODE` value, so we do this instead:
    // cyw43_wifi_pm(&cyw43_state, cyw43_pm_value(CYW43_NO_POWERSAVE_MODE, 20, 1, 1, 1));
    cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
	set_io_port(LED1);
	set_io_port(LED2);
	set_io_port(LED3);
	set_io_port(LED4);
    printf("Connecting to WiFi... %s, %s\n",WIFI_SSID,WIFI_PASSWORD);
    if (cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 30000)) {
		Led_Off(LED1);
        printf("Failed Connecting to WiFi... %s, %s\n",WIFI_SSID,WIFI_PASSWORD);
        return 1;
    } else {
        printf("Connected.\n");
		Led_On(LED1);
        extern cyw43_t cyw43_state;
        auto ip_addr = cyw43_state.netif[CYW43_ITF_STA].ip_addr.addr;
        printf("IP Address: %lu.%lu.%lu.%lu\n", ip_addr & 0xFF, (ip_addr >> 8) & 0xFF, (ip_addr >> 16) & 0xFF, ip_addr >> 24);
    }
    // turn on LED to signal connected


    run_server();
}

int tuh_get_string_descriptor(uint8_t index, uint8_t languageId, uint16_t length, char * str)
{
	int i, ret = 0;
	ret = tuh_descriptor_get_string_sync(g_address, index, languageId, str, length);
	uint8_t stringLength = 0;
    if (ret<0) return ret;
	return 0;
}

static void print_adb_message(adb_message * message)
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
		printf("AUTH message [%lx] %ld %ld\n", message->command, message->arg0, message->arg1);
		break;
	default:
		printf("WTF message [%lx] %ld %ld\n", message->command, message->arg0, message->arg1);
		break;
	}
}


void finish_sending_ok_message(tuh_xfer_t* xfer){
	if(check_command_result(xfer)){
		printf("Succeeded in sending ok message now listening for data again\n");
		listen_for_data_at_address(g_address, g_config.inputEndPointAddress,&g_adb_connection, 1280);
	}else{
		printf("Sending ok message failed\n");
	}
}


void send_ok_message(uint32_t arg0, uint32_t arg1){
	printf("Now sending ok message\n");
	adb_writeEmptyMessage(g_address, g_config.outputEndPointAddress, A_OKAY, arg0, arg1, finish_sending_ok_message);
}



void finish_send_start_tcpip_command(tuh_xfer_t* xfer){
	if(check_command_result(xfer)){
		printf("Now finishing sending start tcpip\n");
		adb_usb_writeMessage_secondary(xfer,check_command_result_cb);
	}else{
		printf("Failed to send finish start tcpip command");
		g_adb_connection.eventHandler(&g_adb_connection,ADB_CONNECTION_FAILED,0,NULL);
	}
}

void send_start_tcpip_command(){
	printf("Now restarting ADBD in tcpip mode\n");
	adb_usb_writeStringMessageWithCallback(g_address, g_config.outputEndPointAddress, A_OPEN, 1, 0,"tcpip:4656", finish_send_start_tcpip_command);
}

void send_start_tcpip_command_callback(tuh_xfer_t* xfer){
	if(check_command_result(xfer)){
		send_start_tcpip_command();
	}else{
		printf("Failed to send start tcpip command");
		g_adb_connection.eventHandler(&g_adb_connection,ADB_CONNECTION_FAILED,0,NULL);
	}
}


void finish_send_start_activity_command(tuh_xfer_t* xfer){
	if(check_command_result(xfer)){
		printf("Now finishing sending start activity\n");
		adb_usb_writeMessage_secondary(xfer,send_start_tcpip_command_callback);
	}else{
		printf("Failed to send connection command message");
		g_adb_connection.eventHandler(&g_adb_connection,ADB_CONNECTION_FAILED,0,NULL);
	}
}

void send_start_home_screen_command(){
	printf("Now starting home screen\n");
	adb_usb_writeStringMessageWithCallback(g_address, g_config.outputEndPointAddress, A_OPEN, 1, 0,"shell:am start -n com.TrajectoryTheatre.SimuLaunchHome/com.unity3d.player.UnityPlayerActivity", finish_send_start_activity_command);
}

void finish_send_tail_video_logs_command(tuh_xfer_t* xfer){
	if(check_command_result(xfer)){
		printf("Now finishing sending start activity\n");
		adb_usb_writeMessage_secondary(xfer,check_command_result_cb);
	}else{
		printf("Failed to send connection command message");
		g_adb_connection.eventHandler(&g_adb_connection,ADB_CONNECTION_FAILED,0,NULL);
	}
}

void send_tail_video_logs_command2(tuh_xfer_t* xfer){
	if(check_command_result(xfer)){
		printf("!!!!!!!!!!!!!!!!!!!!!!!! Now sending tail video command\n");
		char* decoded = "shell:exec tail -f /sdcard/Movies/output2_vid8.mp4";
        g_adb_connection.command_running = true;
        g_adb_connection.g_data_received_size = 0;
        adb_usb_writeStringMessageWithCallback(g_config.address, g_config.outputEndPointAddress, A_OPEN, 1, 0,decoded, finish_send_tail_video_logs_command);
	}else{
		printf("Failed to send connection command message");
	}
}


void finish_send_start_logging_video_command2(tuh_xfer_t* xfer){
	if(check_command_result(xfer)){
		printf("Now finishing sending start logging video\n");
		sleep_ms(2000);
		adb_usb_writeMessage_secondary(xfer,send_tail_video_logs_command2);
	}else{
		printf("Failed to send start logging video command message");
	}
}


void send_start_logging_video_command2(){
    char* decoded = "shell:screenrecord --verbose /sdcard/Movies/output2_vid8.mp4";
	printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Now starting logging video = {%s} !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n",decoded);
    g_adb_connection.command_running = true;
	g_adb_connection.g_data_received_size = 0;
	adb_usb_writeStringMessageWithCallback(g_config.address, g_config.outputEndPointAddress, A_OPEN, 3, 0,decoded, finish_send_start_logging_video_command2);
}


void send_start_home_screen_command_callback(tuh_xfer_t* xfer){
	if(check_command_result(xfer)){
		//send_start_logging_video_command2(); //This is the bit we hacked to get the video streaming to work
		send_start_home_screen_command();
		//send_start_wifi_login_command();
	}else{
		printf("Failed to send disable sleep command message");
		g_adb_connection.eventHandler(&g_adb_connection,ADB_CONNECTION_FAILED,0,NULL);
	}
}

void finish_send_start_wifi_login(tuh_xfer_t* xfer){
	if(check_command_result(xfer)){
		printf("Now finishing sending start activity\n");
		adb_usb_writeMessage_secondary(xfer,send_start_home_screen_command_callback);
	}else{
		printf("Failed to send connection command message");
		g_adb_connection.eventHandler(&g_adb_connection,ADB_CONNECTION_FAILED,0,NULL);
	}
}

void send_start_wifi_login_command(){
	printf("Now sending start wifi login\n");
	adb_usb_writeStringMessageWithCallback(g_address, g_config.outputEndPointAddress, A_OPEN, 1, 0,"shell:am start -n com.steinwurf.adbjoinwifi/.MainActivity -e ssid storystarter -e password_type WPA -e password password", finish_send_start_wifi_login);
}



void send_wifi_login_command_callback(tuh_xfer_t* xfer){
	if(check_command_result(xfer)){
		//send_start_logging_video_command2(); //This is the bit we hacked to get the video streaming to work
		//send_start_home_screen_command();
		send_start_wifi_login_command();
	}else{
		printf("Failed to send disable sleep command message");
		g_adb_connection.eventHandler(&g_adb_connection,ADB_CONNECTION_FAILED,0,NULL);
	}
}

void finish_send_disable_sleep_command(tuh_xfer_t* xfer){
	if(check_command_result(xfer)){
		printf("Now finishing sending disable sleep command\n");
		adb_usb_writeMessage_secondary(xfer,send_wifi_login_command_callback);
	}else{
		printf("Failed to send connection command message");
		g_adb_connection.eventHandler(&g_adb_connection,ADB_CONNECTION_FAILED,0,NULL);
	}
}

void send_disable_sleep_command(){
	printf("Now starting home screen\n");
	adb_usb_writeStringMessageWithCallback(g_address, g_config.outputEndPointAddress, A_OPEN, 1, 0,"shell:settings put system screen_off_timeout 2147460000", finish_send_disable_sleep_command);
}

void handle_connection_established(){
	printf("-------------- Connection established now doing stuff ----------------");
	Led_On(LED4);
	g_adb_connection.receiverStatus = ADB_AWAITING_MESSAGE_OR_DATA;
	send_disable_sleep_command();
}
void check_private_auth_command_result(tuh_xfer_t* xfer){
	if(check_command_result(xfer)){
		printf("Successfully sent private auth command assuming connection established\n");
		//handle_connection_established();
	}else{
		printf("Failed to send private auth command command message\n");
		g_adb_connection.eventHandler(&g_adb_connection,ADB_CONNECTION_FAILED,0,NULL);
	}
}


void finish_send_auth_command(tuh_xfer_t* xfer){
	if(check_command_result(xfer)){
		printf("Now finishing sending auth\n");
		adb_usb_writeMessage_secondary(xfer,check_command_result_cb);
	}else{
		printf("Failed to send connection command message\n");
		g_adb_connection.eventHandler(&g_adb_connection,ADB_CONNECTION_FAILED,0,NULL);
	}
}

void finish_send_private_auth_command(tuh_xfer_t* xfer){
	if(check_command_result(xfer)){
		printf("Now finishing sending private auth\n");
		adb_usb_writeMessage_secondary_with_length(xfer,check_private_auth_command_result,(uint8_t*) &g_signed_auth_data,AUTH_MESSAGE_SIZE);
	}else{
		printf("Failed to send connection command message\n");
		g_adb_connection.eventHandler(&g_adb_connection,ADB_CONNECTION_FAILED,0,NULL);
	}
}

void send_public_key_auth_command(char* token){
	printf("Now sending public key auth\n");
	g_adb_connection.receiverStatus = ADB_AWAITING_AUTH_RESPONSE;

	adb_usb_writeStringMessageWithCallback(g_address, g_config.outputEndPointAddress, A_AUTH, 3, 0,(char*)PUBLIC_KEY_ADB_FORMAT, finish_send_auth_command);

	//  uint8_t *adb_format;
    // int adb_format_size = convert_pub_key_pem_to_adb_format((const char*)PUBLIC_KEY, &adb_format);

    // if (adb_format_size > 0) {
    //     // The `adb_format` buffer now contains the RSA public key in ADB format
    //     // You can use it for your purposes here

    //     // Remember to free the buffer when it is no longer needed
	// 	adb_usb_writeStringMessageWithCallback(g_address, g_config.outputEndPointAddress, A_AUTH, 3, 0,bytes_to_string(adb_format,adb_format_size), finish_send_auth_command);
    //     //free(adb_format);
    // } else {
    //     printf("Failed to convert public key\n");
    // }

	//sleep_ms(5000);
	
}



void send_private_key_auth_command(char *token, size_t tokenlen){
	printf("Now sending private key auth. Token length is=%d\n",tokenlen);
	size_t signature_len;

	printf("Token:");
		for (size_t i = 0; i < tokenlen; i++) {
			printf(" %02x", token[i]);
		}
		printf("\n");
	

	int ret = sign_token(token, tokenlen,(const char*)PRIVATE_KEY,(unsigned char (*))&g_signed_auth_data, &signature_len);

	//int ret = sign_key(PRIVATE_KEY, strlen((const char*)PRIVATE_KEY) + 1, token, tokenlen, signature, &signature_len);

	if(ret == 0){
		//sleep_ms(5000);
		adb_usb_writeDataMessageWithCallback(g_address, g_config.outputEndPointAddress, A_AUTH, 2, 0, g_signed_auth_data, AUTH_MESSAGE_SIZE, finish_send_private_auth_command);
	}else{
		printf("Problem signing token=%d",ret);
	}
}



void set_awaiting_auth(tuh_xfer_t* xfer){
	if(check_command_result(xfer)){
		printf("Connected, now awaiting auth!!\n");
		g_adb_connection.receiverStatus = ADB_AWAITING_AUTH_MESSAGE;
		g_adb_connection.eventHandler(&g_adb_connection,ADB_CONNECTION_OPEN,0,NULL);
	}else{
		printf("Failed to send connection command data\n");
		g_adb_connection.eventHandler(&g_adb_connection,ADB_CONNECTION_FAILED,0,NULL);
	}
}
void finish_send_connection_command(tuh_xfer_t* xfer){
	if(check_command_result(xfer)){
		printf("Now finishing sending connection\n");
		adb_usb_writeMessage_secondary(xfer,set_awaiting_auth);
	}else{
		printf("Failed to send connection command message");
		g_adb_connection.eventHandler(&g_adb_connection,ADB_CONNECTION_FAILED,0,NULL);
	}
}

void send_connection_command(tuh_xfer_t* xfer){
	if(check_command_result(xfer)){
		printf("Now sending connection\n");
		adb_usb_writeStringMessageWithCallback(g_address, g_config.outputEndPointAddress, A_CNXN, 0x01000000, 4096, g_adb_connection.connectionString, finish_send_connection_command);
	}
}

void clear_input_feature(tuh_xfer_t* xfer){
  printf("clear input feature\n");
  clear_endpoint_feature(g_address,g_config.inputEndPointAddress,USB_FEATURE_ENDPOINT_HALT,send_connection_command, NULL);
}

void clear_output_feature(){
  printf("clear output feature\n");
  clear_endpoint_feature(g_address,g_config.outputEndPointAddress,USB_FEATURE_ENDPOINT_HALT,clear_input_feature, NULL);
}

/**
 * Initialises an ADB device.
 *
 * @param device the USB device.
 * @param configuration configuration information.
 */
void adb_tuh_init_usb()
{
	printf("Device connected waiting\n");
	printf("--------------------------------------------------- Now sending ADB command ------------------------------------------------\n");
	g_adb_connection.status = ADB_OPENING;
	clear_output_feature();
}


void adb_device_mounted_callback(tuh_xfer_t* xfer){
	adb_usbConfiguration config = device_descriptor_is_adb(xfer, &desc_device, &g_adb_connection);
	g_adb_connection.receiverStatus = ADB_DEVICE_CONNECTED;
	if (!is_default(&config)){
		Led_On(LED3);
		g_config = config;
		sleep_ms(1000);
		adb_tuh_init_usb();
	}
}

static bool adb_try_get_message(adb_message * message,  uint16_t length, uint8_t * data)
{
	// Check if the received number of bytes matches our expected 24 bytes of ADB message header.
	if (length != sizeof(adb_message)){
		printf("Received data size %d doesn't match message so bailing", length);
		return false;
	} 
	memcpy((void*)message, (void*)data, sizeof(adb_message));
	// If the message is corrupt, return.
	if (message->magic != (message->command ^ 0xffffffff))
	{
		printf("Broken message, magic mismatch, %d bytes\n", length);
		return false;
	}
	return true;
}


void copyArray(uint8_t* target, uint8_t* source, int targetIndex, int sourceLength) {
    int i;

    for (i = 0; i < sourceLength; i++) {
        target[targetIndex + i] = source[i];
    }
}

bool handle_data_received(adb_connection * connection, uint16_t length, uint8_t * data){
	adb_message message;
	printf("Handling data received:\n");
	int i;
	switch (connection->receiverStatus)
	{
		case ADB_AWAITING_AUTH_MESSAGE:
			memcpy((void*)&message, (void*)data, sizeof(adb_message));
			printf("Awaiting auth message got message:\n");
			print_adb_message(&message);
			connection->receiverStatus = ADB_AWAITING_AUTH_DATA;
			break;
		case ADB_AWAITING_AUTH_DATA:
			printf("Awaiting auth data got data:\n");
			for( i = 0; i < 20; i++ ){
				printf("%02X%s", data[i],( i + 1 ) % 16 == 0 ? "\r\n" : " " );
			}
			
			connection->receiverStatus = ADB_AWAITING_AUTH_MESSAGE;
			if(!has_attempted_auth){
				//has_attempted_auth = true;
				sleep_ms(5000);
				send_private_key_auth_command((char*)data, length);
			}else{
				send_public_key_auth_command(NULL);
			}
			break;
		case ADB_AWAITING_AUTH_RESPONSE:
			if(adb_try_get_message(&message, length, data)){
				printf("Got message:\n");
				print_adb_message(&message);
				if (message.command == A_CNXN) {
					handle_connection_established();
				}
			}
			break;
		case ADB_AWAITING_MESSAGE_OR_DATA:
			if(adb_try_get_message(&message, length, data)){
				printf("Got message:\n");
				print_adb_message(&message);
				if (message.command == A_CLSE) {
					printf("Received close message so terminating command");
					connection->command_running = false;
				}
				else if (message.command == A_WRTE) {
					connection->data_streaming = true;
					connection->data_streaming_arg_0 = message.arg0;
					connection->data_streaming_arg_1 = message.arg1;
					return false;
				}
				//free((void*)connection->g_data_received);
			}else{
				printf("Got data now copying array:\n");	
				int new_data_length = connection->g_data_received_size + length;
				char * message = bytes_to_string(data, length);
				printf("Got data:%s\n", message);		
				//printf("Got data:\n");		
				if (new_data_length < DATA_RECEIVED_BUFFER_SIZE) {
					connection->g_data_buffer_ready_for_reading_by_client = true;
					copyArray(connection->g_data_received, data, connection->g_data_received_size, length);
					connection->g_data_received_size = new_data_length;
					//char * result = bytes_to_string(connection->g_data_received, connection->g_data_received_size);
					//printf("Resulting data is =%s\n", result);
				}else{
					printf("Message does not fit in the buffer\n");
				}
				if (connection->data_streaming) {
					connection->data_streaming = false;
					send_ok_message(connection->data_streaming_arg_0, connection->data_streaming_arg_1);
					return false;
				}
			}
			break;

	}
	return true;
}

bool adbEventHandler(adb_connection * connection, adb_eventType event, uint16_t length, uint8_t * data)
{
	int i;

	switch (event)
	{
		case ADB_CONNECT:
			printf("ADB EVENT CONNECT\n");
			break;
		case ADB_DISCONNECT:
			printf("ADB EVENT DISCONNECT\n");
			break;
		case ADB_CONNECTION_OPEN:
			printf("ADB EVENT OPEN connection=[%s]\n", connection->connectionString);
			break;
		case ADB_CONNECTION_CLOSE:
			printf("ADB EVENT CLOSE connection=[%s]\n", connection->connectionString);
			break;
		case ADB_CONNECTION_FAILED:
			printf("ADB EVENT FAILED connection=[%s]\n", connection->connectionString);
			break;
		case ADB_CONNECTION_RECEIVE:
			return handle_data_received(connection,length, data);
	}
	return true;

}

void
Led_On(int led)
{
    printf("GPIO%d on\n", led);
    gpio_put(led, 1);
}

void
Led_Off(int led)
{
    printf("GPIO%d off\n", led);
    gpio_put(led, 0);
}


// /*------------- TinyUSB Callbacks -------------*/

// // Invoked when device is mounted (configured)
void tuh_mount_cb (uint8_t daddr)
{

	has_connected = true;
	Led_On(LED2);

	g_adb_connection.connectionString = "host::microbridge";
	g_adb_connection.g_data_received_size = 0;
	g_adb_connection.status = ADB_OPENING;
	g_adb_connection.eventHandler = adbEventHandler;
	g_adb_connection.receiverStatus = ADB_UNKOWN_DEVICE_CONNECTED;
	printf("Device attached, address = %d\r\n", daddr);

	g_address = daddr;

	tuh_descriptor_get_device(g_address, &desc_device, 18, adb_device_mounted_callback, 0);

}

/// Invoked when device is unmounted (bus reset/unplugged)
void tuh_umount_cb(uint8_t daddr)
{
	g_adb_connection.receiverStatus = ADB_DEVICE_DISCONNECTED;
	Led_Off(LED2);
	Led_Off(LED3);
	Led_Off(LED4);
    printf("Device removed, address = %d\r\n", daddr);

}


