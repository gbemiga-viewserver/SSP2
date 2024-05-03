#include "custom_lwip_opts.h"
#include "adb.h"
#include "adb_utils.h"
#include "lwip/apps/httpd.h"
#include "pico/cyw43_arch.h"
#include "lwipopts.h"
#include "cgi.h"
#include "pico/stdlib.h"
//#include "tusb.h"


adb_usbConfiguration * g_cgi_adb_config;
adb_connection * g_cgi_adb_connection;
uint8_t g_received_command_data[256];

char hex_to_char(const char *hex) {
    char c = 0;
    for (int i = 0; i < 2; ++i) {
        c *= 16;
        if (hex[i] >= '0' && hex[i] <= '9') {
            c += hex[i] - '0';
        } else if (hex[i] >= 'A' && hex[i] <= 'F') {
            c += hex[i] - 'A' + 10;
        } else if (hex[i] >= 'a' && hex[i] <= 'f') {
            c += hex[i] - 'a' + 10;
        } else {
            // Invalid hex character
            return '\0';
        }
    }
    return c;
}

void clearString(char* str) {
    memset(str, '\0', strlen(str));
}


size_t url_decode(const char* encoded, uint8_t* decoded ) {
    size_t len = strlen(encoded);
    size_t decoded_len = 0;
    for (size_t i = 0; i < len; ++i) {
        if (encoded[i] == '%') {
            if (i + 2 < len) {
                char hex[3] = {encoded[i+1], encoded[i+2], '\0'};
                char c = hex_to_char(hex);
                if (c != '\0') {
                    decoded[decoded_len++] = c;
                    i += 2;
                    continue;
                }
            }
            return NULL;
        } else if (encoded[i] == '+') {
            decoded[decoded_len++] = ' ';
        } else {
            decoded[decoded_len++] = encoded[i];
        }
    }
    return decoded_len;
}

static const tCGI cgi_handlers[] = {
    {
        /* Html request for "/leds.cgi" will start cgi_handler_basic */
        "/leds.cgi", cgi_handler_basic
    },
    {
        /* Html request for "/leds2.cgi" will start cgi_handler_extended */
        "/leds_ext.cgi", cgi_handler_extended
    }
};



void finish_send_start_activity_command2(tuh_xfer_t* xfer){
	if(check_command_result(xfer)){
		printf("Now finishing sending start activity\n");
		adb_usb_writeMessage_secondary_with_length(xfer,check_command_result_cb, g_received_command_data, xfer->user_data);
	}else{
		printf("Failed to send connection command message");
	}
}


void send_start_activity_command2(char *command){
    size_t decoded_len = url_decode(command, g_received_command_data);
	printf("Now starting activity len = {%s}\n",decoded_len);
    g_cgi_adb_connection->command_running = true;
	g_cgi_adb_connection->g_data_received_size = 0;
	adb_usb_writeDataMessageWithCallback(g_cgi_adb_config->address, g_cgi_adb_config->outputEndPointAddress, A_OPEN, 1, 0,g_received_command_data, decoded_len, finish_send_start_activity_command2);
}


void send_tail_video_logs_command(tuh_xfer_t* xfer){
	if(check_command_result(xfer)){
		printf("Now sending tail video command\n");
		char* decoded = "shell:exec tail -f /sdcard/Movies/output_vid.mp4";
        g_cgi_adb_connection->command_running = true;
        g_cgi_adb_connection->g_data_received_size = 0;
        adb_usb_writeStringMessageWithCallback(g_cgi_adb_config->address, g_cgi_adb_config->outputEndPointAddress, A_OPEN, 1, 0,decoded, finish_send_start_activity_command2);
	}else{
		printf("Failed to send connection command message");
	}
}

void finish_send_start_logging_video_command(tuh_xfer_t* xfer){
	if(check_command_result(xfer)){
		printf("Now finishing sending start logging video\n");
		adb_usb_writeMessage_secondary(xfer,send_tail_video_logs_command);
	}else{
		printf("Failed to send start logging video command message");
	}
}


void send_start_logging_video_command(){
    char* decoded = "shell:screenrecord /sdcard/Movies/output_vid.mp4";
	printf("Now starting logging video = {%s}\n",decoded);
    g_cgi_adb_connection->command_running = true;
	g_cgi_adb_connection->g_data_received_size = 0;
	adb_usb_writeStringMessageWithCallback(g_cgi_adb_config->address, g_cgi_adb_config->outputEndPointAddress, A_OPEN, 1, 0,decoded, finish_send_start_logging_video_command);
}


/* cgi-handler triggered by a request for "/leds.cgi" */
const char * cgi_handler_basic(int iIndex, int iNumParams, char *pcParam[], char *pcValue[])
{

    /* We use this handler for one page request only: "/leds.cgi"
     * and it is at position 0 in the tCGI array (see above).
     * So iIndex should be 0.
     */
	//clearString(g_cgi_adb_connection->g_data_received);

    //g_cgi_adb_connection->g_data_received = "FOOOO";
    printf("cgi_handler_basic called with index %d\n", iIndex);

    if (g_cgi_adb_connection->receiverStatus == ADB_AWAITING_MESSAGE_OR_DATA && !g_cgi_adb_connection->command_running) {
        printf("looks like we're connected so sending command to device");
        send_start_activity_command2(pcValue[0]);
        while (g_cgi_adb_connection->command_running)
        {
            tuh_task();
            sleep_ms(50);
            printf(".");
        }
        return "/ssi_cgi.shtml";
    }else{
        printf("not connected so sending disconnected status to device");
        return "/disconnected_ssi_cgi.shtml";
    }
   
}

/* cgi-handler triggered by a request for "/leds_ext.cgi".
 *
 * It is almost identical to cgi_handler_basic().
 * Both handlers could be easily implemented in one function -
 * distinguish them by looking at the iIndex parameter.
 * I left it this way to show how to implement two (or more)
 * enirely different handlers.
 */
const char *
cgi_handler_extended(int iIndex, int iNumParams, char *pcParam[], char *pcValue[])
{
    printf("cgi_handler_basic extended with index %d\n", iIndex);
    send_start_logging_video_command();
    while (g_cgi_adb_connection->command_running)
 	{
        tuh_task();
        sleep_ms(50);
        printf(".");
 	}

    /* Our response to the "SUBMIT" is to send "/ssi_cgi.shtml".
     * The extension ".shtml" tells the server to insert some values
     * which show the user what has been done in response.
     */
    return "/ssi_cgi.shtml";
}

/* initialize the CGI handler */
void
cgi_init(adb_usbConfiguration * cfg, adb_connection * con)
{
    g_cgi_adb_config = cfg;
    g_cgi_adb_connection = con;
    http_set_cgi_handlers(cgi_handlers, 2);

    
}

// /* led control and debugging info */
// void
// Led_On(int led)
// {
//     printf("GPIO%d on\n", led);
//     gpio_put(led, 1);
// }

// void
// Led_Off(int led)
// {
//     printf("GPIO%d off\n", led);
//     gpio_put(led, 0);
// }


