#include "custom_lwip_opts.h"
#include "hardware/adc.h"
#include "lwip/apps/httpd.h"
#include "pico/cyw43_arch.h"
#include "lwipopts.h"
#include "ssi.h"
#include "cgi.h"


adb_connection *g_ssi_adb_connection;           

// char* bytes_to_string2(const uint8_t* byte_array, size_t byte_array_len)
// {
//     char* string = (char*) malloc(byte_array_len + 1); // +1 for the null-terminator
//     if (string == NULL) return NULL; // Failed to allocate memory

//     memcpy(string, byte_array, byte_array_len);
//     string[byte_array_len] = '\0'; // Null-terminate the string

//     return string;
// }
// max length of the tags defaults to be 8 chars
// LWIP_HTTPD_MAX_TAG_NAME_LEN
const char * __not_in_flash("httpd") ssi_example_tags[] = {
    "stated",    // 0
    "counter",  // 1
    "GPIO",     // 2
    "state1",   // 3
    "state2",   // 4
    "state3",   // 5
    "state4",   // 6
    "bg1",      // 7
    "bg2",      // 8
    "bg3",      // 9
    "bg4"       // 10
};

u16_t __time_critical_func(ssi_handler)(int iIndex, char *pcInsert, int iInsertLen, u16_t current_tag_part, u16_t *next_tag_part)
{
    size_t printed;
    printf("At the start next tag part is =%d\n",*next_tag_part);
    switch (iIndex) {
        case 0: /* "stated" */
            switch (g_ssi_adb_connection->receiverStatus)
            {
                case ADB_UNKOWN_DEVICE_CONNECTED:
                    printed = snprintf(pcInsert, iInsertLen, "Unkown Device");
                    break;
                case ADB_DEVICE_CONNECTED:
                    printed = snprintf(pcInsert, iInsertLen, "Connected...");
                    break;
                case ADB_DEVICE_DISCONNECTED:
                    printed = snprintf(pcInsert, iInsertLen, "No Headset");
                    break;
                case ADB_AWAITING_AUTH_DATA:
                case ADB_AWAITING_AUTH_RESPONSE:
                    printed = snprintf(pcInsert, iInsertLen, "Authorizing...");
                    break;
                case ADB_AWAITING_MESSAGE_OR_DATA:
                    printed = snprintf(pcInsert, iInsertLen, "Ready");
                    break;
                default:
                    printed = snprintf(pcInsert, iInsertLen, "Unknown status");
                    break;

            }
            break;
        case 1: /* "counter" */
        {
            static int counter;
            counter++;
            printed = snprintf(pcInsert, iInsertLen, "%d", counter);
        }
            break;
        case 2: /* "GPIO" */
        {
            const float voltage = adc_read() * 3.3f / (1 << 12);
            printed = snprintf(pcInsert, iInsertLen, "%f", voltage);
            break;
        }
        case 3:{
     

            /* Calculate how many characters we can return this time */
            int data_offset = current_tag_part * iInsertLen;
            int len = g_ssi_adb_connection->g_data_received_size - data_offset;
            if (len > (iInsertLen-1)) {
                /* We can't return all, adjust len to fit the buffer and set next_tag_part for next turn */
                len = iInsertLen-1;
                *next_tag_part = (current_tag_part + 1);
                printf("inserted fragment ilen=%d len=%d nxt=%d\n",iInsertLen, len,*next_tag_part);
            } else {
                printf("inserted fragment complete ilen=%d len=%d\n",iInsertLen, len);
                /* We can return all, set next_tag_part to 0 which means we are done after this turn */
                //*next_tag_part = 0;
            }

           MEMCPY(pcInsert, g_ssi_adb_connection->g_data_received + data_offset, len);
           pcInsert[len] = '\0';
           //char * message = bytes_to_string2(g_ssi_adb_connection->g_data_received, g_ssi_adb_connection->g_data_received_size);
           printf("ADB=%s\n",pcInsert);
           //printed = snprintf(pcInsert, iInsertLen, "%s", message);
           printed = len; 
        }
        break;
        case 4: /* "state2" */
        case 5: /* "state3" */
        case 6: /* "state4" */
        {
            bool state = NULL;
            if(iIndex == 3)
                state = gpio_get(LED1);
            else if(iIndex == 4)
                state = gpio_get(LED2);
            else if(iIndex == 5)
                state = gpio_get(LED3);
            else if(iIndex == 6)
                state = gpio_get(LED4);

            if(state)
                printed = snprintf(pcInsert, iInsertLen, "checked");
            else
                printed = snprintf(pcInsert, iInsertLen, " ");
        }
          break;

        case 7:  /* "bg1" */
        case 8:  /* "bg2" */
        case 9:  /* "bg3" */
        case 10: /* "bg4" */
        {
            bool state = NULL;
            if(iIndex == 7)
                state = gpio_get(LED1);
            else if(iIndex == 8)
                state = gpio_get(LED2);
            else if(iIndex == 9)
                state = gpio_get(LED3);
            else if(iIndex == 10)
                state = gpio_get(LED4);

            if(state)
                printed = snprintf(pcInsert, iInsertLen, "\"background-color:green;\"");
            else
                printed = snprintf(pcInsert, iInsertLen, "\"background-color:red;\"");
        }
          break;
         case 11: /* "adb" */
        {
            printed = snprintf(pcInsert, iInsertLen,"%s","FPPBAR");
        }
          break;
        default: /* unknown tag */
            printed = 0;
            break;
    }
      LWIP_ASSERT("sane length", printed <= 0xFFFF);
      return (u16_t)printed;
}

void ssi_init(adb_connection *global_connection)
{
    g_ssi_adb_connection = global_connection;
    adc_init();
    adc_gpio_init(26);
    adc_select_input(0);
    size_t i;
    for (i = 0; i < LWIP_ARRAYSIZE(ssi_example_tags); i++) {
        LWIP_ASSERT("tag too long for LWIP_HTTPD_MAX_TAG_NAME_LEN",
                    strlen(ssi_example_tags[i]) <= LWIP_HTTPD_MAX_TAG_NAME_LEN);
    }

      http_set_ssi_handler(ssi_handler,
                           ssi_example_tags, LWIP_ARRAYSIZE(ssi_example_tags)
      );
}
