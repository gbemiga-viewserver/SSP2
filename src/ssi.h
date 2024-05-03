#include "custom_lwip_opts.h"
#include "adb.h"
#ifndef __SSI_H__
#define __SSI_H__

u16_t __time_critical_func(ssi_handler)(int iIndex, char *pcInsert, int iInsertLen);
void ssi_init(adb_connection *g_adb_connection);

#endif // __SSI_H__

