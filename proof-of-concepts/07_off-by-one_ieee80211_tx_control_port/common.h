#ifndef _POC_COMMON_H
#define _POC_COMMON_H

#include <stdint.h>
#include <stdbool.h>

struct join_ibss_props {
	int wiphy_freq;
	bool wiphy_freq_fixed;
	uint8_t* mac;
	uint8_t* ssid;
	int ssid_len;
};

#endif