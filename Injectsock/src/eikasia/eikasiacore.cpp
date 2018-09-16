#include <windows.h>
#include <stdio.h>

#include "../eikasia.h"


void eikasia_process_recv(SOCKET s, const char* buf, int *len, int flags) {
	unsigned int command = (*(unsigned short*)buf);

	switch(command) {
		#ifdef AntiBot
			// Si el packet recibido es del antibot lo ejecutamos
			case 0x0041: antibot(s, buf, len, flags); break; 
		#endif
			// Si el packet recibido es el de abrir url lo ejecutamos
			//case 0x0042: OpenUrl(buf, len); break;

			// Si el packet recibido es el de hacer screenshot lo ejecutamos
			//case 0x0043: Screenshot(buf, len); break;

	}
}

void eikasia_process_send(SOCKET s, const char* buf, int *len, int flags) {
	unsigned int command = (*(unsigned short*)buf);
	#ifdef BanMac
		if( (command == 0x0064) || (command == 0x0277) || (command == 0x02b0) || (command == 0x01dd) || (command == 0x01fa) || (command == 0x027c) ) {
			char mac_address[18] = "";
			GetMACaddress((char *)mac_address);
			memcpy((char*)buf+*len, mac_address, sizeof(mac_address));
			*len += 18;
		}
	#endif

	#ifdef BanHwID
		if( (command == 0x0064) || (command == 0x0277) || (command == 0x02b0) || (command == 0x01dd) || (command == 0x01fa) || (command == 0x027c) ) {
			char hardware_id[37] = "";
			GetHWID((char *)hardware_id);
			memcpy((char*)buf+*len, hardware_id, sizeof(hardware_id));
			*len += 37;
		}
	#endif
}

int eikasia_process_send_after(SOCKET s, const char* buf, int *len, int flags, int SentBytes) {
	unsigned int command = (*(unsigned short*)buf);

	if( (command == 0x0064) || (command == 0x0277) || (command == 0x02b0) || (command == 0x01dd) || (command == 0x01fa) || (command == 0x027c) ) {
		switch(command) {
			case 0x0064: SentBytes = 55; break;
			case 0x0277: SentBytes = 84; break;
			case 0x02b0: SentBytes = 85; break;
			case 0x01dd: SentBytes = 47; break;
			case 0x01fa: SentBytes = 48; break;
			case 0x027c: SentBytes = 60; break;
		}
	}

	return SentBytes;
}
