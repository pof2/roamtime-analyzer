/*
Copyright 2014 Pontus Fuchs <pontus.fuchs@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ether.h>

#define RA_POS 22
#define TA_POS 28
#define TYPE_POS 18

int cmp_eth(const uint8_t *addr1, const struct ether_addr *addr2)
{
	struct ether_addr *_addr1 = (struct ether_addr *) addr1;

	return memcmp(_addr1, addr2, sizeof(*_addr1)) == 0;
}

static void usage(char **argv)
{
	printf("%s pcap mac\n", argv[0]);
	exit(1);
}

static uint8_t get_pkt_type(const uint8_t b)
{
	return b >> 4 | (b & 0x0c) << 2;
}

static uint16_t get_freq(const uint8_t *p)
{
	return p[10] | p[11] << 8;
}

static double get_timestamp(struct pcap_pkthdr *hdr)
{
	return hdr->ts.tv_sec * 1000000 + hdr->ts.tv_usec;
}


int main(int argc, char *argv[])
{
	/* Packet counter */
	int cnt = 0;

	/* Packet number of last acked data frame */
	int last_acked = 0;

	/* Packet number of last roam */
	int last_swap = 0;
	struct ether_addr dut_addr, *tmp_eth, tmp_ta;

	/* Details of packet from previous BSS */
	struct pcap_pkthdr last_data_hdr = {};
	struct ether_addr last_bss = {};
	uint16_t last_freq = 0;

	/* Details packet from current BSS */
	struct pcap_pkthdr curr_data_hdr;
	struct ether_addr curr_bss = {};
	uint16_t curr_freq;

	struct pcap_pkthdr *hdr;
	int ret;
	char pcap_err[PCAP_ERRBUF_SIZE];
	const uint8_t *p;
	unsigned char ftype;

	if (argc != 3)
		usage(argv);

	tmp_eth = ether_aton(argv[2]);
	if (!tmp_eth)
		usage(argv);
	memcpy(&dut_addr, tmp_eth, sizeof(dut_addr));

	pcap_t *pcap = pcap_open_offline(argv[1], pcap_err);
	if (!pcap) {
		printf("Error %s\n", pcap_err);
		exit(1);
	}

	printf("BSSID                                  Frame#              Time (ms)   Freq\n");
	while (1) {
		ret = pcap_next_ex(pcap, &hdr, &p);
		cnt++;
		if (ret < 0)
			break;

		ftype = get_pkt_type(p[TYPE_POS]);

		/* Match data packets with dut's RA or TA */
		if ((ftype == 0x28 || ftype == 0x20) &&
		    (cmp_eth(p + RA_POS, &dut_addr) ||
		     cmp_eth(p + TA_POS, &dut_addr))) {

			/* Get BSS of current packet */
			if (cmp_eth(p + TA_POS, &dut_addr))
				memcpy(&curr_bss, p + RA_POS, 6);
			else
				memcpy(&curr_bss, p + TA_POS, 6);

			/* Save info about the data packet. Checking for the ack
			   will overwrite */
			memcpy(&tmp_ta, p + TA_POS, 6);
			memcpy(&curr_data_hdr, hdr, sizeof(curr_data_hdr));
			curr_freq = get_freq(p);

			/* Check if packet was ACKed */
			ret = pcap_next_ex(pcap, &hdr, &p);
			cnt++;
			if (ret < 0)
				break;
			if (get_pkt_type(p[TYPE_POS]) == 0x1d &&
			    cmp_eth(p + RA_POS, &tmp_ta)) {
//				printf("Packet # %06d %d:%d %08d %02x\n", cnt, (int)hdr->ts.tv_sec, (int)hdr->ts.tv_usec, hdr->len, ftype);
//				printf("%d Acked %s--", cnt, ether_ntoa(&tmp_bss));
//				printf("%s\n", ether_ntoa(&tmp_ta));

				/* BSS changed? */
				if (memcmp(&last_bss, &curr_bss, sizeof(last_bss)) != 0) {
					if (last_swap) {
						double delta = (get_timestamp(&curr_data_hdr) - get_timestamp(&last_data_hdr)) / 1000;
						printf("%s", ether_ntoa(&last_bss));
						printf(" -> %s %7d -> %7d ", ether_ntoa(&curr_bss), last_acked-1, cnt-1);
						printf("%12f ", delta);
						printf("%04d -> %04d ", last_freq, curr_freq);
//						printf("(%f - %f)", get_timestamp(&curr_data_hdr), get_timestamp(&last_data_hdr));
						printf("\n");
					}
					memcpy(&last_bss, &curr_bss, sizeof(last_bss));
					last_swap = cnt;
				}
				last_acked = cnt;
				last_freq = curr_freq;
				memcpy(&last_data_hdr, &curr_data_hdr, sizeof(last_data_hdr));
			}
		}
	}
	printf("Analyzed %d frames\n", cnt);
	return 0;
}
