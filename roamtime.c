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

#define RA_POS 4
#define TA_POS 10
#define TYPE_POS 0
#define SEQNR_POS 22
#define BA_SSN_POS 18
#define BA_BM_POS 18

static int cmp_eth(const uint8_t *addr1, const struct ether_addr *addr2)
{
	struct ether_addr *_addr1 = (struct ether_addr *) addr1;

	return memcmp(_addr1, addr2, sizeof(*_addr1)) == 0;
}

static void usage(char **argv)
{
	printf("%s pcap mac\n", argv[0]);
	exit(1);
}

static uint8_t get_pkt_type(const uint8_t *p)
{
	return p[TYPE_POS] >> 4 | (p[TYPE_POS] & 0x0c) << 2;
}

static uint16_t get_freq(const uint8_t *p)
{
	return p[10] | p[11] << 8;
}

static uint16_t get_seqnr(const uint8_t *p)
{
	return (p[SEQNR_POS + 1] << 8 | p[SEQNR_POS]) >> 4;
}

static uint16_t get_ssn(const uint8_t *p)
{
	return (p[BA_SSN_POS + 1] << 8 | p[BA_SSN_POS]) >> 4;
}

static double get_timestamp(struct pcap_pkthdr *hdr)
{
	return hdr->ts.tv_sec * 1000000 + hdr->ts.tv_usec;
}

static int is_pkt_acked(const uint8_t *wp, struct ether_addr *last_ta,
			uint16_t seqnr)
{
	/* Normal ACK with correct RA */
	if (get_pkt_type(wp) == 0x1d && cmp_eth(wp + RA_POS, last_ta))
		return 1;

	/* BA. Only BA directly after data frame is checked */
	if (get_pkt_type(wp) == 0x19 && cmp_eth(wp + RA_POS, last_ta)) {
		const uint8_t *bm = wp + BA_BM_POS;
		uint16_t ssn;
		int bit_offset, byte, bit;

		ssn = get_ssn(wp);
		bit_offset = seqnr - ssn;

		if (bit_offset > 63)
			return 0;

		byte = bit_offset / 8;
		bit = bit_offset % 8;
		return !!(bm[byte] & 1 << bit);
	}

	return 0;
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
	uint16_t tmp_seqnr;

	/* Details of packet from previous BSS */
	struct pcap_pkthdr last_data_hdr = {};
	struct ether_addr last_bss = {};
	uint16_t last_freq = 0;

	/* Details packet from current BSS */
	struct pcap_pkthdr curr_data_hdr;
	struct ether_addr curr_bss = {};
	uint16_t curr_freq;

	struct pcap_pkthdr *hdr;
	uint16_t radiotap_len;

	int ret;
	char pcap_err[PCAP_ERRBUF_SIZE];
	const uint8_t *rp, *wp;
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
		ret = pcap_next_ex(pcap, &hdr, &rp);
		cnt++;
		if (ret < 0)
			break;

		radiotap_len = rp[2] | rp[3] << 8;
		wp = rp + radiotap_len;

		ftype = get_pkt_type(wp);

		/* Match data packets with dut's RA or TA */
		if ((ftype == 0x28 || ftype == 0x20) &&
		    (cmp_eth(wp + RA_POS, &dut_addr) ||
		     cmp_eth(wp + TA_POS, &dut_addr))) {

			/* Get BSS of current packet */
			if (cmp_eth(wp + TA_POS, &dut_addr))
				memcpy(&curr_bss, wp + RA_POS, 6);
			else
				memcpy(&curr_bss, wp + TA_POS, 6);

			/* Save info about the data packet. Checking for the ack
			   will overwrite */
			memcpy(&tmp_ta, wp + TA_POS, 6);
			memcpy(&curr_data_hdr, hdr, sizeof(curr_data_hdr));
			curr_freq = get_freq(rp);
			tmp_seqnr = get_seqnr(wp);

			/* Check if packet was ACKed */
			ret = pcap_next_ex(pcap, &hdr, &rp);
			radiotap_len = rp[2] | rp[3] << 8;
			wp = rp + radiotap_len;
			cnt++;
			if (ret < 0)
				break;
			if (is_pkt_acked(wp, &tmp_ta, tmp_seqnr)) {
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
