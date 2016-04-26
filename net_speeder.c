#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <libnet.h>
#include <getopt.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 65535

#ifdef COOKED
#define ETHERNET_H_LEN 16
#else
#define ETHERNET_H_LEN 14
#endif

#define SPECIAL_TTL 99

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_usage(void);

static struct net_speeder_ctx {
	char ns_iface[32];
	int  ns_repeat;
	char *ns_rule;
} ns_ctx;

static int parse_int(const char *s)
{
	char *ep = NULL;
	long n;

	n = strtol(s, &ep, 10);
	if (ep == s || n <= 0 || n == LONG_MAX) {
		fprintf(stderr, "invalid number: %s\n", s);
		exit(1);
	}

	if (n > (long)INT_MAX) {
		fprintf(stderr, "integer too large: %ld\n", n);
		exit(1);
	}

	return (int)n;
}

static int init_ctx(int argc, char *argv[])
{
	int opt, i, len;
	char *rule;

	memset(&ns_ctx, 0, sizeof(ns_ctx));
	ns_ctx.ns_repeat = -1;

	while ((opt = getopt(argc, argv, "hi:c:")) != -1) {
		switch (opt) {
		case 'i':
			strncpy(ns_ctx.ns_iface, optarg, sizeof(ns_ctx.ns_iface) - 1);
			break;

		case 'c':
			ns_ctx.ns_repeat = parse_int(optarg);
			break;

		case 'h':
			print_usage();
			exit(0);

		default:
			fprintf(stderr, "unknown opt '%c'.\n", opt);
			exit(1);
		}
	}

	if (ns_ctx.ns_iface[0] == '\0') {
		fprintf(stderr, "No interface specified. try `-h' for help\n");
		exit(1);
	}
	if (optind >= argc) {
		fprintf(stderr, "No filter rule specified. Try `-h' for help\n");
		exit(1);
	}
	if (ns_ctx.ns_repeat < 0) {
		ns_ctx.ns_repeat = 1;
	}

	len = 0;
	for (i = optind; i < argc; ++i)
		len += (int)strlen(argv[i]) + 1;

	rule = malloc(len);
	if (rule == NULL) {
		fprintf(stderr, "malloc(%d) failed\n", len);
		exit(1);
	}

	opt = 0;
	for (i = optind; i < argc; ++i) {
		if (i > optind)
			rule[opt++] = ' ';
		len = (int)strlen(argv[i]);
		memcpy(&rule[opt], argv[i], len);
		opt += len;
	}
	rule[opt] = '\0';

	ns_ctx.ns_rule = rule;
	printf("rule: %s\n", rule);

	return 0;
}

static void fini_ctx(void)
{
	free(ns_ctx.ns_rule);
	memset(&ns_ctx, 0, sizeof(ns_ctx));
}

void print_usage(void)
{
	printf("Usage: %s -i <interface> -c <repeat> <filter>\n", "net_speeder");
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("    repeat       Number of duplicated packets\n");
	printf("    filter       Rules to filter packets.\n");
	printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static long total_count = 1;
	struct libnet_ipv4_hdr *ip;
	libnet_t *libnet_handler = (libnet_t *)args;

	(void)header;
	total_count++;

	ip = (struct libnet_ipv4_hdr*)(packet + ETHERNET_H_LEN);

	if (ip->ip_ttl != SPECIAL_TTL) {
		int len_written, i;

		ip->ip_ttl = SPECIAL_TTL;

		for (i = 1; i <= ns_ctx.ns_repeat; ++i) {
			len_written = libnet_adv_write_raw_ipv4(libnet_handler, (u_int8_t *)ip, ntohs(ip->ip_len));
			if (len_written < 0) {
				printf("%d:%6ld: packet len:[%d] actual write:[%d]\n", i, total_count,
						ntohs(ip->ip_len), len_written);
				printf("%d:%6ld: err msg: %s", i, total_count, libnet_geterror(libnet_handler));
			}
		}
	} else {
		/* The packet net_speeder sent. Nothing to do */
	}
	return;
}

libnet_t* start_libnet(char *dev)
{
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *libnet_handler = libnet_init(LIBNET_RAW4_ADV, dev, errbuf);

	if (NULL == libnet_handler) {
		printf("libnet_init: error %s\n", errbuf);
	}
	return libnet_handler;
}

int main(int argc, char *argv[])
{
	struct net_speeder_ctx *ctx = &ns_ctx;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	struct bpf_program fp;
	bpf_u_int32 net, mask;

	if (init_ctx(argc,  argv) != 0) {
		fprintf(stderr, "init failed\n");
		return 1;
	}

	printf("Ethernet header len: [%d] (14:normal, 16:cooked)\n", ETHERNET_H_LEN);

	if (pcap_lookupnet(ctx->ns_iface, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "cannot get netmask for device %s: %s\n", ctx->ns_iface, errbuf);
		net = 0;
		mask = 0;
	}

	printf("init pcap\n");
	handle = pcap_open_live(ctx->ns_iface, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "pcap_open_live dev:[%s] err %s\n", ctx->ns_iface, errbuf);
		fprintf(stderr, "init pcap failed\n");
		return -1;
	}

	printf("init libnet\n");
	libnet_t *libnet_handler = start_libnet(ctx->ns_iface);
	if(NULL == libnet_handler) {
		fprintf(stderr, "init libnet failed\n");
		return -1;
	}

	if (pcap_compile(handle, &fp, ctx->ns_rule, 0, net) == -1) {
		fprintf(stderr, "filter rule err: [%s][%s]\n", ctx->ns_rule, pcap_geterr(handle));
		return -1;
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "set filter failed: [%s][%s]\n", ctx->ns_rule, pcap_geterr(handle));
		return -1;
	}

	while (1) {
		pcap_loop(handle, 1, got_packet, (u_char *)libnet_handler);
	}

	pcap_freecode(&fp);
	pcap_close(handle);
	libnet_destroy(libnet_handler);
	fini_ctx();

	return 0;
}
