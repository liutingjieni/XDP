#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"

static int xdp_link_detach(int ifindex, __u32 xdp_flags)
{
	/* Next assignment this will move into ../common/
	 * (in more generic version)
	 */
	int err;

	if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
		fprintf(stderr, "ERR: link set xdp unload failed (err=%d):%s\n",
			err, strerror(-err));
		return EXIT_FAIL_XDP;
	}
	return EXIT_OK;
}

int main(int argc, char **argv)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	char filename[256] = "xdp_pass_kern.o";
	int prog_fd, err;

	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex   = -1,
		.do_unload = false,
	};

    cfg.ifname = (char *)&cfg.ifname_buf;
	strncpy(cfg.ifname, "wlp2s0", IF_NAMESIZE);
	cfg.ifindex = if_nametoindex(cfg.ifname);


    cfg.xdp_flags &= ~XDP_FLAGS_MODES; 
	// parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);
	// /* Required option */
	// if (cfg.ifindex == -1) {
	// 	fprintf(stderr, "ERR: required option --dev missing\n");
	// 	usage(argv[0], __doc__, long_options, (argc == 1));
	// 	return EXIT_FAIL_OPTION;
	// }
	// if (cfg.do_unload)
	return xdp_link_detach(cfg.ifindex, cfg.xdp_flags);
	
}
