#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <net/if.h>

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"

static const char *default_filename = "xdp_pass_kern.o";
static const char *default_progsec = "xdp_pass";

struct bpf_object *__load_bpf_object_file(const char *filename, int ifindex)
{
	/* In next assignment this will be moved into ../common/ */
	int first_prog_fd = -1;
	struct bpf_object *obj;
	int err;

	/* Lesson#3: This struct allow us to set ifindex, this features is used
	 * for hardware offloading XDP programs.
	 */
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
		.ifindex	= ifindex,
	};
	prog_load_attr.file = filename;

	/* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
	 * loading this into the kernel via bpf-syscall
	 */
	err = bpf_prog_load_xattr(&prog_load_attr, &obj, &first_prog_fd);
	if (err) {
		fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
			filename, err, strerror(-err));
		return NULL;
	}

	/* Notice how a pointer to a libbpf bpf_object is returned */
	return obj;
}

struct bpf_object *__load_bpf_and_xdp_attach(struct config *cfg)
{
	/* In next assignment this will be moved into ../common/ */
	struct bpf_program *bpf_prog;
	struct bpf_object *bpf_obj;
	int offload_ifindex = 0;
	int prog_fd = -1;
	int err;

	/* If flags indicate hardware offload, supply ifindex */
	if (cfg->xdp_flags & XDP_FLAGS_HW_MODE)
		offload_ifindex = cfg->ifindex;

	/* Load the BPF-ELF object file and get back libbpf bpf_object */
	bpf_obj = __load_bpf_object_file(cfg->filename, offload_ifindex);
	if (!bpf_obj) {
		fprintf(stderr, "ERR: loading file: %s\n", cfg->filename);
		exit(EXIT_FAIL_BPF);
	}
	/* At this point: All XDP/BPF programs from the cfg->filename have been
	 * loaded into the kernel, and evaluated by the verifier. Only one of
	 * these gets attached to XDP hook, the others will get freed once this
	 * process exit.
	 */

	/* Find a matching BPF prog section name */
	bpf_prog = bpf_object__find_program_by_title(bpf_obj, cfg->progsec);
	if (!bpf_prog) {
		fprintf(stderr, "ERR: finding progsec: %s\n", cfg->progsec);
		exit(EXIT_FAIL_BPF);
	}

	prog_fd = bpf_program__fd(bpf_prog);
	if (prog_fd <= 0) {
		fprintf(stderr, "ERR: bpf_program__fd failed\n");
		exit(EXIT_FAIL_BPF);
	}

	/* At this point: BPF-progs are (only) loaded by the kernel, and prog_fd
	 * is our select file-descriptor handle. Next step is attaching this FD
	 * to a kernel hook point, in this case XDP net_device link-level hook.
	 */
	err = xdp_link_attach(cfg->ifindex, cfg->xdp_flags, prog_fd);
	if (err)
		exit(err);

	return bpf_obj;
}

int main(int argc, char **argv) {
  struct bpf_object *bpf_obj;
  char filename[256] = "xdp_prog_kern.o";
  int prog_fd, err;

  struct config cfg = {
      .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
      .ifindex = -1,
      .do_unload = false,
  };

  /* Set default BPF-ELF object file and BPF program name */
  strncpy(cfg.filename, "xdp_prog_kern.o", sizeof(cfg.filename));
  strncpy(cfg.progsec,  "xdp_drop",  sizeof(cfg.progsec));
  
  cfg.ifname = (char *)&cfg.ifname_buf;
  strncpy(cfg.ifname, "wlp2s0", IF_NAMESIZE);
  cfg.ifindex = if_nametoindex(cfg.ifname);

  cfg.xdp_flags &= ~XDP_FLAGS_MODES;

  char *dest  = (char *)&cfg.progsec;
  strncpy(dest, "xdp_drop", sizeof(cfg.progsec));
 
  bpf_obj = __load_bpf_and_xdp_attach(&cfg);
	// if (!bpf_obj)
	// 	return EXIT_FAIL_BPF;

	// if (verbose)
	// 	list_avail_progs(bpf_obj);

	// if (verbose) {
	// 	printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
	// 			cfg.filename, cfg.progsec);
	// 	printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
	// 			cfg.ifname, cfg.ifindex);
	// }
	/* Other BPF section programs will get freed on exit */
	return EXIT_OK;
}
