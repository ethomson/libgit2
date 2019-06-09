#ifndef CLI_printerr_h__
#define CLI_printerr_h__

extern void gitcli_error(const char *fmt, ...);
extern void gitcli_error_git(const char *fmt, ...);
extern void gitcli_error_os(const char *fmt, ...);

#define gitcli_die(...) \
	do { gitcli_error(__VA_ARGS__); exit(1); } while(0)
#define gitcli_die_git(...) \
	do { gitcli_error_git(__VA_ARGS__); exit(1); } while(0)
#define gitcli_die_os(...) \
	do { gitcli_error_os(__VA_ARGS__); exit(1); } while(0)

#endif /* CLI_printerr_h__ */
