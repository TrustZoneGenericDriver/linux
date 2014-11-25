/*
 * Author:
 * Javier Gonzalez <jgon@itu.dk>
 *
 * Device driver for ARM TrustZone.
 *
 * TODO: Copyright
 * TODO: Implement hooks to delegate functions to specific TrustZone
 * implementations.
 */

#ifndef __LINUX_TRUSTZONE_H__
#define __LINUX_TRUSTZONE_H__

#include <asm/siginfo.h>

//TODO: We need to check if any TrustZone implementation is actually loaded. It
//is important to check wheather we can do this dynamically with LKMs or not. It
//this is possible, we can keep Sierraware's implementation as a LKM - as they
//originally designed it - and let other implementations be coded in a different
//fashion. This might not make sense in a real depolyment since only one
//TrustZone implementation should be used (or not?).

/*
 * Chip num is the value of a trustzone id.
 * This is the default
 */
#define TRUSTZONE_ANY_NUM 0xFFFF

enum tz_param_type {
	TZ_UINT8 = 0,
	TZ_UINT32,
	TZ_GENERIC
};

//TODO: Implement INOUT
enum tz_param_purpose {
	TZ_PARAM_IN = 0x0,
	TZ_PARAM_OUT,
	TZ_PARAM_INOUT
};

enum tz_services {
	TZ_SECURE_PRIMITIVE_SVC = 0x0
};

struct trustzone_parameter {
	uint8_t type; 
	uint8_t inout;
	void *value;
	uint32_t size;
	struct trustzone_parameter *nxt;
};

struct trustzone_parameter_list {
	struct trustzone_parameter *params;
	uint8_t n_params;
};

//XXX: Maybe we introduce a flag marking if the command was executed or not...
struct trustzone_cmd {
	int cmd;
};

struct trustzone_session{
	void *impl_session;
};

/*
 * Hooks to Secure System Primitives
 */
extern int tz_monitor_syscall(u32, struct trustzone_session*, unsigned long,
		siginfo_t*);

/*
 * TrustZone Generic Operations
 */
extern int tz_open(u32, struct trustzone_session*, u8);
extern int tz_close(u32, struct trustzone_session*);
extern int tz_transmit(u32, struct trustzone_session*, struct trustzone_cmd*,
		struct trustzone_parameter_list*);
extern int tz_send_operation(u32, struct trustzone_session*, struct
		trustzone_cmd*, struct trustzone_parameter_list*);

//TODO: This should be under a DEBUG ifdef
extern int tz_send_test_operation(u32, u8);

//TODO: This should be under a debug flag
enum trustzone_test_implementations {
	TZ_OPEN_VIRTUALIZATION = 0,
	TZ_SAFEG,
	TZ_GENODE
};

#endif
