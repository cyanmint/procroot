/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * User-space PID namespace virtualization ("-p" / "--proc").
 */

#ifndef PID_VIRT_H
#define PID_VIRT_H

#include "extension/extension.h"

extern int pid_virt_callback(Extension *extension, ExtensionEvent event,
			intptr_t data1, intptr_t data2);

/* Returns true if a binding targeting the host "/proc" is already
 * pending for @tracee, which conflicts with "-p"/"--proc".  */
extern bool pid_virt_binding_conflicts(Tracee *tracee);

#endif /* PID_VIRT_H */
