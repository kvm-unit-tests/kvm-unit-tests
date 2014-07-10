/*
 * Copyright (C) 2014, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include "libcflat.h"
#include "virtio.h"
#include "virtio-mmio.h"

struct virtio_device *virtio_bind(u32 devid)
{
	return virtio_mmio_bind(devid);
}
