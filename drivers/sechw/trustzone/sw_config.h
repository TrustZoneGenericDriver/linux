/*
 * OpenVirtualization:
 * For additional details and support contact developer@sierraware.com.
 * Additional documentation can be found at www.openvirtualization.org
 *
 * Copyright (C) 2011 SierraWare
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

/*
 * Config variable declaration
 */

#ifndef SW_CONFIG
#define SW_CONFIG

#if defined(__GNUC__) && \
	defined(__GNUC_MINOR__) && \
defined(__GNUC_PATCHLEVEL__) && \
((__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)) \
> 40700
#define USE_ARCH_EXTENSION_SEC 1
#else
#define USE_ARCH_EXTENSION_SEC 0
#endif
#endif
