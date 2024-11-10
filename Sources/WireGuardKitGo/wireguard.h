/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#ifndef WIREGUARD_H
#define WIREGUARD_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

typedef void(*logger_fn_t)(void *context, int level, const char *msg);
extern void wgSetLogger(void *context, logger_fn_t logger_fn);
extern int wgTurnOn(const char *settings, int32_t tun_fd);
extern void wgTurnOff(int handle);
extern int64_t wgSetConfig(int handle, const char *settings);
extern char *wgGetConfig(int handle);
extern void wgBumpSockets(int handle);
extern void wgDisableSomeRoamingForBrokenMobileSemantics(int handle);
extern const char *wgVersion();

//Wstunnel
extern void Initialise(bool development, const char *logPath);
extern bool StartProxy(const char *listenAddress, const char *remoteAddress, int tunnelType, long mtu , bool extraPadding);
extern void Stop();

//Cd
extern void StartCd(const char *cdUID, const char *homeDir, const char *upstreamProto,
        int logLevel, const char *logPath);
extern int StopCd(bool restart, int pin);
extern void SetMetaData(const char *newHostName, const char *newLanIp, const char *newMacAddress)
extern bool IsCdRunning();

#endif
