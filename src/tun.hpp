#pragma once

#include <string>

int tun_alloc(std::string& name);

void tun_destroy(int fd);

void list_ifaces();

void loop(int fd, bool& running);

void set_ip_address(int fd, const char* name, const std::string& ip, const std::string& mask);