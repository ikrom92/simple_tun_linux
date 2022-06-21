#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include "tun.hpp"
#include <unistd.h>
#include <thread>

int main() {

	std::string name;
	int fd = tun_alloc(name);
	if (fd >= 0) {
		cout << "allocated dev name: " << name << endl;
		set_ip_address(fd, name.c_str(), "192.168.110.1", "255.255.0.0");
		bool running = true;
		auto thr = std::thread([&running, fd] {
			loop(fd, running);
		});
		std::cin.get();
		running = false;
		tun_destroy(fd);
		thr.join();
	}
	else {
		cerr << "alloc failed: " << fd << endl;
	}
	
	return 0;
}