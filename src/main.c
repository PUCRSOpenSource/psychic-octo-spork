#include "dhcp.h"
#include "monitor.h"
#include "sniffer.h"

int main(int argc, char* argv[])
{
	sniffer_start(argc, argv);
	monitor_start(argc, argv);
}
