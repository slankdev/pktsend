
/*
 * MIT License
 *
 * Copyright (c) 2017 Susanow
 * Copyright (c) 2017 Hiroki SHIROKURA
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include <string>
#include <getopt.h>
#include <slankdev/net/hdr.h>
#include <slankdev/socketfd.h>
#include <slankdev/hexdump.h>
#include <slankdev/checksum.h>
#include <pgen/io.h>
using namespace slankdev;

std::string ifname = "";
std::string filename = "";
size_t count = 1;

void version()
{
  printf("pktsend version 0.0\n");
  printf("Copyright 2017 Hiroki SHIROKURA\n");
}

void usage(const char* progname)
{
  printf("\n");
  printf("USAGE: %s [OPTION] \n", progname);

  printf("\n");
  printf("[+] Basic Option\n");
  printf("    -i ifname                    interface name  \n");
  printf("    -w file                      write as pcap format\n");
  printf("    -c count                     packet count    \n");
  printf("    -v                           show version    \n");
  printf("    -h                           show usage    \n");

  printf("\n");
  printf("[+] Option for Crafting Packet Binary\n");
  printf("    --hsrc=11:22:33:44:55:66     src mac address \n");
  printf("    --hdst=ff:ff:ff:ff:ff:ff     dst mac address \n");
  printf("    --etype=0x0800               ethernet type   \n");
  printf("    --psrc=192.168.0.10          src ip address  \n");
  printf("    --pdst=192.168.0.1           dst ip address  \n");
  printf("    --proto=1                    ip protocol     \n");

  printf("\n");
}

inline static size_t
craft_eh(struct ether* eh, uint8_t dst[], uint8_t src[], uint16_t type)
{
  constexpr size_t IP_ADDR_LEN = 6;
  for (size_t i=0; i<IP_ADDR_LEN; i++) {
    eh->dst.addr_bytes[i] = dst[i];
    eh->src.addr_bytes[i] = src[i];
  }
  eh->type = bswap16(type);
  return sizeof(ether);
}

inline static size_t
craft_ih(struct ip* ih, uint16_t tot_len, uint8_t proto, int32_t csum, uint32_t src, uint32_t dst)
{
  ih->ver_ihl = 0x45;
  ih->tos     = 0x00;
  ih->tot_len = bswap16(tot_len);
  ih->id      = bswap16(0x0000);
  ih->off     = bswap16(0x0000);
  ih->ttl     = 0x40;
  ih->proto   = proto;
  ih->sum     = bswap16(0x0000);
  ih->src     = bswap32(src);
  ih->dst     = bswap32(dst);

  if (csum < 0) {
    ih->sum = bswap16(checksum(ih, 20));
  } else {
    ih->sum = bswap16(csum);
  }
  return 20;
}

inline static void
dump_packet(const ether* eh, const ip* ih, uint8_t* pkt_ptr, size_t pkt_len)
{
  eh->print(stdout);
  ih->print(stdout);
  slankdev::hexdump(stdout, pkt_ptr, pkt_len);
}

inline static void
parse_opt(int argc, char** argv)
{
  int version_flag = 0;

  static struct option long_options[] =
  {
    /* These options don’t set a flag. We distinguish them by their indices. */
    // {"add",     no_argument,       0, 'a'},
    // {"append",  no_argument,       0, 'b'},
    // {"delete",  required_argument, 0, 'd'},
    // {"create",  required_argument, 0, 'c'},
    // {"file",    required_argument, 0, 'f'},
    {0, 0, 0, 0},
  };

  while (true) {
    int option_index = 0;
    char c = getopt_long(argc, argv, "i:w:c:vh", long_options, &option_index);

    if (c == -1) break;
    switch (c) {
      case 0:
        printf("long option\n");
        throw slankdev::exception("Not Support This Option yet");
        break;
      case 'c':
        count = atoi(optarg);
        break;
      case 'i':
        ifname = optarg;
        break;
      case 'w':
        filename = optarg;
        break;
      case 'v':
        version();
        exit(0);
      case 'h':
        usage(argv[0]);
        exit(0);
      default:
        usage(argv[0]);
        exit(-1);
    }
  }
}


int main(int argc, char** argv)
{
  parse_opt(argc, argv);

  uint8_t pkt_ptr[1000] = {0x00};
  size_t  pkt_len = 0;
  const char* str = "slankdev";

  /*
   * Craft Ethernet Header
   */
  ether* eh = (ether*)(pkt_ptr);
  uint8_t dst_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  uint8_t src_mac[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  uint16_t type = 0x0800;
  pkt_len += craft_eh(eh, dst_mac, src_mac, type);

  /*
   * Craft IPv4 Header
   */
  ip* ih = (ip*)(pkt_ptr + pkt_len);
  uint16_t tot_len = 20 + strlen(str);
  uint8_t  proto = 0x01;
  int32_t  csum = -1;
  uint32_t src_ip = 0xc0a8000a;
  uint32_t dst_ip = 0xc0a80001;
  pkt_len += craft_ih(ih, tot_len, proto, csum, src_ip, dst_ip);

  /*
   * Fill Application Data
   */
  uint8_t* dp = (uint8_t*)(pkt_ptr + pkt_len);
  memcpy(dp, str, strlen(str));
  pkt_len += strlen(str);

  /*
   * Dump Packet information
   */
  dump_packet(eh, ih, pkt_ptr, pkt_len);

  /*
   * Send Network Interface if ifnams is set;
   */
  if (ifname != "") {
    printf("[+] Send to Network Interface \"%s\" cnt=%zd \n", ifname.c_str(), count);
    slankdev::socketfd sock;
    sock.open_afpacket(ifname.c_str());
    for (size_t i=0; i<count; i++) {
      sock.write(pkt_ptr, pkt_len);
    }
  }

  /*
   * Write Pcap file if filename is set;
   */
  if (filename != "") {
    printf("[+] Write to pcap file \"%s\" cnt=%zd \n", filename.c_str(), count);
    pgen::pcapng_stream stream(filename.c_str(), pgen::open_mode::pcapng_write);
    for (size_t i=0; i<count; i++) {
      stream.send(pkt_ptr, pkt_len);
    }
  }
}


