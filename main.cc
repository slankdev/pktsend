
/*
 * MIT License
 *
 * Copyright (c) 2017 Project Susanow
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
#include <slankdev/color.h>
#include <pgen/io.h>
#include <pgen/core.h>
using namespace slankdev;

std::string ifname = "";
std::string filename = "";
size_t count = 1;
bool verbose = false;
bool hex = false;
ssize_t send_pktlen = -1;
const ssize_t max_pktlen = 10000;

std::string str_hdst    = "";
std::string str_hsrc    = "";
std::string str_etype   = "";
std::string str_tot_len = "";
std::string str_proto   = "";
std::string str_psrc    = "";
std::string str_pdst    = "";
std::string str_csum    = "";

void log(const char* fmt, ...)
{
  printf("[%s+%s] ", RED, RESET);
  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
}

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
  printf("Basic Option\n");
  printf("    -i ifname                    interface name  \n");
  printf("    -w file                      write as pcap format\n");
  printf("    -c count                     packet count    \n");
  printf("    -h                           show usage    \n");
  printf("    -l length                    send packet length \n");
  printf("    --version                    show version    \n");
  printf("    --verbose                    verbose output  \n");
  printf("    --hex                        print packet as hex \n");

  printf("\n");
  printf("Option for Crafting Packet Binary\n");
  printf("    --hsrc=11:22:33:44:55:66     src mac address \n");
  printf("    --hdst=ff:ff:ff:ff:ff:ff     dst mac address \n");
  printf("    --etype=0x0800               ethernet type   \n");
  printf("    --psrc=192.168.0.10          src ip address  \n");
  printf("    --pdst=192.168.0.1           dst ip address  \n");
  printf("    --proto=1                    ip protocol     \n");

  printf("\n");
}

inline static size_t
craft_eh(struct ether* eh,
    pgen::macaddress& dst, pgen::macaddress& src, uint16_t type)
{
  constexpr size_t IP_ADDR_LEN = 6;
  for (size_t i=0; i<IP_ADDR_LEN; i++) {
    eh->dst.addr_bytes[i] = dst.get_octet(i+1);
    eh->src.addr_bytes[i] = src.get_octet(i+1);
  }
  eh->type = bswap16(type);
  return sizeof(ether);
}

inline static size_t
craft_ih(struct ip* ih, uint16_t tot_len, uint8_t proto, int32_t csum,
    pgen::ipv4address& src, pgen::ipv4address& dst)
{
  union U {
    uint32_t u32;
    uint8_t u8[4];
  };
  U src_U, dst_U;

  ih->ver_ihl = 0x45;
  ih->tos     = 0x00;
  ih->tot_len = bswap16(tot_len);
  ih->id      = bswap16(0x0000);
  ih->off     = bswap16(0x0000);
  ih->ttl     = 0x40;
  ih->proto   = proto;
  ih->sum     = bswap16(0x0000);

  for (size_t i=0; i<4; i++) {
    src_U.u8[i] = src.get_octet(i+1);
    dst_U.u8[i] = dst.get_octet(i+1);
  }
  ih->src     = src_U.u32;
  ih->dst     = dst_U.u32;

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
}

enum OPT_FLAG {
  F_HDST=1,
  F_HSRC ,
  F_ETYPE,
  F_TOT_LEN,
  F_PROTO,
  F_CSUM,
  F_PSRC,
  F_PDST,
  F_VERBOSE,
  F_VERSION,
  F_HEX,
};

inline static void
parse_long_opt(OPT_FLAG flag, const char* optarg)
{
  switch (flag) {
    case F_ETYPE  : str_etype   = optarg; break;
    case F_HSRC   : str_hsrc    = optarg; break;
    case F_HDST   : str_hdst    = optarg; break;
    case F_TOT_LEN: str_tot_len = optarg; break;
    case F_PROTO  : str_proto   = optarg; break;
    case F_CSUM   : str_csum    = optarg; break;
    case F_PSRC   : str_psrc    = optarg; break;
    case F_PDST   : str_pdst    = optarg; break;
    case F_VERBOSE: verbose = true      ; break;
    case F_HEX    : hex     = true      ; break;
    case F_VERSION: version(); exit(0);
  }
}

inline static void
parse_opt(int argc, char** argv)
{
  int optflag = -1;

  static struct option long_options[] =
  {
    /* These options don’t set a flag. We distinguish them by their indices. */
    {"hdst"   ,  required_argument, &optflag, F_HDST},
    {"hsrc"   ,  required_argument, &optflag, F_HSRC},
    {"etype"  ,  required_argument, &optflag, F_ETYPE},
    {"tot_len",  required_argument, &optflag, F_TOT_LEN},
    {"proto"  ,  required_argument, &optflag, F_PROTO},
    {"csum"   ,  required_argument, &optflag, F_CSUM},
    {"psrc"   ,  required_argument, &optflag, F_PSRC},
    {"pdst"   ,  required_argument, &optflag, F_PDST},
    {"verbose",  no_argument      , &optflag, F_VERBOSE},
    {"version",  no_argument      , &optflag, F_VERSION},
    {"hex"    ,  no_argument      , &optflag, F_HEX},
    {0, 0, 0, 0},
  };

  while (true) {
    int option_index = 0;
    char c = getopt_long(argc, argv, "i:w:c:l:vh", long_options, &option_index);

    if (c == -1) break;
    switch (c) {
      case 0: {
        parse_long_opt((OPT_FLAG)optflag, optarg);
        break;
      }
      case 'l':
        send_pktlen = atoi(optarg);
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
      case 'h':
        usage(argv[0]);
        exit(0);
      default:
        usage(argv[0]);
        exit(-1);
    }
  }
}

uint32_t htoi(const char* str)
{
  char *endptr;
  uint32_t n = strtol(str, &endptr, 16);
  return n;
}

int main(int argc, char** argv)
{
  parse_opt(argc, argv);

  if (send_pktlen > max_pktlen) {
    fprintf(stderr, "invalid packet length %zd\n", send_pktlen);
    exit(1);
  }

  uint8_t pkt_ptr[max_pktlen] = {0xee};
  size_t  pkt_len = 0;
  const char* str = "slankdev";

  /*
   * Craft Ethernet Header
   */
  ether* eh = (ether*)(pkt_ptr);
  pgen::macaddress dst_mac;
  pgen::macaddress src_mac;
  uint16_t type = str_etype==""?0x0800:htoi(str_etype.c_str());
  dst_mac = str_hdst==""?"ff:ff:ff:ff:ff:ff":str_hdst;
  src_mac = str_hsrc==""?"ff:ff:ff:ff:ff:ff":str_hsrc;
  pkt_len += craft_eh(eh, dst_mac, src_mac, type);

  /*
   * Craft IPv4 Header
   */
  ip* ih = (ip*)(pkt_ptr + pkt_len);
  uint16_t tot_len = str_tot_len==""?(20+strlen(str)):atoi(str_tot_len.c_str());
  uint8_t  proto = str_proto==""?(0x01):atoi(str_proto.c_str());
  int32_t  csum = str_csum==""?(-1):htoi(str_csum.c_str());
  pgen::ipv4address src_ip;
  pgen::ipv4address dst_ip;
  src_ip = str_psrc==""?"192.168.0.10":str_psrc;
  dst_ip = str_pdst==""?"192.168.0.1" :str_pdst;
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
  if (verbose) dump_packet(eh, ih, pkt_ptr, pkt_len);
  if (hex)     slankdev::hexdump(stdout, pkt_ptr, pkt_len);

  if (send_pktlen != -1) {
    pkt_len = send_pktlen > pkt_len ? send_pktlen : pkt_len;
  }

  /*
   * Send Network Interface if ifnams is set;
   */
  if (ifname != "") {
    log("Send to Network Interface \"%s\" cnt=%zd \n", ifname.c_str(), count);
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
    log("Write to pcap file \"%s\" cnt=%zd \n", filename.c_str(), count);
    pgen::pcapng_stream stream(filename.c_str(), pgen::open_mode::pcapng_write);
    for (size_t i=0; i<count; i++) {
      stream.send(pkt_ptr, pkt_len);
    }
  }
}


