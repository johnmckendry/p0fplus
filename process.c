/*
   p0f - packet capture and overall host / flow bookkeeping
   --------------------------------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

/*
 * Modified:
 *  26 September 2017 by John McKendry (jfm), CyGlass, Inc.
 *  Changed find_offset() logic to test every Ethernet packet's link header
 *  for 802.1q VLAN tags and MPLS tags.
 *
 *  2 October 2017 by jfm
 *  Populate new fields in struct packet_data (see process.h modified same day)
 *  for Ethernet dst/src MAC, ethertype, IP length and protocol, UDP ports.
 *  After we get this much working we will add DNS- and HTTP-specific fields.
 *  The purpose is to use p0f to replicate what we are currently collecting
 *  with dumpcap and tshark.
 *
 *  17 October 2017 by jfm
 *  Finishing up with DNS parsing
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <time.h>
#include <ctype.h>

#include <sys/fcntl.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "types.h"
#include "config.h"
#include "debug.h"
#include "alloc-inl.h"
#include "process.h"
#include "hash.h"
#include "tcp.h"
#include "readfp.h"
#include "p0f.h"

#include "fp_tcp.h"
#include "fp_mtu.h"
#include "fp_http.h"

#include "strutils.h"
#include "rtypes.h"

u64 packet_cnt;                         /* Total number of packets processed  */

static s8 link_off = -1;                /* Link-specific IP header offset     */
static u8 bad_packets;                  /* Seen non-IP packets?               */

static struct host_data *host_by_age,   /* All host entries, by last mod      */
                        *newest_host;   /* Tail of the list                   */

static struct packet_flow *flow_by_age, /* All flows, by creation time        */
                          *newest_flow; /* Tail of the list                   */

static struct timeval* cur_time;        /* Current time, courtesy of pcap     */

/* Bucketed hosts and flows: */

static struct host_data    *host_b[HOST_BUCKETS];
static struct packet_flow  *flow_b[FLOW_BUCKETS];

static u32 host_cnt, flow_cnt;          /* Counters for bookkeeping purposes  */

static void flow_dispatch(struct packet_data* pk);
static void nuke_flows(u8 silent);
static void expire_cache(void);


/* Get unix time in milliseconds. */

u64 get_unix_time_ms(void) {

  return ((u64)cur_time->tv_sec) * 1000 + (cur_time->tv_usec / 1000);
}


/* Get unix time in seconds. */

u32 get_unix_time(void) {
  return cur_time->tv_sec;
}


/* Find link-specific offset (pcap knows, but won't tell). */

static void find_offset(const u8* data, s32 total_len) {

  u8 i;

  /* Check hardcoded values for some of the most common options. */

  switch (link_type) {

    case DLT_RAW:        link_off = 0;  return;

    case DLT_NULL:
    case DLT_PPP:        link_off = 4;  return;

    case DLT_LOOP:

#ifdef DLT_PPP_SERIAL
    case DLT_PPP_SERIAL:
#endif /* DLT_PPP_SERIAL */

    case DLT_PPP_ETHER:  link_off = 8;  return;

    case DLT_EN10MB:     /* jfm 26 Sept 2017 - Check for presence of 802.1q VLAN
    						tag in Ethertype field (also check for 8847/8848 MPLS tag). */
    					 if ((data[12] == 0x81 && data[13] == 0) ||
    							 (data[12] == 0x88 && ((data[13] == 0x47) || (data[13] == 0x48)))) {
    						 link_off = 18;
    					 } else {
    						 link_off = 14;
    					 }
    					 return;

#ifdef DLT_LINUX_SLL
    case DLT_LINUX_SLL:  link_off = 16; return;
#endif /* DLT_LINUX_SLL */

    case DLT_PFLOG:      link_off = 28; return;

    case DLT_IEEE802_11: link_off = 32; return;
  }

  /* If this fails, try to auto-detect. There is a slight risk that if the
     first packet we see is maliciously crafted, and somehow gets past the
     configured BPF filter, we will configure the wrong offset. But that
     seems fairly unlikely. */

  for (i = 0; i < 40; i += 2, total_len -= 2) {

    if (total_len < MIN_TCP4) break;

    /* Perhaps this is IPv6? We check three things: IP version (first 4 bits);
       total length sufficient to accommodate IPv6 and TCP headers; and the
       "next protocol" field equal to PROTO_TCP. */

    if (total_len >= MIN_TCP6 && (data[i] >> 4) == IP_VER6) {

      struct ipv6_hdr* hdr = (struct ipv6_hdr*)(data + i);

      if (hdr->proto == PROTO_TCP) {

        DEBUG("[#] Detected packet offset of %u via IPv6 (link type %u).\n", i,
              link_type);
        link_off = i;
        break;

      }
      
    }

    /* Okay, let's try IPv4 then. The same approach, except the shortest packet
       size must be just enough to accommodate IPv4 + TCP (already checked). */

    if ((data[i] >> 4) == IP_VER4) {

      struct ipv4_hdr* hdr = (struct ipv4_hdr*)(data + i);

      if (hdr->proto == PROTO_TCP) {

        DEBUG("[#] Detected packet offset of %u via IPv4 (link type %u).\n", i,
              link_type);
        link_off = i;
        break;

      }

    }

  }

  /* If we found something, adjust for VLAN tags (ETH_P_8021Q == 0x8100). Else,
     complain once and try again soon. */

  if (link_off >= 4 && data[i-4] == 0x81 && data[i-3] == 0x00) {

    DEBUG("[#] Adjusting offset due to VLAN tagging.\n");
    link_off -= 4;

  } else if (link_off == -1) {

    link_off = -2;
    WARN("Unable to find link-specific packet offset. This is bad.");

  }

}


/* Convert IPv4 or IPv6 address to a human-readable form. */

u8* addr_to_str(u8* data, u8 ip_ver) {

  static char tmp[128];

  /* We could be using inet_ntop(), but on systems that have older libc
     but still see passing IPv6 traffic, we would be in a pickle. */

  if (ip_ver == IP_VER4) {

    sprintf(tmp, "%u.%u.%u.%u", data[0], data[1], data[2], data[3]);

  } else {

    sprintf(tmp, "%x:%x:%x:%x:%x:%x:%x:%x",
            (data[0] << 8) | data[1], (data[2] << 8) | data[3], 
            (data[4] << 8) | data[5], (data[6] << 8) | data[7], 
            (data[8] << 8) | data[9], (data[10] << 8) | data[11], 
            (data[12] << 8) | data[13], (data[14] << 8) | data[15]);

  }

  return (u8*)tmp;

}


/* Parse PCAP input, with plenty of sanity checking. Store interesting details
   in a protocol-agnostic buffer that will be then examined upstream. */

void parse_packet(void* junk, const struct pcap_pkthdr* hdr, const u8* data) {

  struct tcp_hdr* tcp;
  // jfm 3 Oct 2017 - add udp header pointer
  struct udp_hdr* udp;
  struct packet_data pk;

  s32 packet_len;
  u32 tcp_doff;

  u8* opt_end;

  packet_cnt++;
  pk.packet_addr = (u8*)data; /* used in DNS parsing */
  cur_time = (struct timeval*)&hdr->ts;
  pk.pkttime = cur_time->tv_sec + (cur_time->tv_usec/1000000.);
  pk.framelen = hdr->len;

  if (!(packet_cnt % EXPIRE_INTERVAL)) expire_cache();

  /* Be paranoid about how much data we actually have off the wire. */

  packet_len = MIN(hdr->len, hdr->caplen);
  if (packet_len > SNAPLEN) packet_len = SNAPLEN;
  pk.packetlen = packet_len;

  // DEBUG("[#] Received packet: len = %d, caplen = %d, limit = %d\n",
  //    hdr->len, hdr->caplen, SNAPLEN);

  // jfm 2 Oct 2017 - copy Ethernet dst and src MAC addresses into the struct packet_data -
  memcpy (pk.etherdst, &data[0], 6);
  memcpy (pk.ethersrc, &data[6], 6);
  // TODO: get ethertype into packet_data, remembering 802.1q VLAN issues. Not currently used,
  //  so it can wait for now.
  //debug
  //u16 ethertype;
  //memcpy (&ethertype, &data[12],2);
  //SAYF ("ethertype = %x\n", ethertype);
  /* Account for link-level headers. */
  /* jfm 26 Sept 2017 - call find_offset() for every packet; do not assume that all headers
   * have the same length. 802.1q VLAN packets and ordinary Ethernet packets can coexist
   * on the same segment.
   *
      if (link_off < 0)
*/
  find_offset(data, packet_len);
  //debug
  //SAYF ("find_offset() returns offset to data of %d\n",link_off);

  if (link_off > 0) {

    data += link_off;
    packet_len -= link_off;

  }

  /* If there is no way we could have received a complete TCP packet, bail
     out early. */
  /* jfm 27 Sept 2017 - Since I'm planning to change this code to process UDP as well
   * as TCP (and eventually ICMP also), just comment this test out. If there's a problem
   * with headers and packet formats we will find it soon enough.
   *
  if (packet_len < MIN_TCP4) {
    DEBUG("[#] Packet too short for any IPv4 + TCP headers, giving up!\n");
    return;
  } */

  pk.quirks = 0;

  if ((*data >> 4) == IP_VER4) {

    /************************
     * IPv4 header parsing. *
     ************************/
    const struct ipv4_hdr* ip4 = (struct ipv4_hdr*)data;

    u32 hdr_len = (ip4->ver_hlen & 0x0F) * 4;
    u16 flags_off = ntohs(RD16(ip4->flags_off));
    u16 tot_len = ntohs(RD16(ip4->tot_len));

    /* If the packet claims to be shorter than what we received off the wire,
       honor this claim to account for etherleak-type bugs. */

    if (packet_len > tot_len) {
      packet_len = tot_len;
      // DEBUG("[#] ipv4.tot_len = %u, adjusted accordingly.\n", tot_len);
    }

    /* Bail out if the result leaves no room for IPv4 + TCP headers. */

    if (packet_len < MIN_TCP4) {
      DEBUG("[#] packet_len = %u. Too short for IPv4 + TCP, giving up!\n",
            packet_len);
      return;
    }

    /* Bail out if the declared length of IPv4 headers is nonsensical. */

    if (hdr_len < sizeof(struct ipv4_hdr)) {
      DEBUG("[#] ipv4.hdr_len = %u. Too short for IPv4, giving up!\n",
            hdr_len);
      return;
    }

    /* If the packet claims to be longer than the recv buffer, best to back
       off - even though we could just ignore this and recover. */

    if (tot_len > packet_len) {
      DEBUG("[#] ipv4.tot_len = %u but packet_len = %u, bailing out!\n",
            tot_len, packet_len);
      return;
    }

    /* And finally, bail out if after skipping the IPv4 header as specified
       (including options), there wouldn't be enough room for TCP. */
    /* jfm 2 Oct 2017 - no more of this TCP-only prejudice.
    if (hdr_len + sizeof(struct tcp_hdr) > packet_len) {
      DEBUG("[#] ipv4.hdr_len = %u, packet_len = %d, no room for TCP!\n",
            hdr_len, packet_len);
      return;
    }*/

    /* Bail out if the subsequent protocol is not TCP. */
    /* jfm 2 Oct 2017 - we are going to do both TCP and UDP, and ICMP later.
     * Fingerprinting will still work fine.
    if (ip4->proto != PROTO_TCP) {
      DEBUG("[#] Whoa, IPv4 packet with non-TCP payload (%u)?\n", ip4->proto);
      return;
    } */

    /* Ignore any traffic with MF or non-zero fragment offset specified. We
       can do enough just fingerprinting the non-fragmented traffic. */
    /* jfm 2 Oct 2017 - this won't happen very often, but we shouldn't throw
     * away packets before we harvest their headers.
    if (flags_off & ~(IP4_DF | IP4_MBZ)) {
      DEBUG("[#] Packet fragment (0x%04x), letting it slide!\n", flags_off);
      return;
    } */

    /* Store some relevant information about the packet. */

    pk.ip_ver = IP_VER4;

    pk.ip_opt_len = hdr_len - 20;

    memcpy(pk.src, ip4->src, 4);
    memcpy(pk.dst, ip4->dst, 4);

    pk.tos = ip4->tos_ecn >> 2;

    pk.ttl = ip4->ttl;

    //jfm 2 Oct 2017
    pk.ipproto = ip4->proto;
    //debug
    //SAYF ("packet ipproto is %d\n", pk.ipproto);
    pk.iplen = tot_len;
    
    if (ip4->tos_ecn & (IP_TOS_CE | IP_TOS_ECT)) pk.quirks |= QUIRK_ECN;

    /* Tag some of the corner cases associated with implementation quirks. */
    
    if (flags_off & IP4_MBZ) pk.quirks |= QUIRK_NZ_MBZ;

    if (flags_off & IP4_DF) {

      pk.quirks |= QUIRK_DF;
      if (RD16(ip4->id)) pk.quirks |= QUIRK_NZ_ID;

    } else {

      if (!RD16(ip4->id)) pk.quirks |= QUIRK_ZERO_ID;

    }

    pk.tot_hdr = hdr_len;

    tcp = (struct tcp_hdr*)(data + hdr_len);
    udp = (struct udp_hdr*)(data + hdr_len);
    packet_len -= hdr_len;
    
  } else if ((*data >> 4) == IP_VER6) {

    /************************
     * IPv6 header parsing. *
     ************************/
    
    const struct ipv6_hdr* ip6 = (struct ipv6_hdr*)data;
    u32 ver_tos = ntohl(RD32(ip6->ver_tos));
    u32 tot_len = ntohs(RD16(ip6->pay_len)) + sizeof(struct ipv6_hdr);

    /* If the packet claims to be shorter than what we received off the wire,
       honor this claim to account for etherleak-type bugs. */

    if (packet_len > tot_len) {
      packet_len = tot_len;
      // DEBUG("[#] ipv6.tot_len = %u, adjusted accordingly.\n", tot_len);
    }

    /* Bail out if the result leaves no room for IPv6 + TCP headers. */

    if (packet_len < MIN_TCP6) {
      DEBUG("[#] packet_len = %u. Too short for IPv6 + TCP, giving up!\n",
            packet_len);
      return;
    }

    /* If the packet claims to be longer than the data we have, best to back
       off - even though we could just ignore this and recover. */

    if (tot_len > packet_len) {
      DEBUG("[#] ipv6.tot_len = %u but packet_len = %u, bailing out!\n",
            tot_len, packet_len);
      return;
    }

    /* Bail out if the subsequent protocol is not TCP. One day, we may try
       to parse and skip IPv6 extensions, but there seems to be no point in
       it today. */
    /*
     * jfm 3 Oct 2017 - I'm going to leave this alone for now, even though
     *  I'm trying to adapt this to handle UDP as well, because I agree that
     *  IPv6 extensions make the job too complicated for too little reward.
     *  For now, our story is that we only support IPv4.
     */
    if (ip6->proto != PROTO_TCP) {
      DEBUG("[#] IPv6 packet with non-TCP payload (%u).\n", ip6->proto);
      return;
    }

    /* Store some relevant information about the packet. */

    pk.ip_ver = IP_VER6;

    pk.ip_opt_len = 0;

    memcpy(pk.src, ip6->src, 16);
    memcpy(pk.dst, ip6->dst, 16);

    pk.tos = (ver_tos >> 22) & 0x3F;

    pk.ttl = ip6->ttl;

    if (ver_tos & 0xFFFFF) pk.quirks |= QUIRK_FLOW;

    if ((ver_tos >> 20) & (IP_TOS_CE | IP_TOS_ECT)) pk.quirks |= QUIRK_ECN;

    pk.tot_hdr = sizeof(struct ipv6_hdr);

    tcp = (struct tcp_hdr*)(ip6 + 1);
    packet_len -= sizeof(struct ipv6_hdr);

  } else {

    if (!bad_packets) {
      WARN("Unknown packet type %u, link detection issue?", *data >> 4);
      bad_packets = 1;
    }

    return;

  }

  /***************
   * TCP parsing *
   ***************/
  if (pk.ipproto == PROTO_TCP) {
  //debug
  //SAYF ("Parsing TCP packet.\n");
  data = (u8*)tcp;

  tcp_doff = (tcp->doff_rsvd >> 4) * 4;

  /* As usual, let's start with sanity checks. */

  if (tcp_doff < sizeof(struct tcp_hdr)) {
    DEBUG("[#] tcp.hdr_len = %u, not enough for TCP!\n", tcp_doff);
    return;
  }

  if (tcp_doff > packet_len) {
    DEBUG("[#] tcp.hdr_len = %u, past end of packet!\n", tcp_doff);
    return;
  }

  pk.tot_hdr += tcp_doff;

  pk.sport = ntohs(RD16(tcp->sport));
  pk.dport = ntohs(RD16(tcp->dport));
  pk.udp_sport = 0;
  pk.udp_dport = 0;

  pk.tcp_type = tcp->flags & (TCP_SYN | TCP_ACK | TCP_FIN | TCP_RST);
  // jfm 4 Oct 2017 
  pk.tcp_flags = tcp->flags;
  /* NUL, SYN+FIN, SYN+RST, FIN+RST, etc, should go to /dev/null. */

  if (((tcp->flags & TCP_SYN) && (tcp->flags & (TCP_FIN | TCP_RST))) ||
      ((tcp->flags & TCP_FIN) && (tcp->flags & TCP_RST)) ||
      !pk.tcp_type) {

    DEBUG("[#] Silly combination of TCP flags: 0x%02x.\n", tcp->flags);
    // jfm 4 Oct 2017 - we want to keep track of this kind of thing,
    //  because it could be malicious, so don't just bail out.
    // return;

  }

  pk.win = ntohs(RD16(tcp->win));

  pk.seq = ntohl(RD32(tcp->seq));

  /* Take note of miscellanous features and quirks. */

  if ((tcp->flags & (TCP_ECE | TCP_CWR)) || 
      (tcp->doff_rsvd & TCP_NS_RES)) pk.quirks |= QUIRK_ECN;

  if (!pk.seq) pk.quirks |= QUIRK_ZERO_SEQ;

  if (tcp->flags & TCP_ACK) {

    if (!RD32(tcp->ack)) pk.quirks |= QUIRK_ZERO_ACK;

  } else {

    /* A good proportion of RSTs tend to have "illegal" ACK numbers, so
       ignore these. */

    if (RD32(tcp->ack) & !(tcp->flags & TCP_RST)) {

      DEBUG("[#] Non-zero ACK on a non-ACK packet: 0x%08x.\n",
            ntohl(RD32(tcp->ack)));

      pk.quirks |= QUIRK_NZ_ACK;

    }

  }

  if (tcp->flags & TCP_URG) {

    pk.quirks |= QUIRK_URG;

  } else {

    if (RD16(tcp->urg)) {

      DEBUG("[#] Non-zero UPtr on a non-URG packet: 0x%08x.\n",
            ntohl(RD16(tcp->urg)));

      pk.quirks |= QUIRK_NZ_URG;

    }

  }

  if (tcp->flags & TCP_PUSH) pk.quirks |= QUIRK_PUSH;

  /* Handle payload data. */

  if (tcp_doff == packet_len) {

    pk.payload = NULL;
    pk.pay_len = 0;

  } else {

    pk.payload = (u8*)data + tcp_doff;
    pk.pay_len = packet_len - tcp_doff;

  }

  /**********************
   * TCP option parsing *
   **********************/

  opt_end = (u8*)data + tcp_doff; /* First byte of non-option data */
  data = (u8*)(tcp + 1);

  pk.opt_cnt     = 0;
  pk.opt_eol_pad = 0;
  pk.mss         = 0;
  pk.wscale      = 0;
  pk.ts1         = 0;

  /* Option parsing problems are non-fatal, but we want to keep track of
     them to spot buggy TCP stacks. */

  while (data < opt_end && pk.opt_cnt < MAX_TCP_OPT) {

    pk.opt_layout[pk.opt_cnt++] = *data;

    switch (*data++) {

      case TCPOPT_EOL:

        /* EOL is a single-byte option that aborts further option parsing.
           Take note of how many bytes of option data are left, and if any of
           them are non-zero. */

        pk.opt_eol_pad = opt_end - data;
        
        while (data < opt_end && !*data++);

        if (data != opt_end) {
          pk.quirks |= QUIRK_OPT_EOL_NZ;
          data = opt_end;
        }

        break;

      case TCPOPT_NOP:

        /* NOP is a single-byte option that does nothing. */

        break;
  
      case TCPOPT_MAXSEG:

        /* MSS is a four-byte option with specified size. */

        if (data + 3 > opt_end) {
          DEBUG("[#] MSS option would end past end of header (%u left).\n",
                opt_end - data);
          goto abort_options;
        }

        if (*data != 4) {
          DEBUG("[#] MSS option expected to have 4 bytes, not %u.\n", *data);
          pk.quirks |= QUIRK_OPT_BAD;
        }

        pk.mss = ntohs(RD16p(data+1));

        data += 3;

        break;

      case TCPOPT_WSCALE:

        /* WS is a three-byte option with specified size. */

        if (data + 2 > opt_end) {
          DEBUG("[#] WS option would end past end of header (%u left).\n",
                opt_end - data);
          goto abort_options;
        }

        if (*data != 3) {
          DEBUG("[#] WS option expected to have 3 bytes, not %u.\n", *data);
          pk.quirks |= QUIRK_OPT_BAD;
        }

        pk.wscale = data[1];

        if (pk.wscale > 14) pk.quirks |= QUIRK_OPT_EXWS;

        data += 2;

        break;

      case TCPOPT_SACKOK:

        /* SACKOK is a two-byte option with specified size. */

        if (data + 1 > opt_end) {
          DEBUG("[#] SACKOK option would end past end of header (%u left).\n",
                opt_end - data);
          goto abort_options;
        }

        if (*data != 2) {
          DEBUG("[#] SACKOK option expected to have 2 bytes, not %u.\n", *data);
          pk.quirks |= QUIRK_OPT_BAD;
        }

        data++;

        break;

      case TCPOPT_SACK:

        /* SACK is a variable-length option of 10 to 34 bytes. Because we don't
           know the size any better, we need to bail out if it looks wonky. */

        if (data == opt_end) {
          DEBUG("[#] SACK option without room for length field.");
          goto abort_options;
        }

        if (*data < 10 || *data > 34) {
          DEBUG("[#] SACK length out of range (%u), bailing out.\n", *data);
          goto abort_options;
        }

        if (data - 1 + *data > opt_end) {
          DEBUG("[#] SACK option (len %u) is too long (%u left).\n",
                *data, opt_end - data);
          goto abort_options;
        }

        data += *data - 1;

        break;

      case TCPOPT_TSTAMP:

        /* Timestamp is a ten-byte option with specified size. */

        if (data + 9 > opt_end) {
          DEBUG("[#] TStamp option would end past end of header (%u left).\n",
                opt_end - data);
          goto abort_options;
        }

        if (*data != 10) {
          DEBUG("[#] TStamp option expected to have 10 bytes, not %u.\n",
                *data);
          pk.quirks |= QUIRK_OPT_BAD;
        }

        pk.ts1 = ntohl(RD32p(data + 1));

        if (!pk.ts1) pk.quirks |= QUIRK_OPT_ZERO_TS1;

        if (pk.tcp_type == TCP_SYN && RD32p(data + 5)) {

          DEBUG("[#] Non-zero second timestamp: 0x%08x.\n",
                ntohl(*(u32*)(data + 5)));

          pk.quirks |= QUIRK_OPT_NZ_TS2;

        }

        data += 9;

        break;

      default:

        /* Unknown option, presumably with specified size. */

        if (data == opt_end) {
          DEBUG("[#] Unknown option 0x%02x without room for length field.",
                data[-1]);
          goto abort_options;
        }

        if (*data < 2 || *data > 40) {
          DEBUG("[#] Unknown option 0x%02x has invalid length %u.\n",
                data[-1], *data);
          goto abort_options;
        }

        if (data - 1 + *data > opt_end) {
          DEBUG("[#] Unknown option 0x%02x (len %u) is too long (%u left).\n",
                data[-1], *data, opt_end - data);
          goto abort_options;
        }

        data += *data - 1;

    }

  }

  if (data != opt_end) {

abort_options:

    DEBUG("[#] Option parsing aborted (cnt = %u, remainder = %u).\n",
          pk.opt_cnt, opt_end - data);

    pk.quirks |= QUIRK_OPT_BAD;

  }
  } //end if (TCP)
  /*
   * UDP Processing
   */
  else if (pk.ipproto == PROTO_UDP){
  data = (u8*)udp;
  // jfm 4 Oct 2017 -
  //  Since we are imitating tshark and writing out both TCP ports and UDP ports in
  //  every record (one or the other pair will be null), we need
  //  to have separate slots in the struct for TCP ports and 
  //  UDP ports. We have to remember to null out the ones not used.
  //  Note: if you specify an output format %.0d to something like printf, a value of
  //  zero does not print at all. This is useful for mimicking the output
  //  of tshark.
  pk.udp_sport = ntohs(RD16(udp->sport));
  pk.udp_dport = ntohs(RD16(udp->dport));
  pk.sport = 0;
  pk.dport =0;
  pk.tcp_flags = 0;
  pk.payload = (u8*)data + sizeof(struct udp_hdr); 
  pk.pay_len = ntohs(RD16(udp->len));
  }

  pk.dns_id = 0;
  pk.dns_flags_response = 0;
  pk.dns_flags_rcode = 0;
  pk. dns_query = (dns_question*) 0;
  pk.dns_response = (dns_rr*) 0;
  if ((pk.sport == 53) || (pk.dport == 53) || (pk.udp_sport == 53) || (pk.udp_dport == 53)) {
    parse_dns(&pk);
  }
  /*
   * jfm 3 Oct 2017 - quick and dirty sanity check
   *  9 Oct 17 - Comment out while debugging parse_dns(), restore after
   * 16 Oct 17 = define DEMO 1 to see all output, 0 if you only want to see DNS results
   */
#define DEMO 1
#if DEMO
  print_like_tshark(&pk);

  // Only TCP has to go to the fingerprinting path
  if (pk.ipproto == PROTO_TCP){
    flow_dispatch(&pk);
  }
#endif //DEMO is defined as 1
}
void parse_dns (struct packet_data *pk){
	// TODO: Since we intend to deal with DNS/TCP as well as DNS/UDP, we need to
	//  protect against TCP handshake packets with no payload. We will also
	//  see packets that are not standard name-lookup queries (query type "A" or "AAAA").
#ifdef TRACE_EXECUTION
	SAYF ("In parse_dns() with payload length %d\n", pk->pay_len);
#endif
	// Payload has to be at least 12 bytes - 2 bytes ID, 2 bytes codes (see below),
	// 2 bytes each for QDCOUNT, ANCOUNT, NSCOUNT, and ARCOUNT (NSCOUNT and ARCOUNT
	//  are ignored, but if they're not present there's a problem).
	//  Note that this could also be a TCP handshake packet. We shouldn't try to parse
	//  those, so bailing out here is appropriate.
	if (pk->pay_len < sizeof(struct dns_header)){
#ifdef TRACE_EXECUTION
		SAYF ("	Payload length %d is too small to be a valid DNS header, not parsed\n", pk->pay_len);
#endif
		return;
	}
	// On entry to this function, pk->payload points to the beginning of a DNS header.
	// Save this pointer because it is needed for calculating offsets in compressed names.
	u16* dns_id_ptr = (u16*)pk->payload;
	pk->dns_id_offset = pk->payload - pk->packet_addr;
	// Prepare this pointer to point to the beginning of the Questions section.
	// parse_dns_questions() should update it to point to the Answers section if any,
	// else zero.
	pk->next_dns_section = pk->payload + sizeof(struct dns_header);
	pk->dns_id = ntohs(RD16p(dns_id_ptr));
	u16* dns_codes_ptr = dns_id_ptr + 1;
	u16 dns_codes = ntohs(RD16p(dns_codes_ptr));
#ifdef TRACE_EXECUTION
	SAYF("DNS ID %#x\n", pk->dns_id);
	SAYF("DNS codes %#x\n", dns_codes);
#endif
	/*
	 * dns_codes looks like this:
	|QR|Opcode |AA|TC|RD| - 1st (high) byte, Opcode is 4 bits, others 1 bit
	|RA|MBZ|Rcode| - 2nd byte, RA 1 bit, MBZ 3 bits, Rcode 4 bits.
	QR - query = 0, response = 1. Opcode - 0 = standard query (there are many other values)
	AA - Authoritative Answer = 1. TC - Response truncated = 1 (bad)
	RD - Recursive lookup desired = 1 (usually set). RA - recursion available
	MBZ - Must be zero. Rcode - 0 = no error, 1 = format error, 2 = server error,
		3 = name error (if AA == 1, the domain name does not exist - NXDOMAIN),
		4 = Not Implemented (Server doesn't do that kind of query),
		5 = Refused (policy prohibits, e.g. unauthorized to do zone transfer)
	Typical values are 0x100 for a request and 0x8180 for a response.
        0x100 = (QR = 0, opcode =0, AA=TC=0, RD =1) in high byte, low byte zeros.
	0x8180 = (QR = 1, 6 zeros, RD = 1) in high byte, (RA = 1, 3 MBZ, Rcode = 0) in low byte.
	0x8183 = same except Rcode = 3 = NXDOMAIN.
	One caveat/gotcha if you're looking at the RFCs: what the RFCs call "bit 0" is the
	high-order bit of whatever field you're looking at; we little-endians think of this
	as bit 7/15/31 depending on the field type. (This is not the same issue as byte order,
	which is handled by the network-to-host-order macros like ntohs.)
	*/
	pk->dns_flags_response = (dns_codes >> 15) & 1;
	pk->dns_flags_rcode = dns_codes & 0x0f;
	// Now deal with the questions and answers.
	u16* dns_qdcount_ptr = dns_codes_ptr + 1;
	pk->dns_qdcount = ntohs(RD16p(dns_qdcount_ptr));
	u16* dns_ancount_ptr = dns_qdcount_ptr + 1;
	pk->dns_ancount = ntohs(RD16p(dns_ancount_ptr));
#ifdef TRACE_EXECUTION
	SAYF ("DNS flags response %#x\n", pk->dns_flags_response);
	SAYF ("DNS flags rcode %#x\n", pk->dns_flags_rcode);
	SAYF ( "DNS questions count %d, answers count %d\n", pk->dns_qdcount,pk->dns_ancount);
#endif
	// Not interested in nscount and arcount right now.
	// parse the Questions section. make sure qdcount is non-zero, just in case someone is
	// trying to be cute with us.
	if (pk->dns_qdcount > 0) {
		parse_dns_questions(pk, (char*)dns_id_ptr);
#ifdef TRACE_EXECUTION
		if (pk->dns_query != (dns_question*)0) {
		  dns_question dq = *(pk->dns_query);
		  SAYF ("DNS question name %s, type %d, class %d\n",
			dq.name, dq.type, dq.cls);
		} else {
		  SAYF ("parse_dns_questions() didn't work\n");
		}
#endif
	}
	if (pk->dns_ancount > 0) {
		parse_dns_answers(pk, (char*)dns_id_ptr);
#ifdef TRACE_EXECUTION
		if (pk->dns_response != (dns_rr*)0) {
		  dns_rr * dr = pk->dns_response;
		  // recurse while dr->next not zero
		  do {
		  	SAYF ("DNS response name %s, type %d, class %d, TTL %d, RDLENGTH %d, Answer %s\n",
			  dr->name, dr->type, dr->cls, dr->ttl, dr->rdlength, dr->data);
			dr = dr->next;
		  } while (dr);
		} else {
		  SAYF ("parse_dns_answers() didn't work\n");
		}
#endif
	}
	return;
}

void parse_dns_questions(struct packet_data *pk, char* dns_base_ptr) {
// Puts a linked list of dns_question structs to pk->dns_query.
// TODO - all the dns_question structs and their name contents need to be freed
//   after use.
// dns_base_ptr is needed to calculate offsets when name compression is used.
    dns_question * last = NULL;
    dns_question * current;
// variables needed for read_rr_name() taken from LANL dns_parse code.
//  The borrowed code uses offsets into the packet rather than pointers to
//  headers and payloads.
    const uint8_t * packet = (const uint8_t *)pk->packet_addr;
    uint32_t packet_p; //offset from start of packet to start of Question record
    uint32_t id_pos; //offset to start of DNS header (i.e. the ID field). Used to
		     // locate components of names that use compression (RFC 1035,
		     // Section 4.1.4)
    uint32_t pktlen = pk->packetlen;
    id_pos = (u8 *)dns_base_ptr - pk->packet_addr;
    packet_p = pk->next_dns_section - pk->packet_addr;

    for (int i=0; i < pk->dns_qdcount; i++) {
        current = malloc(sizeof(dns_question));
        current->next = NULL; current->name = NULL;

        current->name = read_rr_name(packet, &packet_p, 
                    id_pos, pktlen);
        if (current->name == NULL) {
	// TODO - Test this.
            // Handle a bad DNS name.
            //fprintf(stderr, "DNS question error\n");

            char * buffer = escape_data(packet, packet_p, pktlen);
            const char * msg = "Bad DNS question: ";
            current->name = malloc(sizeof(char) * (strlen(buffer) +
                                                   strlen(msg) + 1));
            sprintf(current->name, "%s%s", msg, buffer);
            free(buffer);
            current->type = 0;
            current->cls = 0;
            if (last == NULL) pk->dns_query = current;
            else last->next = current;
	    // If we can't parse a Question we won't be able to find any
	    // following sections, so don't bother to try.
	    pk->dns_ancount = 0; 
            return;
        }
	// read_rr_name() updates packet_p to the offset following the
	// last name in the Question record, i.e. the offset to the Type
	// field.

	// TODO - fix this to use ntohs
        current->type = (packet[packet_p] << 8) + packet[packet_p +1 ];
        current->cls = (packet[packet_p + 2] << 8) + packet[packet_p + 3];

        // Add this question object to the list.
        if (last == NULL) pk->dns_query = current;
        else last->next = current;
        last = current;
    }
    // Update pointer to address of first DNS Answer record (if any). 
    // parse_dns_answers() needs this value.
    // the Magic Number 4 here is the size of the Type and Class fields.
    pk->next_dns_section = pk->packet_addr + packet_p + 4;
    return;
}

void parse_dns_answers(struct packet_data *pk, char* dns_base_ptr){
// Puts a linked list of dns_rr (resource record) structs to pk->dns_response.
// TODO - all the dns_rr structs and their name contents need to be freed
//   after use.
    rr_parser_container* parser; 
// dns_base_ptr is needed to calculate offsets when name compression is used.
    dns_rr * last = NULL;
    dns_rr * current;
// variables needed for read_rr_name() taken from LANL dns_parse code.
//  The borrowed code uses offsets into the packet rather than pointers to
//  headers and payloads.
    const uint8_t * packet = (const uint8_t *)pk->packet_addr;
    uint32_t packet_p; //offset from start of packet to start of Question record
    uint32_t id_pos; //offset to start of DNS header (i.e. the ID field). Used to
		     // locate components of names that use compression (RFC 1035,
		     // Section 4.1.4)
    uint32_t pktlen = pk->packetlen;
    id_pos = (u8 *)dns_base_ptr - pk->packet_addr;
    packet_p = pk->next_dns_section - pk->packet_addr;

    for (int i=0; i < pk->dns_ancount; i++) {
        current = malloc(sizeof(dns_rr));
        current->next = NULL; current->name = NULL;

        current->name = read_rr_name(packet, &packet_p, 
                    id_pos, pktlen);
        if (current->name == NULL) {
	// TODO - test this. 
            // Handle a bad DNS name.
            //fprintf(stderr, "DNS Answer parse error on Answer %d\n", i);

            char * buffer = escape_data(packet, packet_p, pktlen);
            const char * msg = "Bad DNS Answer: ";
            current->name = malloc(sizeof(char) * (strlen(buffer) +
                                                   strlen(msg) + 1));
            sprintf(current->name, "%s%s", msg, buffer);
            free(buffer);

            current->type = 0;
            current->cls = 0;
            if (last == NULL) pk->dns_response = current;
            else last->next = current;
            return;
        }
	// read_rr_name() updates packet_p to the offset following the
	// last name in the Answer record, i.e. the offset to the Type
	// field.

	current->type = ntohs(RD16p(&packet[packet_p]));
	current->cls = ntohs(RD16p(&packet[packet_p + 2]));
	//  The fields following the class are 
	//   Time to Live (4 bytes, use ntohl),
	//   Response Data length in bytes (RDLENGTH), 2 bytes,
	//   Response Data, length determined by RDLENGTH.
	current->ttl = ntohl(RD32p(&packet[packet_p + 4]));
	current->rdlength = ntohs(RD16p(&packet[packet_p + 8]));
	//
	// So far, so good, but now we have to get the actual answer, which
	//  may be an IPv4 address, an IPv6 address, a name string, or something
	//  even more sinister, depending on the query and answer type and class.
	// TODO - use the existing parser code from the LANL dns_parse
	//  package to get the RDATA.
	parser = find_parser(current->cls, current->type);
	current->rr_name = parser->name;
	packet_p += 10; // Index of RDATA.
			// Magic Number = 10 because Type = 2 bytes, 
			// Class = 2 bytes, TTL = 4 bytes, 
			// and RDLENGTH = 2 bytes.
	current->data = parser->parser(packet, packet_p, id_pos, 
				current->rdlength, pktlen);
        // Add this Answer (Resource Record) object to the list.
        if (last == NULL) pk->dns_response = current;
        else last->next = current;
        last = current;
	// Update index to the position of the next Answer record. 
	packet_p += current->rdlength;
    }

    return;
}

// Free a dns_rr struct.
void dns_rr_free(dns_rr * rr) {
    if (rr == NULL) return;
    if (rr->name != NULL) free(rr->name);
    if (rr->data != NULL) free(rr->data);
    dns_rr_free(rr->next);
    free(rr);
}

// Free a dns_question struct.
void dns_question_free(dns_question * question) {
    if (question == NULL) return;
    if (question->name != NULL) free(question->name);
    dns_question_free(question->next);
    free(question);
}

#define USING_STRUTILS
#ifndef USING_STRUTILS /*This code is borrowed from strutils.c. Now that I
	have decided to bring strutils.c into the project I don't need the
	code here, but I added some comments that I want to keep. */
char * read_rr_name(const uint8_t * packet, uint32_t * packet_p, 
                    uint32_t id_pos, uint32_t len) {
// 'packet' is the address of the raw packet.
// On entry, 'packet_p' points to the offset from the start of the packet to 
//  the start of a Question record. Note it does not point to the start of
//  the Question record, it points to a number that can be used as an
//  index into an array of char.
// 'id_pos' is the offset from start of packet to start of the DNS header. It
//  is needed for calculating offsets for name compression. It is not
//  modified.
// 'len' = header->len from caller, where header is *pcap_pkthdr,
//  so it's the whole packet length.
// The string returned from this function is malloced and should be freed
//  when it is no longer needed. 
    uint32_t i, next, pos=*packet_p;
    uint32_t end_pos = 0;
    uint32_t name_len=0;
    uint32_t steps = 0;
    char * name;

    // Scan through the name, one character at a time. We need to look at 
    // each character to look for values we can't print in order to allocate
    // extra space for escaping them.  'next' is the next position to look
    // for a compression jump or name end.
    // It's possible that there are endless loops in the name. Our protection
    // against this is to make sure we don't read more bytes in this process
    // than twice the length of the data.  Names that take that many steps to 
    // read in should be impossible.
    // next and pos are index numbers over packet[] as an array of char. pos moves
    // one character at a time; next increments by the length of a piece of a name.
    // Domain names in DNS are represented as counted strings, e.g. "google.com"
    // is represented as 6,g,o,o,g,l,e,3,c,o,m,0 . If that's the content of the
    // name field here, at first both packet[pos] and packet[next] would be 6 (the
    // number of chars in 'google'). Then pos is incremented by 1 and next is incremented
    // by 1 plus the number 6 in the char just read. So packet[pos] is now 'g', and
    // packet[next] is 3, the beginning of the 'com' part of the name. As long as pos 
    // is less than next we are stepping through an array of characters that are part of
    // a name; when pos catches up to next we are looking at a count of characters in
    // the next part of the name, or 0 if we have reached the end.
    // Name compression makes it a little more complicated. 
    next = pos;
    while (pos < len && !(next == pos && packet[pos] == 0)
           && steps < len*2) {
        uint8_t c = packet[pos];
        steps++;
        if (next == pos) {
            // Handle message compression.  
            // If the length byte starts with the bits 11, then the rest of
            // this byte and the next form the offset from the dns proto start
            // to the start of the remainder of the name.
            if ((c & 0xc0) == 0xc0) {
                if (pos + 1 >= len) return 0;
                if (end_pos == 0) end_pos = pos + 1;
                pos = id_pos + ((c & 0x3f) << 8) + packet[pos+1];
                next = pos;
            } else {
                name_len++;
                pos++;
                next = next + c + 1; 
            }
        } else {
            if (c >= '!' && c <= 'z' && c != '\\') name_len++;
            else name_len += 4;
            pos++;
        }
    }
    if (end_pos == 0) end_pos = pos;

    // Due to the nature of DNS name compression, it's possible to get a
    // name that is infinitely long. Return an error in that case.
    // We use the len of the packet as the limit, because it shouldn't 
    // be possible for the name to be that long.
    if (steps >= 2*len || pos >= len) return NULL;

    name_len++;

    name = (char *)malloc(sizeof(char) * name_len);
    pos = *packet_p;

    //Now actually assemble the name.
    //We've already made sure that we don't exceed the packet length, so
    // we don't need to make those checks anymore.
    // Non-printable and whitespace characters are replaced with a question
    // mark. They shouldn't be allowed under any circumstances anyway.
    // Other non-allowed characters are kept as is, as they appear sometimes
    // regardless.
    // This shouldn't interfere with IDNA (international
    // domain names), as those are ascii encoded.
    next = pos;
    i = 0;
    while (next != pos || packet[pos] != 0) {
        if (pos == next) {
            if ((packet[pos] & 0xc0) == 0xc0) {
                pos = id_pos + ((packet[pos] & 0x3f) << 8) + packet[pos+1];
                next = pos;
            } else {
                // Add a period except for the first time.
                if (i != 0) name[i++] = '.';
                next = pos + packet[pos] + 1;
                pos++;
            }
        } else {
            uint8_t c = packet[pos];
            if (c >= '!' && c <= '~' && c != '\\') {
                name[i] = packet[pos];
                i++; pos++;
            } else {
                name[i] = '\\';
                name[i+1] = 'x';
                name[i+2] = c/16 + 0x30;
                name[i+3] = c%16 + 0x30;
                if (name[i+2] > 0x39) name[i+2] += 0x27;
                if (name[i+3] > 0x39) name[i+3] += 0x27;
                i+=4; 
                pos++;
            }
        }
    }
    name[i] = 0;
    // return updated "next record" offset to caller
    *packet_p = end_pos + 1;

    return name;
}
#endif //USING_STRUTILS

void print_like_tshark (struct packet_data *pk) {
	char* dns_qname = "";
	char* dns_a = "";
	int free_dns_a = 0;
	// Mimic what tshark does for its display filter field "frame.time_delta_displayed".
	// This is the time delta between the current displayed packet and the previous displayed
	// packet. Fortunately, every packet we see here is a "displayed packet", so we don't have
	// to expend a lot of logic on that question.
	static double previous_pkttime = 0.0;
	double time_delta;
	if (previous_pkttime == 0.0) {
	// first time through, time delta from previous packet is 0.
	time_delta = 0.0;
	} else {
	time_delta = pk->pkttime - previous_pkttime;
	}
	previous_pkttime = pk->pkttime;

	if (pk->dns_query != (dns_question*) 0) {
	  dns_qname = pk->dns_query->name;
	}
	// Assume we got more than one Answer record. Search the linked list
	// until we find a Type 1 (IPv4 address) answer, and use that data
	// as "dns.a".
	// tshark returns a comma-separated string all the Type 1
	// values, so we will do that, too.
	if (pk->dns_response != (dns_rr*) 0) {
	  dns_rr* next_rr = pk->dns_response;
	  char* buffer = NULL;
	  char* prev_buffer = NULL;
	  int buflen = 0;
	  int is_first_value = 1;
	  do {
	    if (next_rr->type == 1) {
		buflen += strlen(next_rr->data) + 1;
		if (!is_first_value) buflen++; //comma before
		buffer = malloc(buflen);
		if (is_first_value){
		  sprintf(buffer, "%s", next_rr->data);
		  prev_buffer = buffer;
		  is_first_value = 0;
		} else {
		  sprintf(buffer,"%s,%s",prev_buffer, next_rr->data);
		  free(prev_buffer);
		  prev_buffer = buffer;
		}
	    }
	    next_rr = next_rr->next;
	  } while (next_rr != 0);
	  if (buffer != NULL) {
	    // TODO - don't forget to free this after use.
	    free_dns_a = 1;
	    dns_a = buffer;
	  }
	}

#ifdef TRACE_EXECUTION
	SAYF 
        ("TSHARK:frame time %.9f, time delta %.9f, framelen %d, ipprotocol %d, TCP flags |%#.0x|, TCP sport |%.0d|, TCP dport |%.0d|, UDP sport |%.0d|, UDP dport |%.0d|\n",
		pk->pkttime, time_delta, pk->framelen, pk->ipproto, pk->tcp_flags, pk->sport, pk->dport, pk->udp_sport, pk->udp_dport);
	// IPv4 addresses are already in printable form in the struct packet_data.
	SAYF ("TSHARK:srcip %d.%d.%d.%d, dstip %d.%d.%d.%d\n",
		pk->src[0], pk->src[1], pk->src[2], pk->src[3],
		pk->dst[0], pk->dst[1], pk->dst[2], pk->dst[3]);

	SAYF ("TSHARK:dst MAC %02x:%02x:%02x:%02x:%02x:%02x, src MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
		pk->etherdst[0],pk->etherdst[1],pk->etherdst[2],pk->etherdst[3],pk->etherdst[4],pk->etherdst[5],
		pk->ethersrc[0],pk->ethersrc[1],pk->ethersrc[2],pk->ethersrc[3],pk->ethersrc[4],pk->ethersrc[5]);
	if (pk->dns_query != (dns_question*) 0) {
	  dns_qname = pk->dns_query->name;
	}
	if (pk->dns_response != (dns_rr*) 0) {
	  if (pk->dns_response->type ==1) dns_a = pk->dns_response->data;
	}
	
	SAYF ("TSHARK:dns.id |%.0x|, dns.flags.response |%.0x|, dns.qry.name |%s|, dns.flags.rcode |%.0x|, dns.a |%s|\n",
		pk->dns_id, pk->dns_flags_response, dns_qname, pk->dns_flags_rcode, dns_a);
#else
/*
 * jfm 17 October 2017 - the tshark command we are replicating is this:
-T fields -E separator=| -e frame.time_epoch -e ip.src -e ip.dst -e udp.srcport -e udp.dstport 
 -e tcp.srcport -e tcp.dstport -e dns.flags.response -e dns.qry.name -e dns.flags.rcode 
 -e ip.proto -e dns.a -e frame.time_delta_displayed -e ip.len -e tcp.flags -e eth.src -e eth.dst 
 -e frame.len -e http.request -e http.response -e http.response.code -e dns.id -e http.request.full_uri

 * Note that the order of presentation is higgledy-piggledy, and we have chosen not to collect the
 * HTTP fields in this program, so we will simply write '||' to represent those fields. I would like
 * to straighten out the order so that it's frame|Ethernet|IP|UDP|TCP|DNS|HTTP, but that requires
 * changes to the back-end collector software and is out of scope for the present task.
 * 
 * Incidentally, I just noticed I don't print IP length (pk->iplen) above. Oh, well, it was just
 *  for debugging anyway.
 */
//#define LABEL_TSHARK_OUTPUT
#ifdef LABEL_TSHARK_OUTPUT
	// Print it with the fields labeled so we can see our mistakes. Remove the labels for test/production.
	SAYF("TSHARK:|frame time %.9f|srcip %d.%d.%d.%d|dstip %d.%d.%d.%d|UDP sport |%.0d|UDP dport |%.0d|"
		"TCP sport |%.0d|TCP dport |%.0d|dns.flags.response |%x|dns.qry.name |%s|dns.flags.rcode |%x|"
		"ipprotocol %d|dns.a |%s|time delta %.9f|IP length %d|TCP flags |%#.0x|"
		"src MAC %02x:%02x:%02x:%02x:%02x:%02x|dst MAC %02x:%02x:%02x:%02x:%02x:%02x|"
		"framelen %d|http.request|http.response|http.response.code|dns.id |%.0x|fulluri|\n",
		pk->pkttime, pk->src[0], pk->src[1], pk->src[2], pk->src[3],
		pk->dst[0], pk->dst[1], pk->dst[2], pk->dst[3],
		pk->udp_sport, pk->udp_dport, pk->sport, pk->dport,
		pk->dns_flags_response, dns_qname, pk->dns_flags_rcode, pk->ipproto, dns_a,
		time_delta, pk->iplen, pk->tcp_flags,
		pk->ethersrc[0],pk->ethersrc[1],pk->ethersrc[2],pk->ethersrc[3],pk->ethersrc[4],pk->ethersrc[5],
		pk->etherdst[0],pk->etherdst[1],pk->etherdst[2],pk->etherdst[3],pk->etherdst[4],pk->etherdst[5],
		pk->framelen, pk->dns_id);
#else
	SAYF("TSHARK:|%.9f|%d.%d.%d.%d|%d.%d.%d.%d|%.0d|%.0d|"
		"%.0d|%.0d|%x|%s|%x|"
		"%d|%s|%.9f|%d|%#.0x|"
		"%02x:%02x:%02x:%02x:%02x:%02x|%02x:%02x:%02x:%02x:%02x:%02x|"
		"%d||||%.0x||\n",
		pk->pkttime, pk->src[0], pk->src[1], pk->src[2], pk->src[3],
		pk->dst[0], pk->dst[1], pk->dst[2], pk->dst[3],
		pk->udp_sport, pk->udp_dport, pk->sport, pk->dport,
		pk->dns_flags_response, dns_qname, pk->dns_flags_rcode, pk->ipproto, dns_a,
		time_delta, pk->iplen, pk->tcp_flags,
		pk->ethersrc[0],pk->ethersrc[1],pk->ethersrc[2],pk->ethersrc[3],pk->ethersrc[4],pk->ethersrc[5],
		pk->etherdst[0],pk->etherdst[1],pk->etherdst[2],pk->etherdst[3],pk->etherdst[4],pk->etherdst[5],
		pk->framelen, pk->dns_id);
#endif //LABEL_TSHARK_OUTPUT

#endif //TRACE_EXECUTION defined/not defined
	if (pk->dns_query != (dns_question*) 0) {
		dns_question_free(pk->dns_query);
	}
	if (pk->dns_response != (dns_rr*) 0) {
		dns_rr_free(pk->dns_response);
	}
	if (free_dns_a) {
		free(dns_a);
	}
}

/* Calculate hash bucket for packet_flow. Keep the hash symmetrical: switching
   source and dest should have no effect. */

static u32 get_flow_bucket(struct packet_data* pk) {

  u32 bucket;

  if (pk->ip_ver == IP_VER4) {
    bucket = hash32(pk->src, 4, hash_seed) ^ hash32(pk->dst, 4, hash_seed);
  } else {
    bucket = hash32(pk->src, 16, hash_seed) ^ hash32(pk->dst, 16, hash_seed);
  }

  bucket ^= hash32(&pk->sport, 2, hash_seed) ^ hash32(&pk->dport, 2, hash_seed);

  return bucket % FLOW_BUCKETS;

}


/* Calculate hash bucket for host_data. */

static u32 get_host_bucket(u8* addr, u8 ip_ver) {

  u32 bucket;

  bucket = hash32(addr, (ip_ver == IP_VER4) ? 4 : 16, hash_seed);

  return bucket % HOST_BUCKETS;

}


/* Look up host data. */

struct host_data* lookup_host(u8* addr, u8 ip_ver) {

  u32 bucket = get_host_bucket(addr, ip_ver);
  struct host_data* h = host_b[bucket];

  while (CP(h)) {

    if (ip_ver == h->ip_ver &&
        !memcmp(addr, h->addr, (h->ip_ver == IP_VER4) ? 4 : 16))
      return h;

    h = h->next;

  }

  return NULL;

}


/* Destroy host data. */

static void destroy_host(struct host_data* h) {

  u32 bucket; 

  bucket = get_host_bucket(CP(h)->addr, h->ip_ver);

  if (h->use_cnt) FATAL("Attempt to destroy used host data.");

  DEBUG("[#] Destroying host data: %s (bucket %d)\n",
        addr_to_str(h->addr, h->ip_ver), bucket);

  /* Remove it from the bucketed linked list. */

  if (CP(h->next)) h->next->prev = h->prev;
  
  if (CP(h->prev)) h->prev->next = h->next;
  else host_b[bucket] = h->next;

  /* Remove from the by-age linked list. */

  if (CP(h->newer)) h->newer->older = h->older;
  else newest_host = h->older;

  if (CP(h->older)) h->older->newer = h->newer;
  else host_by_age = h->newer; 

  /* Free memory. */

  ck_free(h->last_syn);
  ck_free(h->last_synack);

  ck_free(h->http_resp);
  ck_free(h->http_req_os);

  ck_free(h);

  host_cnt--;

}


/* Indiscriminately kill some of the older hosts. */

static void nuke_hosts(void) {

  u32 kcnt = 1 + (host_cnt * KILL_PERCENT / 100);
  struct host_data* target = host_by_age;

  if (!read_file)
    WARN("Too many host entries, deleting %u. Use -m to adjust.", kcnt);

  nuke_flows(1);

  while (kcnt && CP(target)) {
    struct host_data* next = target->older;
    if (!target->use_cnt) { kcnt--; destroy_host(target); }
    target = next;
  }

}
  


/* Create a minimal host data. */

static struct host_data* create_host(u8* addr, u8 ip_ver) {

  u32 bucket = get_host_bucket(addr, ip_ver);
  struct host_data* nh;

  if (host_cnt > max_hosts) nuke_hosts();

  DEBUG("[#] Creating host data: %s (bucket %u)\n",
        addr_to_str(addr, ip_ver), bucket);

  nh = ck_alloc(sizeof(struct host_data));

  /* Insert into the bucketed linked list. */

  if (CP(host_b[bucket])) {
    host_b[bucket]->prev = nh;
    nh->next = host_b[bucket];
  }

  host_b[bucket] = nh;

  /* Insert into the by-age linked list. */
 
  if (CP(newest_host)) {

    newest_host->newer = nh;
    nh->older = newest_host;

  } else host_by_age = nh;

  newest_host = nh;

  /* Populate other data. */

  nh->ip_ver = ip_ver;
  memcpy(nh->addr, addr, (ip_ver == IP_VER4) ? 4 : 16);

  nh->last_seen = nh->first_seen = get_unix_time();

  nh->last_up_min     = -1;
  nh->last_class_id   = -1;
  nh->last_name_id    = -1;
  nh->http_name_id    = -1;
  nh->distance        = -1;

  host_cnt++;

  return nh;

}


/* Touch host data to make it more recent. */

static void touch_host(struct host_data* h) {

  CP(h);

  DEBUG("[#] Refreshing host data: %s\n", addr_to_str(h->addr, h->ip_ver));

  if (h != CP(newest_host)) {

    /* Remove from the the by-age linked list. */

    CP(h->newer);
    h->newer->older = h->older;

    if (CP(h->older)) h->older->newer = h->newer;
    else host_by_age = h->newer; 

    /* Re-insert in front. */

    newest_host->newer = h;
    h->older = newest_host;
    h->newer = NULL;

    newest_host = h;

    /* This wasn't the only entry on the list, so there is no
       need to update the tail (host_by_age). */

  }

  /* Update last seen time. */

  h->last_seen = get_unix_time();

}



/* Destroy a flow. */

static void destroy_flow(struct packet_flow* f) {

  CP(f);
  CP(f->client);
  CP(f->server);

  DEBUG("[#] Destroying flow: %s/%u -> ",
        addr_to_str(f->client->addr, f->client->ip_ver), f->cli_port);

  DEBUG("%s/%u (bucket %u)\n",
        addr_to_str(f->server->addr, f->server->ip_ver), f->srv_port,
        f->bucket);

  /* Remove it from the bucketed linked list. */

  if (CP(f->next)) f->next->prev = f->prev;
  
  if (CP(f->prev)) f->prev->next = f->next;
  else { CP(flow_b[f->bucket]); flow_b[f->bucket] = f->next; }

  /* Remove from the by-age linked list. */

  if (CP(f->newer)) f->newer->older = f->older;
  else { CP(newest_flow); newest_flow = f->older; }

  if (CP(f->older)) f->older->newer = f->newer;
  else flow_by_age = f->newer; 

  /* Free memory, etc. */

  f->client->use_cnt--;
  f->server->use_cnt--;

  free_sig_hdrs(&f->http_tmp);

  ck_free(f->request);
  ck_free(f->response);
  ck_free(f);

  flow_cnt--;  

}


/* Indiscriminately kill some of the oldest flows. */

static void nuke_flows(u8 silent) {

  u32 kcnt = 1 + (flow_cnt * KILL_PERCENT / 100);

  if (silent)
    DEBUG("[#] Pruning connections - trying to delete %u...\n",kcnt);
  else if (!read_file)
    WARN("Too many tracked connections, deleting %u. "
         "Use -m to adjust.", kcnt);

  while (kcnt-- && flow_by_age) destroy_flow(flow_by_age);

}



/* Create flow, and host data if necessary. If counts exceeded, prune old. */

static struct packet_flow* create_flow_from_syn(struct packet_data* pk) {

  u32 bucket = get_flow_bucket(pk);
  struct packet_flow* nf;

  if (flow_cnt > max_conn) nuke_flows(0);

  DEBUG("[#] Creating flow from SYN: %s/%u -> ",
        addr_to_str(pk->src, pk->ip_ver), pk->sport);

  DEBUG("%s/%u (bucket %u)\n",
        addr_to_str(pk->dst, pk->ip_ver), pk->dport, bucket);

  nf = ck_alloc(sizeof(struct packet_flow));

  nf->client = lookup_host(pk->src, pk->ip_ver);

  if (nf->client) touch_host(nf->client);
  else nf->client = create_host(pk->src, pk->ip_ver);

  nf->server = lookup_host(pk->dst, pk->ip_ver);

  if (nf->server) touch_host(nf->server);
  else nf->server = create_host(pk->dst, pk->ip_ver);

  nf->client->use_cnt++;
  nf->server->use_cnt++;

  nf->client->total_conn++;
  nf->server->total_conn++;

  /* Insert into the bucketed linked list.*/

  if (CP(flow_b[bucket])) {
    flow_b[bucket]->prev = nf;
    nf->next = flow_b[bucket];
  }

  flow_b[bucket] = nf;

  /* Insert into the by-age linked list */
 
  if (CP(newest_flow)) {
    newest_flow->newer = nf;
    nf->older = newest_flow;
  } else flow_by_age = nf;

  newest_flow = nf;

  /* Populate other data */

  nf->cli_port = pk->sport;
  nf->srv_port = pk->dport;
  nf->bucket   = bucket;
  nf->created  = get_unix_time();

  nf->next_cli_seq = pk->seq + 1;

  flow_cnt++;
  return nf;

}


/* Look up an existing flow. */

static struct packet_flow* lookup_flow(struct packet_data* pk, u8* to_srv) {

  u32 bucket = get_flow_bucket(pk);
  struct packet_flow* f = flow_b[bucket];

  while (CP(f)) {

    CP(f->client);
    CP(f->server);

    if (pk->ip_ver != f->client->ip_ver) goto lookup_next;

    if (pk->sport == f->cli_port && pk->dport == f->srv_port &&
        !memcmp(pk->src, f->client->addr, (pk->ip_ver == IP_VER4) ? 4 : 16) &&
        !memcmp(pk->dst, f->server->addr, (pk->ip_ver == IP_VER4) ? 4 : 16)) {

      *to_srv = 1;
      return f;

    }

    if (pk->dport == f->cli_port && pk->sport == f->srv_port &&
        !memcmp(pk->dst, f->client->addr, (pk->ip_ver == IP_VER4) ? 4 : 16) &&
        !memcmp(pk->src, f->server->addr, (pk->ip_ver == IP_VER4) ? 4 : 16)) {

      *to_srv = 0;
      return f;

    }

lookup_next:

    f = f->next;

  }

  return NULL;

}


/* Go through host and flow cache, expire outdated items. */

static void expire_cache(void) {
  struct host_data* target;
  static u32 pt;

  u32 ct = get_unix_time();

  if (ct == pt) return;
  pt = ct;

  DEBUG("[#] Cache expiration kicks in...\n");

  while (CP(flow_by_age) && ct - flow_by_age->created > conn_max_age)
    destroy_flow(flow_by_age);

  target = host_by_age;

  while (CP(target) && ct - target->last_seen > host_idle_limit * 60) {
    struct host_data* newer = target->newer;
    if (!target->use_cnt) destroy_host(target);
    target = newer;
  }

}


/* Insert data from a packet into a flow, call handlers as appropriate. */

static void flow_dispatch(struct packet_data* pk) {

  struct packet_flow* f;
  struct tcp_sig* tsig;
  u8 to_srv = 0;
  u8 need_more = 0;

  DEBUG("[#] Received TCP packet: %s/%u -> ",
        addr_to_str(pk->src, pk->ip_ver), pk->sport);

  DEBUG("%s/%u (type 0x%02x, pay_len = %u)\n",
        addr_to_str(pk->dst, pk->ip_ver), pk->dport, pk->tcp_type,
        pk->pay_len);
    
  f = lookup_flow(pk, &to_srv);

  switch (pk->tcp_type) {

    case TCP_SYN:

      if (f) {

        /* Perhaps just a simple dupe? */
        if (to_srv && f->next_cli_seq - 1 == pk->seq) return;

        DEBUG("[#] New SYN for an existing flow, resetting.\n");
        destroy_flow(f);

      }

      f = create_flow_from_syn(pk);

      tsig = fingerprint_tcp(1, pk, f);

      /* We don't want to do any further processing on generic non-OS
         signatures (e.g. NMap). The easiest way to guarantee that is to 
         kill the flow. */

      if (!tsig && !f->sendsyn) {

        destroy_flow(f);
        return;

      }

      fingerprint_mtu(1, pk, f);
      check_ts_tcp(1, pk, f);

      if (tsig) {

        /* This can't be done in fingerprint_tcp because check_ts_tcp()
           depends on having original SYN / SYN+ACK data. */
 
        ck_free(f->client->last_syn);
        f->client->last_syn = tsig;

      }

      break;

    case TCP_SYN | TCP_ACK:

      if (!f) {

        DEBUG("[#] Stray SYN+ACK with no flow.\n");
        return;

      }

      /* This is about as far as we want to go with p0f-sendsyn. */

      if (f->sendsyn) {

        fingerprint_tcp(0, pk, f);
        destroy_flow(f);
        return;

      }


      if (to_srv) {

        DEBUG("[#] SYN+ACK from client to server, trippy.\n");
        return;

      }

      if (f->acked) {

        if (f->next_srv_seq - 1 != pk->seq)
          DEBUG("[#] Repeated but non-identical SYN+ACK (0x%08x != 0x%08x).\n",
                f->next_srv_seq - 1, pk->seq);

        return;

      }

      f->acked = 1;

      tsig = fingerprint_tcp(0, pk, f);

      /* SYN from real OS, SYN+ACK from a client stack. Weird, but whatever. */

      if (!tsig) {

        destroy_flow(f);
        return;

      }

      fingerprint_mtu(0, pk, f);
      check_ts_tcp(0, pk, f);

      ck_free(f->server->last_synack);
      f->server->last_synack = tsig;

      f->next_srv_seq = pk->seq + 1;

      break;

    case TCP_RST | TCP_ACK:
    case TCP_RST:
    case TCP_FIN | TCP_ACK:
    case TCP_FIN:

       if (f) {

         check_ts_tcp(to_srv, pk, f);
         destroy_flow(f);

       }

       break;

    case TCP_ACK:

      if (!f) return;

      /* Stop there, you criminal scum! */

      if (f->sendsyn) {
        destroy_flow(f);
        return;
      }

      if (!f->acked) {

        DEBUG("[#] Never received SYN+ACK to complete handshake, huh.\n");
        destroy_flow(f);
        return;

      }

      if (to_srv) {

        /* We don't do stream reassembly, so if something arrives out of order,
           we won't catch it. Oh well. */

        if (f->next_cli_seq != pk->seq) {

          /* Not a simple dupe? */

          if (f->next_cli_seq - pk->pay_len != pk->seq)
            DEBUG("[#] Expected client seq 0x%08x, got 0x%08x.\n", f->next_cli_seq, pk->seq);
 
          return;
        }

        /* Append data */

        if (f->req_len < MAX_FLOW_DATA && pk->pay_len) {

          u32 read_amt = MIN(pk->pay_len, MAX_FLOW_DATA - f->req_len);

          f->request = ck_realloc_kb(f->request, f->req_len + read_amt + 1);
          memcpy(f->request + f->req_len, pk->payload, read_amt);
          f->req_len += read_amt;

        }

        check_ts_tcp(1, pk, f);

        f->next_cli_seq += pk->pay_len;

      } else {

        if (f->next_srv_seq != pk->seq) {

          /* Not a simple dupe? */

          if (f->next_srv_seq - pk->pay_len != pk->seq)
            DEBUG("[#] Expected server seq 0x%08x, got 0x%08x.\n",
                  f->next_cli_seq, pk->seq);
 
          return;

        }

        /* Append data */

        if (f->resp_len < MAX_FLOW_DATA && pk->pay_len) {

          u32 read_amt = MIN(pk->pay_len, MAX_FLOW_DATA - f->resp_len);

          f->response = ck_realloc_kb(f->response, f->resp_len + read_amt + 1);
          memcpy(f->response + f->resp_len, pk->payload, read_amt);
          f->resp_len += read_amt;

        }

        check_ts_tcp(0, pk, f);

        f->next_srv_seq += pk->pay_len;

      }

      if (!pk->pay_len) return;

      need_more |= process_http(to_srv, f);

      if (!need_more) {

        DEBUG("[#] All modules done, no need to keep tracking flow.\n");
        destroy_flow(f);

      } else if (f->req_len >= MAX_FLOW_DATA && f->resp_len >= MAX_FLOW_DATA) {

        DEBUG("[#] Per-flow capture size limit exceeded.\n");
        destroy_flow(f);

      }

      break;

    default:

      WARN("Huh. Unexpected packet type 0x%02x in flow_dispatch().", pk->tcp_type);

  }

}


/* Add NAT score, check if alarm due. */

void add_nat_score(u8 to_srv, struct packet_flow* f, u16 reason, u8 score) {

  static u8 rea[1024];

  struct host_data* hd;
  u8 *scores, *rptr = rea;
  u32 i;
  u8  over_5 = 0, over_2 = 0, over_1 = 0, over_0 = 0;

  if (to_srv) {

    hd = f->client;
    scores = hd->cli_scores;

  } else {

    hd = f->server;
    scores = hd->srv_scores;

  }

  memmove(scores, scores + 1, NAT_SCORES - 1);
  scores[NAT_SCORES - 1] = score;
  hd->nat_reasons |= reason;

  if (!score) return;

  for (i = 0; i < NAT_SCORES; i++) switch (scores[i]) {
    case 6 ... 255: over_5++;
    case 3 ... 5:   over_2++;
    case 2:         over_1++;
    case 1:         over_0++;
  }

  if (over_5 > 2 || over_2 > 4 || over_1 > 6 || over_0 > 8) {

    start_observation("ip sharing", 2, to_srv, f);

    reason = hd->nat_reasons;

    hd->last_nat = get_unix_time();

    memset(scores, 0, NAT_SCORES);
    hd->nat_reasons = 0;

  } else {

    /* Wait for something more substantial. */
    if (score == 1) return;

    start_observation("host change", 2, to_srv, f);

    hd->last_chg = get_unix_time();

  }

  *rptr = 0;

#define REAF(_par...) do { \
    rptr += sprintf((char*)rptr, _par); \
  } while (0) 

  if (reason & NAT_APP_SIG)  REAF(" app_vs_os");
  if (reason & NAT_OS_SIG)   REAF(" os_diff");
  if (reason & NAT_UNK_DIFF) REAF(" sig_diff");
  if (reason & NAT_TO_UNK)   REAF(" x_known");
  if (reason & NAT_TS)       REAF(" tstamp");
  if (reason & NAT_TTL)      REAF(" ttl");
  if (reason & NAT_PORT)     REAF(" port");
  if (reason & NAT_MSS)      REAF(" mtu");
  if (reason & NAT_FUZZY)    REAF(" fuzzy");

  if (reason & NAT_APP_VIA)  REAF(" via");
  if (reason & NAT_APP_DATE) REAF(" date");
  if (reason & NAT_APP_LB)   REAF(" srv_sig_lb");
  if (reason & NAT_APP_UA)   REAF(" ua_vs_os");

#undef REAF

  add_observation_field("reason", rea[0] ? (rea + 1) : NULL);

  OBSERVF("raw_hits", "%u,%u,%u,%u", over_5, over_2, over_1, over_0);

}


/* Verify if tool class (called from modules). */

void verify_tool_class(u8 to_srv, struct packet_flow* f, u32* sys, u32 sys_cnt) {

  struct host_data* hd;
  u32 i;

  if (to_srv) hd = f->client; else hd = f->server;

  CP(sys);

  /* No existing data; although there is perhaps some value in detecting
     app-only conflicts in absence of other info, it's probably OK to just
     wait until more data becomes available. */

  if (hd->last_class_id == -1) return;

  for (i = 0; i < sys_cnt; i++)

    if ((sys[i] & SYS_CLASS_FLAG)) {

      if (SYS_NF(sys[i]) == hd->last_class_id) break;

    } else {

      if (SYS_NF(sys[i]) == hd->last_name_id) break;

    }

  /* Oops, a mismatch. */

  if (i == sys_cnt) {

    DEBUG("[#] Detected app not supposed to run on host OS.\n");
    add_nat_score(to_srv, f, NAT_APP_SIG, 4);

  } else {

    DEBUG("[#] Detected app supported on host OS.\n");
    add_nat_score(to_srv, f, 0, 0);

  }

}


/* Clean up everything. */

void destroy_all_hosts(void) {

  while (flow_by_age) destroy_flow(flow_by_age);
  while (host_by_age) destroy_host(host_by_age);

}
