#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"
#include "net.h"

// xv6's ethernet and IP addresses
static uint8 local_mac[ETHADDR_LEN] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
static uint32 local_ip = MAKE_IP_ADDR(10, 0, 2, 15);

// qemu host's ethernet address.
static uint8 host_mac[ETHADDR_LEN] = { 0x52, 0x55, 0x0a, 0x00, 0x02, 0x02 };

static struct spinlock netlock;

// UDP Socket Implementation Structures
#define NSOCK 16

struct rx_entry {
  char *buf;              // The raw packet buffer
  int len;                // Length of the buffer
  struct rx_entry *next;  // Next packet in the queue
};

struct sock {
  int port;               // Local port (0 if unused)
  struct spinlock lock;   // Protects the rx queue
  struct rx_entry *rx_head; // Queue head
  struct rx_entry *rx_tail; // Queue tail
};

static struct sock sockets[NSOCK];

void
netinit(void)
{
  initlock(&netlock, "netlock");
  for(int i = 0; i < NSOCK; i++) {
    initlock(&sockets[i].lock, "sock");
    sockets[i].port = 0;
    sockets[i].rx_head = 0;
    sockets[i].rx_tail = 0;
  }
}

//
// bind(int port)
// prepare to receive UDP packets address to the port,
// i.e. allocate any queues &c needed.
//
uint64
sys_bind(void)
{
  int port;
  argint(0, &port); // Changed: removed return value check

  acquire(&netlock);
  // Check if port is already bound
  for(int i = 0; i < NSOCK; i++) {
    if(sockets[i].port == port) {
      release(&netlock);
      return -1;
    }
  }

  // Find a free socket slot
  for(int i = 0; i < NSOCK; i++) {
    if(sockets[i].port == 0) {
      sockets[i].port = port;
      sockets[i].rx_head = 0;
      sockets[i].rx_tail = 0;
      release(&netlock);
      return 0;
    }
  }
  release(&netlock);
  return -1;
}

//
// unbind(int port)
// release any resources previously created by bind(port);
// from now on UDP packets addressed to port should be dropped.
//
uint64
sys_unbind(void)
{
  int port;
  argint(0, &port); // Changed: removed return value check

  acquire(&netlock);
  for(int i = 0; i < NSOCK; i++) {
    if(sockets[i].port == port) {
      acquire(&sockets[i].lock);
      sockets[i].port = 0; // Mark as free

      // Free any pending packets in the queue
      struct rx_entry *e = sockets[i].rx_head;
      while(e) {
        struct rx_entry *next = e->next;
        kfree(e->buf);
        kfree((char*)e);
        e = next;
      }
      sockets[i].rx_head = 0;
      sockets[i].rx_tail = 0;
      
      release(&sockets[i].lock);
      release(&netlock);
      return 0;
    }
  }
  release(&netlock);
  return 0;
}

//
// recv(int dport, int *src, short *sport, char *buf, int maxlen)
// if there's a received UDP packet already queued that was
// addressed to dport, then return it.
// otherwise wait for such a packet.
//
// sets *src to the IP source address.
// sets *sport to the UDP source port.
// copies up to maxlen bytes of UDP payload to buf.
// returns the number of bytes copied,
// and -1 if there was an error.
//
// dport, *src, and *sport are host byte order.
// bind(dport) must previously have been called.
//
uint64
sys_recv(void)
{
  int dport;
  uint64 src_ip_addr;
  uint64 src_port_addr;
  uint64 buf_addr;
  int maxlen;

  // Changed: removed return value checks as argint/argaddr return void
  argint(0, &dport);
  argaddr(1, &src_ip_addr);
  argaddr(2, &src_port_addr);
  argaddr(3, &buf_addr);
  argint(4, &maxlen);

  struct sock *s = 0;

  // Find the socket
  acquire(&netlock);
  for(int i = 0; i < NSOCK; i++) {
    if(sockets[i].port == dport) {
      s = &sockets[i];
      acquire(&s->lock); // Lock the socket before releasing global lock
      break;
    }
  }
  release(&netlock);

  if(s == 0)
    return -1;

  // Wait for packets
  while(s->rx_head == 0) {
    if(myproc()->killed) {
      release(&s->lock);
      return -1;
    }
    sleep(s, &s->lock);
  }

  // Dequeue packet
  struct rx_entry *e = s->rx_head;
  s->rx_head = e->next;
  if(s->rx_head == 0)
    s->rx_tail = 0;
  release(&s->lock);

  // Parse packet headers
  struct eth *eth = (struct eth*)e->buf;
  struct ip *ip = (struct ip*)(eth + 1);
  struct udp *udp = (struct udp*)(ip + 1);
  char *payload = (char*)(udp + 1);

  uint32 src_ip = ntohl(ip->ip_src);
  uint16 src_port = ntohs(udp->sport);
  int payload_len = ntohs(udp->ulen) - sizeof(struct udp);
  
  int copylen = (payload_len < maxlen) ? payload_len : maxlen;

  // Copy to user space
  if(copyout(myproc()->pagetable, src_ip_addr, (char*)&src_ip, sizeof(src_ip)) < 0 ||
     copyout(myproc()->pagetable, src_port_addr, (char*)&src_port, sizeof(src_port)) < 0 ||
     copyout(myproc()->pagetable, buf_addr, payload, copylen) < 0) {
       kfree(e->buf);
       kfree((char*)e);
       return -1;
  }

  // Free resources
  kfree(e->buf);
  kfree((char*)e);

  return copylen;
}

// This code is lifted from FreeBSD's ping.c, and is copyright by the Regents
// of the University of California.
static unsigned short
in_cksum(const unsigned char *addr, int len)
{
  int nleft = len;
  const unsigned short *w = (const unsigned short *)addr;
  unsigned int sum = 0;
  unsigned short answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (nleft == 1) {
    *(unsigned char *)(&answer) = *(const unsigned char *)w;
    sum += answer;
  }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum & 0xffff) + (sum >> 16);
  sum += (sum >> 16);
  /* guaranteed now that the lower 16 bits of sum are correct */

  answer = ~sum; /* truncate to 16 bits */
  return answer;
}

//
// send(int sport, int dst, int dport, char *buf, int len)
//
uint64
sys_send(void)
{
  struct proc *p = myproc();
  int sport;
  int dst;
  int dport;
  uint64 bufaddr;
  int len;

  argint(0, &sport);
  argint(1, &dst);
  argint(2, &dport);
  argaddr(3, &bufaddr);
  argint(4, &len);

  int total = len + sizeof(struct eth) + sizeof(struct ip) + sizeof(struct udp);
  if(total > PGSIZE)
    return -1;

  char *buf = kalloc();
  if(buf == 0){
    printf("sys_send: kalloc failed\n");
    return -1;
  }
  memset(buf, 0, PGSIZE);

  struct eth *eth = (struct eth *) buf;
  memmove(eth->dhost, host_mac, ETHADDR_LEN);
  memmove(eth->shost, local_mac, ETHADDR_LEN);
  eth->type = htons(ETHTYPE_IP);

  struct ip *ip = (struct ip *)(eth + 1);
  ip->ip_vhl = 0x45; // version 4, header length 4*5
  ip->ip_tos = 0;
  ip->ip_len = htons(sizeof(struct ip) + sizeof(struct udp) + len);
  ip->ip_id = 0;
  ip->ip_off = 0;
  ip->ip_ttl = 100;
  ip->ip_p = IPPROTO_UDP;
  ip->ip_src = htonl(local_ip);
  ip->ip_dst = htonl(dst);
  ip->ip_sum = in_cksum((unsigned char *)ip, sizeof(*ip));

  struct udp *udp = (struct udp *)(ip + 1);
  udp->sport = htons(sport);
  udp->dport = htons(dport);
  udp->ulen = htons(len + sizeof(struct udp));

  char *payload = (char *)(udp + 1);
  if(copyin(p->pagetable, payload, bufaddr, len) < 0){
    kfree(buf);
    printf("send: copyin failed\n");
    return -1;
  }

  e1000_transmit(buf, total);

  return 0;
}

void
ip_rx(char *buf, int len)
{
  // don't delete this printf; make grade depends on it.
  static int seen_ip = 0;
  if(seen_ip == 0)
    printf("ip_rx: received an IP packet\n");
  seen_ip = 1;

  // Check buffer length validity for IP header
  if(len < sizeof(struct eth) + sizeof(struct ip)) {
    kfree(buf);
    return;
  }

  struct ip *ip = (struct ip*)(buf + sizeof(struct eth));

  // Verify IP Checksum
  if(in_cksum((unsigned char*)ip, sizeof(struct ip)) != 0) {
    kfree(buf);
    return;
  }

  // Check if it is UDP
  if(ip->ip_p != IPPROTO_UDP) {
    kfree(buf);
    return;
  }

  // Check buffer length validity for UDP header
  if(len < sizeof(struct eth) + sizeof(struct ip) + sizeof(struct udp)) {
    kfree(buf);
    return;
  }

  struct udp *udp = (struct udp*)(ip + 1);
  uint16 dport = ntohs(udp->dport);

  // Find destination socket
  struct sock *s = 0;
  acquire(&netlock);
  for(int i = 0; i < NSOCK; i++) {
    if(sockets[i].port == dport) {
      s = &sockets[i];
      acquire(&s->lock);
      break;
    }
  }
  release(&netlock);

  // If socket found, enqueue the packet
  if(s) {
    struct rx_entry *e = (struct rx_entry*)kalloc();
    if(e == 0) {
      release(&s->lock);
      kfree(buf);
      return;
    }
    
    e->buf = buf;
    e->len = len;
    e->next = 0;

    if(s->rx_tail) {
      s->rx_tail->next = e;
    } else {
      s->rx_head = e;
    }
    s->rx_tail = e;
    
    wakeup(s); // Wake up sys_recv
    release(&s->lock);
  } else {
    // No socket bound to this port, drop packet
    kfree(buf);
  }
}

//
// send an ARP reply packet to tell qemu to map
// xv6's ip address to its ethernet address.
// this is the bare minimum needed to persuade
// qemu to send IP packets to xv6; the real ARP
// protocol is more complex.
//
void
arp_rx(char *inbuf)
{
  static int seen_arp = 0;

  if(seen_arp){
    kfree(inbuf);
    return;
  }
  printf("arp_rx: received an ARP packet\n");
  seen_arp = 1;

  struct eth *ineth = (struct eth *) inbuf;
  struct arp *inarp = (struct arp *) (ineth + 1);

  char *buf = kalloc();
  if(buf == 0)
    panic("send_arp_reply");

  struct eth *eth = (struct eth *) buf;
  memmove(eth->dhost, ineth->shost, ETHADDR_LEN); // ethernet destination = query source
  memmove(eth->shost, local_mac, ETHADDR_LEN); // ethernet source = xv6's ethernet address
  eth->type = htons(ETHTYPE_ARP);

  struct arp *arp = (struct arp *)(eth + 1);
  arp->hrd = htons(ARP_HRD_ETHER);
  arp->pro = htons(ETHTYPE_IP);
  arp->hln = ETHADDR_LEN;
  arp->pln = sizeof(uint32);
  arp->op = htons(ARP_OP_REPLY);

  memmove(arp->sha, local_mac, ETHADDR_LEN);
  arp->sip = htonl(local_ip);
  memmove(arp->tha, ineth->shost, ETHADDR_LEN);
  arp->tip = inarp->sip;

  e1000_transmit(buf, sizeof(*eth) + sizeof(*arp));

  kfree(inbuf);
}

void
net_rx(char *buf, int len)
{
  struct eth *eth = (struct eth *) buf;

  if(len >= sizeof(struct eth) + sizeof(struct arp) &&
     ntohs(eth->type) == ETHTYPE_ARP){
    arp_rx(buf);
  } else if(len >= sizeof(struct eth) + sizeof(struct ip) &&
     ntohs(eth->type) == ETHTYPE_IP){
    ip_rx(buf, len);
  } else {
    kfree(buf);
  }
}
