#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "e1000_dev.h"
#include "net.h"

#define TX_RING_SIZE 16
static struct tx_desc tx_ring[TX_RING_SIZE] __attribute__((aligned(16)));
static void *tx_mbufs[TX_RING_SIZE]; // 使用 void* (char*) 而非 struct mbuf*

#define RX_RING_SIZE 16
static struct rx_desc rx_ring[RX_RING_SIZE] __attribute__((aligned(16)));
static void *rx_mbufs[RX_RING_SIZE]; // 使用 void* (char*) 而非 struct mbuf*

// 如果头文件中没有定义接收中断标志，手动定义它
#ifndef E1000_IMS_RXT0
#define E1000_IMS_RXT0 0x80
#endif

// remember where the e1000 is, to access its registers.
volatile uint32 *regs;

struct spinlock e1000_lock;

// called by pci_init().
// xregs is the memory address at which the
// e1000's registers are mapped.
void
e1000_init(uint32 *xregs)
{
  int i;
  initlock(&e1000_lock, "e1000");

  regs = xregs;

  // Reset the device
  regs[E1000_IMS] = 0; // disable interrupts
  regs[E1000_CTL] |= E1000_CTL_RST;
  regs[E1000_IMS] = 0; // redisable interrupts
  __sync_synchronize();

  // 初始化发送环
  for(i = 0; i < TX_RING_SIZE; i++) {
    tx_ring[i].status = E1000_TXD_STAT_DD;
    tx_mbufs[i] = 0;
  }
  regs[E1000_TDBAL] = (uint64) tx_ring;
  if(sizeof(tx_ring) % 128 != 0)
    panic("e1000");
  regs[E1000_TDLEN] = sizeof(tx_ring);
  regs[E1000_TDH] = regs[E1000_TDT] = 0;
  
  // 初始化接收环
  for(i = 0; i < RX_RING_SIZE; i++) {
    // 使用 kalloc 分配 4KB 页面作为接收缓冲区
    rx_mbufs[i] = kalloc();
    if (!rx_mbufs[i])
      panic("e1000");
    rx_ring[i].addr = (uint64) rx_mbufs[i];
    rx_ring[i].status = 0;
  }
  regs[E1000_RDBAL] = (uint64) rx_ring;
  if(sizeof(rx_ring) % 128 != 0)
    panic("e1000");
  regs[E1000_RDLEN] = sizeof(rx_ring);
  regs[E1000_RDH] = 0;
  regs[E1000_RDT] = RX_RING_SIZE - 1;
  regs[E1000_MTA] = 0;

  // 配置控制寄存器
  // 修正：移除了可能导致编译错误的 CT/COLD 宏调用，使用基本启用标志
  regs[E1000_TCTL] = E1000_TCTL_EN | E1000_TCTL_PSP;
  regs[E1000_RCTL] = E1000_RCTL_EN | E1000_RCTL_BAM | E1000_RCTL_SZ_2048 | E1000_RCTL_SECRC;
  
  // 启用接收中断
  regs[E1000_IMS] = E1000_IMS_RXT0;
}

// 修改后的函数签名：接收 char *buf 和 int len
int
e1000_transmit(char *buf, int len)
{
  acquire(&e1000_lock);

  uint32 idx = regs[E1000_TDT];

  // 检查当前描述符是否可用 (E1000_TXD_STAT_DD 设置为 1 表示网卡已处理完)
  if((tx_ring[idx].status & E1000_TXD_STAT_DD) == 0){
    release(&e1000_lock);
    return -1;
  }

  // 释放该位置上一次使用的缓冲区
  if(tx_mbufs[idx]){
    kfree(tx_mbufs[idx]);
    tx_mbufs[idx] = 0;
  }

  // 记录新的缓冲区指针，以便将来释放
  tx_mbufs[idx] = buf;
  
  // 填充描述符
  tx_ring[idx].addr = (uint64)buf;
  tx_ring[idx].length = len;
  tx_ring[idx].cmd = E1000_TXD_CMD_EOP | E1000_TXD_CMD_RS;

  // 更新尾部指针
  regs[E1000_TDT] = (idx + 1) % TX_RING_SIZE;

  release(&e1000_lock);
  return 0;
}

static void
e1000_recv(void)
{
  // 接收数据包
  // 检查 E1000_RDT + 1 位置
  acquire(&e1000_lock);
  
  uint32 idx = (regs[E1000_RDT] + 1) % RX_RING_SIZE;

  while(1) {
    // 检查是否有新包到达 (DD 标志位)
    if((rx_ring[idx].status & E1000_RXD_STAT_DD) == 0){
      break;
    }

    // 获取缓冲区指针
    void *buf = rx_mbufs[idx];
    
    // 将数据包传递给网络层 net_rx
    // 注意：根据你的环境，net_rx 可能需要 char* 和 int
    release(&e1000_lock);
    net_rx((char*)buf, rx_ring[idx].length);
    acquire(&e1000_lock);

    // 因为旧缓冲区已经交给 net_rx (可能被上层协议栈使用或释放)，
    // 我们必须分配一个新的空白缓冲区给网卡使用
    void *new_buf = kalloc();
    if(!new_buf){
      // 如果内存不足，无法补充接收环，停止处理
      break; 
    }

    // 将新缓冲区挂载到接收环
    rx_mbufs[idx] = new_buf;
    rx_ring[idx].addr = (uint64)new_buf;
    rx_ring[idx].status = 0; // 清除状态位

    // 更新 RDT 指针，告诉网卡这个位置可以用了
    regs[E1000_RDT] = idx;

    // 移动到下一个位置
    idx = (idx + 1) % RX_RING_SIZE;
  }

  release(&e1000_lock);
}

void
e1000_intr(void)
{
  // 告诉网卡我们处理了中断
  regs[E1000_ICR] = 0xffffffff;

  e1000_recv();
}
