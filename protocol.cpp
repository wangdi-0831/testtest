#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <bitset>
using namespace std;

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  //Total Length 大于 len 时, 不合法
  if((packet[2] << 8) + packet[3] > len)
    return false;
  //Command 是否为 1 或 2
  if(packet[28] !=1 && packet[28] != 2)
    return false;
  //Version 是否为 2
  if(packet[29] != 2 )
    return false;
  //Zero 是否为 0
  if(packet[30]|packet[31])
    return false;
  //计算IP包个数
  output->numEntries = ((packet[2] << 8) + packet[3] - 32)/20;
  //检查每个IP中的内容
  for(int i = 0; i<output->numEntries;i++){
    //Family 和 Command 是否有正确的对应关系
    uint32_t family = (packet[32+20*i]<<8)+packet[33+20*i];
    if((packet[28] == 1 && family != 0)|(packet[28] == 2 && family != 2))
      return false;
    //Tag 是否为 0
    if(packet[34+20*i]|packet[35+20*i])
      return false;
    //Mask 的二进制是不是连续的 1 与连续的 0 组成
    uint32_t mask = (packet[40 + 20*i]<<24)+(packet[41 + 20*i]<<16)+(packet[42 + 20*i]<<8)+packet[43 + 20*i];
    uint32_t judge_mask = (mask-1)|mask;
    if(judge_mask != 0xffffffff)
      return false;
    //Metric 转换成小端序后是否在 [1,16] 的区间内
    uint32_t metric = (packet[48 + 20*i]<<24)+(packet[49 + 20*i]<<16)+(packet[50 + 20*i]<<8)+packet[51 + 20*i];
    if(metric<1|metric>16)
      return false;
    //写入output
    output->command = packet[28];
    output->entries[i].addr = (packet[39 + 20*i]<<24)+(packet[38 + 20*i]<<16)+(packet[37 + 20*i]<<8)+packet[36 + 20*i] ;    
    output->entries[i].mask = htonl(mask);
    output->entries[i].nexthop = (packet[47 + 20*i]<<24)+(packet[46 + 20*i]<<16)+(packet[45 + 20*i]<<8)+packet[44 + 20*i];
    output->entries[i].metric = htonl(metric);
    }
    return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  //command
  buffer[0] = rip->command;
  //version
  buffer[1] = 2;
  //zero
  buffer[2] = buffer[3] = 0;
  uint32_t count = rip->numEntries;
  for(int i = 0; i < count; i++){
    //family
    buffer[4+20*i] = 0;
    if(rip->command == 1)
      buffer[5 + 20*i] = 0;
    else
      buffer[5 + 20*i] = 2;
    //tag
    buffer[6 + 20*i] = buffer[7 + 20*i] = 0;
    //addr
    uint32_t addr_temp = rip->entries[i].addr;
    buffer[8+20*i] = addr_temp&0xff;
    buffer[9+20*i] = addr_temp>>8&0xff;
    buffer[10+20*i] = addr_temp>>16&0xff;
    buffer[11+20*i] = addr_temp>>24;
    //mask
    uint32_t mask_temp = rip->entries[i].mask;
    buffer[12+20*i] = mask_temp&0xff;
    buffer[13+20*i] = mask_temp>>8&0xff;
    buffer[14+20*i] = mask_temp>>16&0xff;
    buffer[15+20*i] = mask_temp>>24;
    //hop
    uint32_t hop_temp = rip->entries[i].nexthop;
    buffer[16+20*i] = hop_temp&0xff;
    buffer[17+20*i] = hop_temp>>8&0xff;
    buffer[18+20*i] = hop_temp>>16&0xff;
    buffer[19+20*i] = hop_temp>>24;
    //metric
    uint32_t metric_temp = rip->entries[i].metric;
    buffer[20+20*i] = metric_temp&0xff;
    buffer[21+20*i] = metric_temp>>8&0xff;
    buffer[22+20*i] = metric_temp>>16&0xff;
    buffer[23+20*i] = metric_temp>>24;
  }
  return 4 + 20*count;
}
