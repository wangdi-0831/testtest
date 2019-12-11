#include <stdint.h>
#include <stdlib.h>

bool validateIPChecksum(uint8_t *packet, size_t len) {
  //存一下，最后用
  uint8_t *packet1 = packet;
  //返回值,初始化为false
  bool isVaild = false;
  //计算长度
  int header_len = 4 * (packet[0]%16);//前一半：Version...后一半：length...
  //记录正确校验和sum
  uint16_t sum = (packet[10] << 8) + packet[11];
  //将分组头中的校验和区域填充为 0
  packet[10] = 0;  
  packet[11] = 0;
  //求校验和
  uint32_t checksum = 0;  
  uint16_t hi;
  for(int i = 0; i < header_len; i = i+2) {
    checksum = checksum + packet[i+1] + (packet[i] << 8);//将所有 16 比特整数相加
    hi = checksum>>16;
    while(hi) {//如果和发生溢出，循环操作直到不溢出
      checksum = (checksum << 16) >> 16;//截取低位
      checksum = checksum + hi;  //将溢出部分加到低 16 比特
      hi = checksum>>16;
    }
  }
//按位取反
checksum = ((~checksum)<<16)>>16;
//复原packet
packet =packet1;
//与旧检验和比较并返回
return checksum==sum?true:false;
}

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  if(!validateIPChecksum(packet, len)) return false;
  //更新Time to Live
  packet[8] = packet[8] - 1;
  //记一下，之后用
  // uint8_t *packet1 = packet;
  //计算新校验和
  int header_len = 4 * (packet[0]%16);//前一半：Version...后一半：length...
  //记录正确校验和sum
  uint16_t sum = (packet[10] << 8) + packet[11];
  //将分组头中的校验和区域填充为 0
  packet[10] = 0;
  packet[11] = 0;
  //求校验和
  uint32_t checksum = 0;  
  uint16_t hi;
  for(int i = 0; i < header_len; i = i+2) {
    checksum = checksum + packet[i+1] + (packet[i] << 8);//将所有 16 比特整数相加
    hi = checksum>>16;
    while(hi) {//如果和发生溢出，循环操作直到不溢出
      checksum = (checksum << 16) >> 16;//截取低位
      checksum = checksum + hi;  //将溢出部分加到低 16 比特
      hi = checksum>>16;
    }
  }
  //按位取反
  checksum = ((~checksum)<<16)>>16;
  //更新packet
  packet[10]=checksum>>8;
  packet[11]=(checksum<<8)>>8;
  return true;
}

