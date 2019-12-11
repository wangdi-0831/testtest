#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */

bool validateIPChecksum(uint8_t *packet, size_t len) {
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
//与旧检验和比较并返回
return checksum==sum?true:false;
}

