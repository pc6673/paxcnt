
// Basic Config
#include "globals.h"

#if (VENDORFILTER)
#include "vendor_array.h"
#endif

// Local logging tag
static const char TAG[] = __FILE__;

uint16_t salt;

uint16_t get_salt(void) {
  salt = (uint16_t)random(65536); // get new 16bit random for salting hashes
  return salt;
}

int8_t isBeacon(uint64_t mac) {
  it = std::find(beacons.begin(), beacons.end(), mac);
  if (it != beacons.end())
    return std::distance(beacons.begin(), it);
  else
    return -1;
}

// Display a key
void printKey(const char *name, const uint8_t *key, uint8_t len, bool lsb) {
  const uint8_t *p;
  char keystring[len + 1] = "", keybyte[3];
  for (uint8_t i = 0; i < len; i++) {
    p = lsb ? key + len - i - 1 : key + i;
    snprintf(keybyte, 3, "%02X", *p);
    strncat(keystring, keybyte, 2);
  }
  ESP_LOGI(TAG, "%s: %s", name, keystring);
}

uint64_t macConvert(uint8_t *paddr) {
  uint64_t *mac;
  mac = (uint64_t *)paddr;
  return (__builtin_bswap64(*mac) >> 16);
}

bool mac_add(uint8_t *paddr, int8_t rssi, bool sniff_type) {

  if (!salt) // ensure we have salt (appears after radio is turned on)
    return false;

  char buff[10]; // temporary buffer for printf
  bool added = false;
  int8_t beaconID;    // beacon number in test monitor mode
  uint16_t hashedmac; // temporary buffer for generated hash value
  uint32_t *mac;      // temporary buffer for shortened MAC

  // only last 3 MAC Address bytes are used for MAC address anonymization
  // but since it's uint32 we take 4 bytes to avoid 1st value to be 0.
  // this gets MAC in msb (= reverse) order, but doesn't matter for hashing it.
  mac = (uint32_t *)(paddr + 2);

#if (VENDORFILTER)
  uint32_t *oui; // temporary buffer for vendor OUI
  oui = (uint32_t *)paddr;

  // use OUI vendor filter list only on Wifi, not on BLE
  if ((sniff_type == MAC_SNIFF_BLE) ||
      std::find(vendors.begin(), vendors.end(), __builtin_bswap32(*oui) >> 8) !=
          vendors.end()) {
#endif

    // salt and hash MAC, and if new unique one, store identifier in container
    // and increment counter on display
    // https://en.wikipedia.org/wiki/MAC_Address_Anonymization

    /*snprintf()并不是标C中规定的函数，但是在许多编译器中，厂商提供了其实现的版本。
    snprintf()函数用于将格式化的数据写入字符串，其原型为： int snprintf(char *str, int n, char * format [, argument, ...]);
    sprintf()最常见的应用之一莫过于把整数打印到字符串中，如：
    sprintf(s, "%d", 123);  //把整数123打印成一个字符串保存在s中
    sprintf(s, "%8x", 4567);  //小写16进制，宽度占8个位置，右对齐*/
    snprintf(buff, sizeof(buff), "%08X",  
             *mac + (uint32_t)salt);      // convert unsigned 32-bit salted MAC
                                          // to 8 digit hex string
    hashedmac = rokkit(&buff[3], 5);      // hash MAC 8 digit -> 5 digit，rokkit is a very quick hash function
    /*auto被解释为一个自动存储变量的关键字，也就是申明一块临时的变量内存
    C程序是面向过程的，在C代码中会出现大量的函数模块，每个函数都有其生命周期（也称作用域），在函数生命周期中声明的变量通常叫做局部变量，也叫自动变量。例如：
    
      int fun(){
        int a = 10;      // auto int a = 10;
        // do something
      return 0;
      }
      整型变量a在fun函数内声明，其作用域为fun函数内，出来fun函数，不能被引用，a变量为自动变量。也就是说编译器会有int a = 10之前会加上auto的关键字。
      auto的出现意味着，当前变量的作用域为当前函数或代码段的局部变量，意味着当前变量会在内存栈上进行分配。
      
    */

    // add hashed MAC, if new unique. 
    //这里貌似 newmac只是临时的，用其second来判断真假，判断完就没用了. 但是mac在main里面定义了，貌似是全局变量。我的理解是mac一直保存着收到hashed mac(16bit) 
    //如果能把mac打印出来或者输出出来，就是你需要的数据。
    //注意这里mac是harshed，并非原始48bit的真实mac;不过也应该够你识别不同信号源和数据处理 
    auto newmac = macs.insert(hashedmac); 

    //
    added = newmac.second ? true
                          : false; // true if hashed MAC is unique in container

    // Count only if MAC was not yet seen
    if (added) {
      // increment counter and one blink led
      if (sniff_type == MAC_SNIFF_WIFI) {
        macs_wifi++; // increment Wifi MACs counter
#if (HAS_LED != NOT_A_PIN) || defined(HAS_RGB_LED)
        blink_LED(COLOR_GREEN, 50);
#endif
      }
#if (BLECOUNTER)
      else if (sniff_type == MAC_SNIFF_BLE) {
        macs_ble++; // increment BLE Macs counter
#if (HAS_LED != NOT_A_PIN) || defined(HAS_RGB_LED)
        blink_LED(COLOR_MAGENTA, 50);
#endif
      }
#endif

      // in beacon monitor mode check if seen MAC is a known beacon
      if (cfg.monitormode) {
        beaconID = isBeacon(macConvert(paddr));
        if (beaconID >= 0) {
          ESP_LOGI(TAG, "Beacon ID#%d detected", beaconID);
#if (HAS_LED != NOT_A_PIN) || defined(HAS_RGB_LED)
          blink_LED(COLOR_WHITE, 2000);
#endif
          payload.reset();
          payload.addAlarm(rssi, beaconID);
          SendPayload(BEACONPORT, prio_high);
        }
      };

    } // added

    // Log scan result
    ESP_LOGV(TAG,
             "%s %s RSSI %ddBi -> salted MAC %s -> Hash %04X -> WiFi:%d  "
             "BLTH:%d -> "
             "%d Bytes left",
             added ? "new  " : "known",
             sniff_type == MAC_SNIFF_WIFI ? "WiFi" : "BLTH", rssi, buff,
             hashedmac, macs_wifi, macs_ble, getFreeRAM());

    /*Adrian's note: ZZ want to see the macs counter, so
    print it out
    */         
    ESP_LOGI(TAG, "the counter value of macs_wifi is     %d", macs_wifi);

    /*Adrian's Note: 
    %a  浮点数、十六进制数字和p-记数法（c99
    %A  浮点数、十六进制数字和p-记法（c99）
    %c  一个字符(char)
    %C  一个ISO宽字符
    %d  有符号十进制整数(int)（%ld、%Ld：长整型数据(long),%hd：输出短整形。）　
    %e  浮点数、e-记数法
    %E  浮点数、E-记数法
    %f  单精度浮点数(默认float)、十进制记数法（%.nf  这里n表示精确到小数位后n位.十进制计数）
    %g  根据数值不同自动选择%f或%e．
    %G  根据数值不同自动选择%f或%e.
    %i  有符号十进制数（与%d相同）
    %o  无符号八进制整数
    %p  指针
    %s  对应字符串char*（%s = %hs = %hS 输出 窄字符）
    %S  对应宽字符串WCAHR*（%ws = %S 输出宽字符串）
    %u  无符号十进制整数(unsigned int)
    %x  使用十六进制数字0xf的无符号十六进制整数　
    %X  使用十六进制数字0xf的无符号十六进制整数
    %%  打印一个百分号
    
    
    %I64d 用于INT64 或者 long long
    %I64u 用于UINT64 或者 unsigned long long
    %I64x 用于64位16进制数据
    ————————————————
    版权声明：本文为CSDN博主「jackytse_」的原创文章，遵循 CC 4.0 BY-SA 版权协议，转载请附上原文出处链接及本声明。
    原文链接：https://blog.csdn.net/xiexievv/article/details/6831194
    */

     /*
     ESP_LOGI(TAG, "rssi is %u", rssi);
     ESP_LOGI(TAG, "hashedmac is %u", hashedmac);
     ESP_LOGI(TAG, "macs_wifi is %u", macs_wifi);
     ESP_LOGI(TAG, "macs_ble is %u", macs_ble);
     */
     /************************************End of Adrian's test*****************************/

#if (VENDORFILTER)
  } else {
    // Very noisy
    // ESP_LOGD(TAG, "Filtered MAC %02X:%02X:%02X:%02X:%02X:%02X",
    // paddr[0],paddr[1],paddr[2],paddr[3],paddr[5],paddr[5]);
  }
#endif

  // True if MAC WiFi/BLE was new
  return added; // function returns bool if a new and unique Wifi or BLE mac was
                // counted (true) or not (false)
}
