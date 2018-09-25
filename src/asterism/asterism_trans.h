#ifndef ASTERISM_TRANS_H_
#define ASTERISM_TRANS_H_
#include "asterism.h"
#include "asterism_core.h"

//消化完窗口大小一半的数据，ack一次，如果窗口是256，则发送128个包后就ack一次
//窗口可以动态调整，当前收到的seq_ack+win_size得到的值必须大于已经发送的seq， seq_ack+win_size - seq = 还可以发送的包个数 -32768 - (32767) = 1
//当缓冲满后，可以将窗口调整到一半，避免网速慢的情况下，大量占用内存，至于具体的窗口调整方式，还没考虑完

#endif