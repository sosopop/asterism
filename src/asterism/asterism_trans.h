#ifndef ASTERISM_TRANS_H_
#define ASTERISM_TRANS_H_
#include "asterism.h"
#include "asterism_core.h"

#define ASTERISM_TRANS_PROTO_SIGN 'A'
#define ASTERISM_TRANS_PROTO_VERSION 0x10

#define ASTERISM_TRANS_PROTO_CONNECT 1
#define ASTERISM_TRANS_PROTO_CONNECT_ACK 2
#define ASTERISM_TRANS_PROTO_DATA 3
#define ASTERISM_TRANS_PROTO_DATA_ACK 4
#define ASTERISM_TRANS_PROTO_DISCONNECT 5
#define ASTERISM_TRANS_PROTO_DISCONNECT_ACK 6
#define ASTERISM_TRANS_PROTO_PING 7
#define ASTERISM_TRANS_PROTO_PONG 8

#pragma pack(push)
#pragma pack(1)
struct asterism_trans_proto_s
{
	unsigned char version;
	unsigned char sign;
	unsigned int i;
	unsigned int d;
	unsigned short seq;
	unsigned short seq_ack;
	//剩余窗口大小
	unsigned short win_size;
	unsigned short packet_size;
	unsigned char cmd;
	unsigned char payload[1];
};
#pragma pack(pop)

//消化完窗口大小一半的数据，ack一次，如果窗口是256，则发送128个包后就ack一次
//窗口可以动态调整，当前收到的seq_ack+win_size得到的值必须大于已经发送的seq， seq_ack+win_size - seq = 还可以发送的包个数 -32768 - (32767) = 1
//当缓冲满后，可以将窗口调整到一半，避免网速慢的情况下，大量占用内存，至于具体的窗口调整方式，还没考虑完

#endif