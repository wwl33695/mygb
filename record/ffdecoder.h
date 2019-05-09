#ifndef __FFDECODER_H__
#define __FFDECODER_H__

#include <list>
#include <mutex>
#include <thread>

struct AVFormatContext;
struct AVCodecContext;
struct SwsContext;
struct AVStream;
struct AVPacket;
struct AVFrame;
struct AVCodecParserContext;

class FFDecoder {
public:
    FFDecoder();
    ~FFDecoder();

    bool OpenUrl(const char *url, int gpu);
    bool SetPacketData(uint8_t *data, int length);

    bool GetInfo(int *width, int *height);
    bool GetCodec(int codec_id, int gpu);

    bool GetRGBData(uint8_t *data, int width, int height);

    void Stop();

    int m_width;
    int m_height;
    uint64_t h_decoder;
    uint64_t cnrt_dev;
    void *mlu_ptrs;
    bool m_useCambricon;

    std::mutex m_mtx_frames;
    std::list<AVFrame*> m_frames;
private:
    static void ReadThread(FFDecoder *that);
    static void DecodeThread(FFDecoder *that);
    int CreateDecoder(int codec_id, int device);

private:
    AVFormatContext *m_ifmt_ctx;
    AVCodecContext *m_avctx;
    SwsContext *m_swsContext;
    AVCodecParserContext *m_parser;
    int m_video_index;

    std::mutex m_mtx;
    std::list<AVPacket*> m_pkts;

    int m_device;
    int m_codec_id;

    bool m_stop;
    std::thread m_read;
    std::thread m_decode;
};

#endif
