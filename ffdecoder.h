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
private:
    static void ReadThread(FFDecoder *that);
    static void DecodeThread(FFDecoder *that);

private:
    AVFormatContext *m_ifmt_ctx;
    AVCodecContext *m_avctx;
    SwsContext *m_swsContext;
    int m_video_index;

    std::mutex m_mtx;
    std::list<AVPacket*> m_pkts;
    std::mutex m_mtx_frames;
    std::list<AVFrame*> m_frames;

    bool m_stop;
    std::thread m_read;
    std::thread m_decode;
};

#endif
