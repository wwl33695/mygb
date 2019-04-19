#include "ffdecoder.h"
#include <unistd.h>
#include <stdio.h>

extern "C" {
#include <libavcodec/avcodec.h>
//#include <libavdevice/avdevice.h>
#include <libavformat/avformat.h>
//#include <libavfilter/avfilter.h>
#include <libavutil/avutil.h>
#include <libavutil/error.h>
#include <libswscale/swscale.h>
//#include <libavutil/pixdesc.h>
}

FFDecoder::FFDecoder()
{
    m_ifmt_ctx = NULL;
    m_avctx = NULL;
    m_swsContext = NULL;
    m_video_index = -1;
    m_stop = false;

    m_width = -1;
    m_height = -1;

    av_register_all();
    avformat_network_init();
}

FFDecoder::~FFDecoder()
{
    m_stop = true;

    if (m_avctx != NULL) {
        avcodec_free_context(&m_avctx);
        m_avctx = NULL;
    }

    if (m_ifmt_ctx != NULL) {
        avformat_close_input(&m_ifmt_ctx);
        m_ifmt_ctx = NULL;
    }
}

void FFDecoder::Stop()
{
    m_stop = true;
    if (m_read.joinable()) m_read.join();
    if (m_decode.joinable()) m_decode.join();
}

bool FFDecoder::OpenUrl(const char* url, int gpu)
{
    char    errbuf[64];
    int ret = avformat_open_input(&m_ifmt_ctx, url, 0, NULL);
    if (ret < 0) {
        printf("avformat_open_input '%s' (error '%s')\n", url, av_make_error_string(errbuf, sizeof(errbuf), ret));
        return false;
    }

    ret = avformat_find_stream_info(m_ifmt_ctx, NULL);
    if (ret < 0) {
        printf("avformat_find_stream_info (error '%s')\n", av_make_error_string(errbuf, sizeof(errbuf), ret));
        return false;
    }

    for (unsigned int i = 0; i < m_ifmt_ctx->nb_streams; i++) {
        av_dump_format(m_ifmt_ctx, i, url, 0);                                // dump information
        AVStream *st = m_ifmt_ctx->streams[i];
        switch(st->codecpar->codec_type) {
        case AVMEDIA_TYPE_AUDIO:
            break;
        case AVMEDIA_TYPE_VIDEO:
            m_video_index = i;
            GetCodec(AV_CODEC_ID_H264, gpu);
            break;
        default: break;
        }
    }
    if (m_avctx == NULL) {
        printf("No H.264 video stream in the input file\n");
        return false;
    }

    m_read = std::thread(ReadThread, this);

    return true;
}

bool FFDecoder::GetInfo(int *width, int *height)
{
    if (m_avctx == NULL) {
        return false;
    }

    *width = m_width;
    *height = m_height;
    return true;
}

bool FFDecoder::SetPacketData(uint8_t *data, int length)
{
    if( !data || length <= 0 )
        return false;

    AVPacket *pkt = av_packet_alloc();
    av_new_packet(pkt, length);
    memcpy(pkt->data, data, length);
    std::lock_guard<std::mutex> lock(m_mtx);
    this->m_pkts.push_back(pkt);

    return true;
}

bool FFDecoder::GetRGBData(uint8_t *data, int width, int height)
{
    AVFrame *frame = NULL;
//    while (frame == NULL) 
    {
        std::lock_guard<std::mutex> lock(m_mtx_frames);
        if (!m_frames.empty()) {
            printf("FFDecoder::GetRGBData:framesize = %d \n", m_frames.size());
            frame = m_frames.front();
            m_frames.pop_front();
//            break;
        }
    }

    if (frame == NULL) {
        return false;
    }

    if (frame->format != AV_PIX_FMT_BGR24 || frame->width != width || frame->height != height) {
        m_swsContext = sws_getCachedContext(m_swsContext,
                                            frame->width, frame->height, (AVPixelFormat)frame->format,
                                            width, height, AV_PIX_FMT_BGR24,
                                            0, NULL, NULL, NULL);
        uint8_t *pixels[4] = { data };
        int pitch[4] = { width * 3 };
        sws_scale(m_swsContext, (const uint8_t *const *)frame->data, frame->linesize,
                  0, frame->height, pixels, pitch);
    } else {

    }

    av_frame_free(&frame);
    return true;
}

bool FFDecoder::GetCodec(int codec_id, int gpu)
{
    int ret = 0;
    AVCodec *codec = NULL;
    const char *forced_codec_name = NULL;
    AVDictionary *opts = NULL;

    AVCodecContext *avctx = avcodec_alloc_context3(NULL);
    if (!avctx) {
        printf("avcodec_alloc_context3 error\n");
        return false;
    }

    codec_id = AV_CODEC_ID_H264;
    if (codec_id == AV_CODEC_ID_MJPEG) {
        forced_codec_name = "mjpeg_cuvid";
    } else if (codec_id == AV_CODEC_ID_H264) {
        forced_codec_name = "h264_cuvid";
    } else if (codec_id == AV_CODEC_ID_HEVC) {
        forced_codec_name = "hevc_cuvid";
    } else if (codec_id == AV_CODEC_ID_MPEG4) {
        forced_codec_name = "mpeg4_cuvid";
    }

    if (forced_codec_name) {
        codec = avcodec_find_decoder_by_name(forced_codec_name);
        if (codec) {
            char buf[32];
            snprintf(buf, 32, "%d", gpu);
            av_dict_set(&opts, "gpu", buf, 0);
            ret = avcodec_open2(avctx, codec, &opts);
            if (ret < 0) {
                char errbuf[64];
                printf("avcodec_open2 %s error '%s'\n", forced_codec_name, av_make_error_string(errbuf, sizeof(errbuf), ret));
                codec = NULL;
            }
        }
    }
    if (!codec) {
        codec = avcodec_find_decoder((AVCodecID)codec_id);
    }

    if (!codec) {
        printf("avcodec_find_decoder error\n");
        goto fail;
    }

    avctx->codec_id = codec->id;

    ret = avcodec_open2(avctx, codec, NULL);
    if (ret < 0) {
        char errbuf[64];
        printf("avcodec_open2 error '%s'\n", av_make_error_string(errbuf, sizeof(errbuf), ret));
        goto fail;
    }
    m_avctx = avctx;
    m_decode = std::thread(DecodeThread, this);

    goto out;

fail:
    avcodec_free_context(&avctx);
    avctx = NULL;
    return false;

out:
    av_dict_free(&opts);
    return true;
}

void FFDecoder::ReadThread(FFDecoder *that)
{
    AVPacket *pkt = NULL;
    while (!that->m_stop) {
        if (pkt == NULL) {
            pkt = new AVPacket;
        }

        if (pkt == NULL) {
            printf("new AVPacket error, exit thread!!!");
            break;
        }

        int ret = av_read_frame(that->m_ifmt_ctx, pkt);
        if (ret < 0) {
            char errbuf[64];
            printf("av_read_frame error '%s', exit thread!!!\n", av_make_error_string(errbuf, sizeof(errbuf), ret));
            break;
        } else if (ret == AVERROR(EAGAIN)) {
            usleep(10 * 1000);
            continue;
        } else if (pkt->stream_index != that->m_video_index) {
            av_packet_unref(pkt);
        } else {
            that->SetPacketData(pkt->data, pkt->size);
            
            av_packet_unref(pkt);
            delete pkt;

//            std::lock_guard<std::mutex> lock(that->m_mtx);
//            that->m_pkts.push_back(pkt);
            pkt = NULL;
        }
    }

    if (pkt) {
        delete pkt;
        pkt = NULL;
    }
}

void FFDecoder::DecodeThread(FFDecoder *that)
{
    pthread_setname_np(pthread_self(), "video_decode");
    AVFrame *frame = av_frame_alloc();
    while (!that->m_stop) 
    {
        AVPacket *pkt = NULL;
        {
            std::lock_guard<std::mutex> lock(that->m_mtx);
            if (!that->m_pkts.empty()) 
            {
                pkt = that->m_pkts.front();
                that->m_pkts.pop_front();
                printf("FFDecoder::DecodeThread:packetsize = %d \n", that->m_pkts.size());
            }
        }

        if( !pkt )
        {
            usleep(20 * 1000);
            continue;
        }

        int got_frame = 0;
        int ret = avcodec_decode_video2(that->m_avctx, frame, &got_frame, pkt);
        if (ret < 0) 
        {
            fprintf(stderr, "Error decoding video frame \n");
//            break;
        }
        else if( got_frame )
        {
            {
                std::lock_guard<std::mutex> lock(that->m_mtx_frames);
                that->m_width = frame->width;
                that->m_height = frame->height;
                that->m_frames.push_back(frame);
            }
            frame = av_frame_alloc();
            if (frame == NULL) {
                printf("av_frame_alloc error!!!");
                break;
            }
        }
        if ( pkt && pkt->data )
        {        
            av_packet_free(&pkt);
/*
            delete []pkt->data;
            delete pkt;
*/
        }

        usleep(10 * 1000);
    }
}
